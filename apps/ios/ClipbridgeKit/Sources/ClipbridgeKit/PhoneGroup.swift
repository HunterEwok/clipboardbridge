// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// A group whose root is this phone (docs/protocol.md, section 9): its group
/// CA, the phone's own member certificate, and the computers it admitted.
/// The keys stay outside: the CA key in the Secure Enclave, the member key
/// in the keychain. It is saved as JSON next to the app's other data.
public struct PhoneGroup: Codable, Equatable, Sendable {
    /// This phone's device ID.
    public var device: String
    /// The group root CA, DER; path length 1.
    public var groupCA: Data
    /// This phone's member certificate, DER, from the group CA.
    public var memberCert: Data
    public var computers: [Computer]
    /// The group's signed device and revocation records; this phone signs
    /// them, and they spread to every member.
    public var records = RecordSet()

    enum CodingKeys: String, CodingKey { case device, groupCA, memberCert, computers, records }

    init(device: String, groupCA: Data, memberCert: Data, computers: [Computer]) {
        (self.device, self.groupCA, self.memberCert, self.computers) = (device, groupCA, memberCert, computers)
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        device = try c.decode(String.self, forKey: .device)
        groupCA = try c.decode(Data.self, forKey: .groupCA)
        memberCert = try c.decode(Data.self, forKey: .memberCert)
        computers = try c.decode([Computer].self, forKey: .computers)
        records = try c.decodeIfPresent(RecordSet.self, forKey: .records) ?? RecordSet()
    }

    /// A computer this phone admitted.
    public struct Computer: Codable, Equatable, Sendable, Identifiable {
        public var device: String
        public var name: String
        /// "linux" or "darwin", as its pairing Info says.
        public var os: String
        public var cert: Data
        public var admitted: Date
        public var id: String { device }
    }

    /// The group tag the computers publish.
    public var tag: String { GroupCertificates.tag(groupCA: groupCA) }

    /// Creates a group: a root CA for caSigner's key, a member certificate
    /// for this phone's member key (a SubjectPublicKeyInfo), and the phone's
    /// own device record under name.
    public static func create(caSigner: CertificateSigner, memberKey: Data, name: String = "iPhone", now: Date) throws -> PhoneGroup {
        let ca = try GroupCertificates.groupCA(signer: caSigner, now: now, pathLength: 1)
        let device = SyncEngine.newID()
        let cert = try GroupCertificates.member(device: device, publicKey: memberKey, ca: ca, caSigner: caSigner, now: now)
        var g = PhoneGroup(device: device, groupCA: ca, memberCert: cert, computers: [])
        _ = try g.record(device: device, name: Self.validName(name), role: "phone", key: Records.keyHash(spki: memberKey),
                         caSigner: caSigner, now: now)
        return g
    }

    /// A name that the records accept: 1 to 64 bytes without control
    /// characters, or "iPhone".
    static func validName(_ s: String) -> String {
        var out = ""
        for ch in s where !ch.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) {
            if (out + String(ch)).utf8.count > 64 { break }
            out.append(ch)
        }
        return out.isEmpty ? "iPhone" : out
    }

    /// Signs and adds a device record.
    mutating func record(device: String, name: String, role: String, key: Data, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        let r = try Records.device(device, name: name, role: role, key: key, group: tag, by: self.device, now: now, signer: caSigner)
        records.add(r, groupCA: groupCA)
        return r
    }

    /// Renews this phone's own member certificate when it is due; reports
    /// whether it did, after which the TLS identity must be made again.
    public mutating func renewOwnCertificate(caSigner: CertificateSigner, now: Date) throws -> Bool {
        guard let renewed = try GroupCertificates.renewal(of: memberCert, groupCA: groupCA, caSigner: caSigner, now: now) else { return false }
        memberCert = renewed
        return true
    }

    /// The devices of the group, from the records.
    public var devices: [RecordSet.Device] { records.devices }

    /// Removes a device from the group: signs a revocation of its key,
    /// which every member then refuses, and returns the record to send.
    public mutating func revoke(device: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard device != self.device else { throw Failure.cannotRemoveItself }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        let r = try Records.revoke([d.key], group: tag, by: self.device, now: now, signer: caSigner)
        records.add(r, groupCA: groupCA)
        computers.removeAll { $0.device == device }
        return r
    }

    public enum Failure: Error, Equatable { case cannotRemoveItself, unknownDevice }

    /// Admits a listening computer over a pairing connection whose TLS
    /// handshake is done (section 6, "The joiner listens"): joinerCert is
    /// the computer's certificate, already checked against the QR code's
    /// fingerprint, and sessionID the TLS exporter's output. The computer
    /// gets a member certificate and the group CA, never a key. On success
    /// the computer is in computers; one admitted again replaces its entry.
    public mutating func admit(over t: FrameTransport, code: String, joinerCert: Data, sessionID: [UInt8],
                               caSigner: CertificateSigner, now: Date) async throws -> PairingMember.Admitted {
        let ca = groupCA
        let admitted = try await PairingMember.admit(
            over: t, code: code, memberCert: memberCert, joinerCert: joinerCert, sessionID: sessionID,
            memberAD: Pairing.MemberAD(device: device, group: tag)
        ) { dev, publicKey, _ in
            Pairing.Welcome(cert: try GroupCertificates.member(device: dev, publicKey: publicKey, ca: ca, caSigner: caSigner, now: now), groupCA: ca)
        }
        computers.removeAll { $0.device == admitted.device }
        computers.append(Computer(device: admitted.device, name: admitted.info.name, os: admitted.info.os, cert: admitted.cert, admitted: now))
        _ = try record(device: admitted.device, name: Self.validName(admitted.info.name), role: admitted.info.os == "darwin" ? "mac" : "linux",
                       key: Records.keyHash(cert: admitted.cert), caSigner: caSigner, now: now)
        return admitted
    }

    /// Reads a saved group; nil when there is none.
    public static func load(from url: URL) throws -> PhoneGroup? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try JSONDecoder().decode(PhoneGroup.self, from: Data(contentsOf: url))
    }

    /// Saves the group in one step, so a crash leaves the old file or the new one.
    public func save(to url: URL) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try enc.encode(self).write(to: url, options: [.atomic])
    }
}
