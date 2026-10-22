// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// A phone group (docs/protocol.md, sections 9 and 10) as this phone holds
/// it: the group CA, the phone's own member certificate, the computers it
/// admitted and the records. The phone is the root, which made the group,
/// an admin with an admin CA under the root, or a member without either.
/// The keys stay outside: the signing key (the root key, or the admin key)
/// in the Secure Enclave, the member key in the keychain. It is saved as
/// JSON next to the app's other data.
public struct PhoneGroup: Codable, Equatable, Sendable {
    /// This phone's device ID.
    public var device: String
    /// The group root CA, DER; path length 1.
    public var groupCA: Data
    /// This phone's member certificate, DER, from the group CA or from
    /// memberIssuer.
    public var memberCert: Data
    /// The admin CA that issued memberCert, which the phone sends after it
    /// in TLS handshakes; nil when the group CA did.
    public var memberIssuer: Data?
    /// Whether this phone holds the root key: it made the group.
    public var isRoot = true
    /// This phone's admin CA when it is an admin but not the root.
    public var adminCA: Data?
    public var computers: [Computer]
    /// The group's signed device and revocation records; admin phones sign
    /// them, and they spread to every member.
    public var records = RecordSet()

    enum CodingKeys: String, CodingKey { case device, groupCA, memberCert, memberIssuer, isRoot, adminCA, computers, records }

    init(device: String, groupCA: Data, memberCert: Data, computers: [Computer]) {
        (self.device, self.groupCA, self.memberCert, self.computers) = (device, groupCA, memberCert, computers)
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        device = try c.decode(String.self, forKey: .device)
        groupCA = try c.decode(Data.self, forKey: .groupCA)
        memberCert = try c.decode(Data.self, forKey: .memberCert)
        memberIssuer = try c.decodeIfPresent(Data.self, forKey: .memberIssuer)
        // Files saved before phones could join belong to a root.
        isRoot = try c.decodeIfPresent(Bool.self, forKey: .isRoot) ?? true
        adminCA = try c.decodeIfPresent(Data.self, forKey: .adminCA)
        computers = try c.decode([Computer].self, forKey: .computers)
        records = try c.decodeIfPresent(RecordSet.self, forKey: .records) ?? RecordSet()
    }

    /// Whether this phone may admit devices, renew certificates and remove
    /// devices: the root and the admins.
    public var isAdmin: Bool { isRoot || adminCA != nil }

    /// The certificate chain this phone presents in TLS, leaf first.
    public var memberChain: [Data] { [memberCert] + (memberIssuer.map { [$0] } ?? []) }

    /// The CA whose key signs for this phone: the root, or its admin CA.
    var signingCA: Data { adminCA ?? groupCA }

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

    /// The group a phone joins, from the welcome the admitting phone sent
    /// and PairingJoiner checked: a member of it, and an admin when the
    /// welcome carries its admin CA. The records arrive from the computers.
    public static func joined(_ j: PairingJoiner.Joined) -> PhoneGroup {
        var g = PhoneGroup(device: j.device, groupCA: j.welcome.groupCA, memberCert: j.welcome.cert, computers: [])
        (g.memberIssuer, g.isRoot, g.adminCA) = (j.welcome.issuer, false, j.welcome.adminCA)
        return g
    }

    public enum Failure: Error, Equatable { case cannotRemoveItself, unknownDevice, notAdmin, cannotRemoveRoot }

    /// Signs and adds a device record.
    mutating func record(device: String, name: String, role: String, key: Data, admin: Data? = nil, caSigner: CertificateSigner,
                         now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        let r = try Records.device(device, name: name, role: role, key: key, admin: admin, group: tag, by: self.device, now: now,
                                   signer: caSigner, adminCA: adminCA)
        records.add(r, groupCA: groupCA)
        return r
    }

    /// Renews this phone's own member certificate when it is due; reports
    /// whether it did, after which the TLS identity must be made again. An
    /// admin issues it from its own admin CA, a phone without one cannot.
    public mutating func renewOwnCertificate(caSigner: CertificateSigner, now: Date) throws -> Bool {
        guard isAdmin, GroupCertificates.isDue(memberCert, groupCA: groupCA, now: now),
              (try? GroupCertificates.verifyMember(memberCert, groupCA: groupCA, issuer: memberIssuer, now: now)) == device else { return false }
        memberCert = try GroupCertificates.member(device: device, publicKey: CertificateInfo(der: memberCert).publicKey, ca: signingCA,
                                                  caSigner: caSigner, now: now)
        memberIssuer = adminCA
        return true
    }

    /// A renewed certificate for a peer's chain (leaf first) when it is due
    /// and this phone may renew it: the root renews any, an admin what its
    /// own admin CA issued.
    public func renewal(chain: [Data], caSigner: CertificateSigner, now: Date) -> Data? {
        guard isAdmin else { return nil }
        return try? GroupCertificates.renewal(chain: chain, groupCA: groupCA, caSigner: caSigner, adminCA: adminCA, now: now)
    }

    /// The devices of the group, from the records.
    public var devices: [RecordSet.Device] { records.devices }

    /// Removes a device from the group: signs a revocation of its key,
    /// which every member then refuses, and returns the record to send. For
    /// an admin phone it revokes its admin key too and keeps the devices
    /// that phone admitted, so they stay in the group (section 10). The
    /// root phone cannot be removed yet: that needs a root record.
    public mutating func revoke(device: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        guard device != self.device else { throw Failure.cannotRemoveItself }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        guard device != records.rootDevice else { throw Failure.cannotRemoveRoot }
        var keys = [d.key], keep: [Data]?
        if let admin = d.adminKey {
            keys.append(admin)
            keep = records.admitted(by: admin).filter { $0 != d.key }
        }
        let r = try Records.revoke(keys, keep: keep, group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA)
        records.add(r, groupCA: groupCA)
        computers.removeAll { $0.device == device }
        return r
    }

    /// Admits a listening device over a pairing connection whose TLS
    /// handshake is done (section 6, "The joiner listens"): joinerCert is
    /// the device's certificate, already checked against the QR code's
    /// fingerprint, and sessionID the TLS exporter's output. The device
    /// gets a member certificate from this phone's CA and the group CA,
    /// never a key. A phone that sent an admin key becomes an admin when
    /// this phone is the root and makeAdmin is set: it gets an admin CA for
    /// that key. On success a computer is in computers, where one admitted
    /// again replaces its entry, and every device has its record.
    public mutating func admit(over t: FrameTransport, code: String, joinerCert: Data, sessionID: [UInt8],
                               caSigner: CertificateSigner, makeAdmin: Bool = true, now: Date) async throws -> PairingMember.Admitted {
        guard isAdmin else { throw Failure.notAdmin }
        let (root, ca, issuer, canMakeAdmins) = (groupCA, signingCA, adminCA, isRoot)
        var adminKey: Data?
        let admitted = try await PairingMember.admit(
            over: t, code: code, memberCert: memberCert, joinerCert: joinerCert, sessionID: sessionID,
            memberAD: Pairing.MemberAD(device: device, group: tag)
        ) { dev, publicKey, info in
            var w = Pairing.Welcome(cert: try GroupCertificates.member(device: dev, publicKey: publicKey, ca: ca, caSigner: caSigner, now: now),
                                    groupCA: root, issuer: issuer)
            if info.os == "ios", let key = info.adminKey, makeAdmin, canMakeAdmins {
                w.adminCA = try GroupCertificates.adminCA(device: dev, publicKey: key, root: root, rootSigner: caSigner)
                adminKey = key
            }
            return w
        }
        let name = Self.validName(admitted.info.name), key = try Records.keyHash(cert: admitted.cert)
        if admitted.info.os == "ios" {
            _ = try record(device: admitted.device, name: name, role: "phone", key: key, admin: adminKey.map(Records.keyHash(spki:)),
                           caSigner: caSigner, now: now)
            return admitted
        }
        computers.removeAll { $0.device == admitted.device }
        computers.append(Computer(device: admitted.device, name: admitted.info.name, os: admitted.info.os, cert: admitted.cert, admitted: now))
        _ = try record(device: admitted.device, name: name, role: admitted.info.os == "darwin" ? "mac" : "linux",
                       key: key, caSigner: caSigner, now: now)
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
