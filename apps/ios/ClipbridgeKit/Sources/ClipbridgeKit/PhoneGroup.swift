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

    /// Creates a group: a root CA for caSigner's key and a member
    /// certificate for this phone's member key (a SubjectPublicKeyInfo).
    public static func create(caSigner: CertificateSigner, memberKey: Data, now: Date) throws -> PhoneGroup {
        let ca = try GroupCertificates.groupCA(signer: caSigner, now: now, pathLength: 1)
        let device = SyncEngine.newID()
        let cert = try GroupCertificates.member(device: device, publicKey: memberKey, ca: ca, caSigner: caSigner, now: now)
        return PhoneGroup(device: device, groupCA: ca, memberCert: cert, computers: [])
    }

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
