// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// The group's signed device and revocation records (docs/protocol.md,
/// section 10), as internal/group/records.go makes and reads them. The phone
/// signs them with its root key, so they carry no chain; records signed
/// through an admin CA come with the admin phones.
public enum Records {
    public static let version = 1

    /// A record body; the fields depend on its type.
    public struct Body: Codable, Equatable, Sendable {
        public var v = Records.version
        public var type: String
        public var group: String
        public var time_ms: Int64
        public var by: String?
        // device
        public var device: String?
        public var name: String?
        public var role: String?
        public var key: Data?
        public var admin: Data?
        // revoke
        public var keys: [Data]?
        public var keep: [Data]?

        public init(type: String, group: String, timeMS: Int64, by: String?) {
            (self.type, self.group, self.time_ms, self.by) = (type, group, timeMS, by)
        }
    }

    /// The hash that names a key in records: SHA-256 over a
    /// SubjectPublicKeyInfo.
    public static func keyHash(spki: Data) -> Data { Data(SHA256.hash(data: spki)) }

    /// The hash of the key a certificate certifies.
    public static func keyHash(cert: Data) throws -> Data { keyHash(spki: try CertificateInfo(der: cert).publicKey) }

    /// A record's ID: SHA-256 over its body.
    public static func id(_ r: Member.Record) -> Data { Data(SHA256.hash(data: r.body)) }

    /// Signs a body with the group CA key (the phone's root).
    public static func sign(_ body: Body, with signer: CertificateSigner) throws -> Member.Record {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try enc.encode(body)
        return Member.Record(body: data, sig: try signer.signature(for: data))
    }

    /// A device record.
    public static func device(_ device: String, name: String, role: String, key: Data, group: String, by: String,
                              now: Date, signer: CertificateSigner) throws -> Member.Record {
        var b = Body(type: "device", group: group, timeMS: ms(now), by: by)
        (b.device, b.name, b.role, b.key) = (device, name, role, key)
        return try sign(b, with: signer)
    }

    /// A revocation record for keys.
    public static func revoke(_ keys: [Data], group: String, by: String, now: Date, signer: CertificateSigner) throws -> Member.Record {
        var b = Body(type: "revoke", group: group, timeMS: ms(now), by: by)
        b.keys = keys
        return try sign(b, with: signer)
    }

    static func ms(_ d: Date) -> Int64 { Int64((d.timeIntervalSince1970 * 1000).rounded(.down)) }
}

/// The record set of a group: verified records, which only grow, and what
/// they say. Like the Go side, what it says depends on the set alone.
public struct RecordSet: Codable, Equatable, Sendable {
    public private(set) var records: [Member.Record] = []

    /// Records beyond this many are refused.
    public static let max = 4096

    public init() {}

    /// A device as the list shows it.
    public struct Device: Equatable, Sendable, Identifiable {
        public var id: String
        public var name: String
        public var role: String
        public var key: Data
    }

    /// Adds a record that the group CA signed, unless it is known; reports
    /// whether it was new. Records of another group, or with a chain (admin
    /// CAs, not supported here yet), are refused.
    @discardableResult
    public mutating func add(_ r: Member.Record, groupCA: Data) -> Bool {
        let id = Records.id(r)
        guard !records.contains(where: { Records.id($0) == id }), records.count < Self.max,
              (r.chain ?? []).isEmpty,
              let body = try? JSONDecoder().decode(Records.Body.self, from: r.body),
              body.v == Records.version, body.group == GroupCertificates.tag(groupCA: groupCA),
              let ca = try? CertificateInfo(der: groupCA),
              let key = try? P256.Signing.PublicKey(derRepresentation: ca.publicKey),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: r.sig),
              key.isValidSignature(sig, for: r.body) else { return false }
        records.append(r)
        return true
    }

    private var bodies: [(Member.Record, Records.Body)] {
        records.compactMap { r in (try? JSONDecoder().decode(Records.Body.self, from: r.body)).map { (r, $0) } }
    }

    /// The revoked keys.
    public var revoked: Set<Data> {
        Set(bodies.filter { $0.1.type == "revoke" }.flatMap { $0.1.keys ?? [] })
    }

    /// The devices list: the latest device record of each device (by time,
    /// then record ID), less the revoked keys, sorted by name.
    public var devices: [Device] {
        let revoked = revoked
        var latest: [String: (Member.Record, Records.Body)] = [:]
        for (r, b) in bodies where b.type == "device" {
            guard let d = b.device else { continue }
            if let cur = latest[d] {
                let newer = b.time_ms != cur.1.time_ms ? b.time_ms > cur.1.time_ms
                    : Records.id(r).lexicographicallyPrecedes(Records.id(cur.0)) == false
                if !newer { continue }
            }
            latest[d] = (r, b)
        }
        return latest.compactMap { d, rb -> Device? in
            guard let key = rb.1.key, !revoked.contains(key) else { return nil }
            return Device(id: d, name: rb.1.name ?? d, role: rb.1.role ?? "", key: key)
        }.sorted { ($0.name, $0.id) < ($1.name, $1.id) }
    }

    /// SHA-256 over the sorted record IDs, base64, as the hello carries it;
    /// nil for an empty set.
    public var digest: String? {
        guard !records.isEmpty else { return nil }
        let ids = records.map(Records.id).sorted { $0.lexicographicallyPrecedes($1) }
        var h = SHA256()
        for id in ids { h.update(data: id) }
        return Data(h.finalize()).base64EncodedString()
    }
}
