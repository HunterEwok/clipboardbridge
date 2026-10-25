// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// Commands (docs/protocol.md, section 15): an admin's order for one member,
/// signed like a record and never stored, as internal/group/command.go makes
/// them. The only one so far sets the receiver's sync mode.
public enum Commands {
    /// How long after signing a command expires; the receivers take at most 30 s.
    public static let lifetimeMS: Int64 = 30_000

    /// A command body.
    public struct Body: Codable, Equatable, Sendable {
        public var v = Records.version
        public var type: String
        public var group: String
        public var by: String
        public var to: String
        public var id: String
        public var time_ms: Int64
        public var expires_ms: Int64
        public var mode: String?
    }

    public enum Failure: Error { case unknownMode(String) }

    /// A new command ID: 128 random bits in hex.
    public static func newID() -> String {
        var g = SystemRandomNumberGenerator()
        return (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &g)) }.joined()
    }

    /// A mode command for the device to, signed with the root key (adminCA
    /// nil) or with an admin CA key, adminCA being that CA's certificate.
    public static func mode(to: String, mode: String, group: String, by: String, now: Date, signer: CertificateSigner,
                            adminCA: Data? = nil, id: String = newID()) throws -> Member.Record {
        guard Member.modes.contains(mode) else { throw Failure.unknownMode(mode) }
        let ms = Records.ms(now)
        let body = Body(type: "mode", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS, mode: mode)
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try enc.encode(body)
        return Member.Record(body: data, sig: try signer.signature(for: data), chain: adminCA.map { [$0] })
    }

    /// The ID in a command's body, or nil when it has none.
    public static func id(of c: Member.Record) -> String? {
        struct ID: Decodable { var id: String? }
        return (try? JSONDecoder().decode(ID.self, from: c.body))?.id
    }
}
