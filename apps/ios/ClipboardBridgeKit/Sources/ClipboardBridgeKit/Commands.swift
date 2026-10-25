// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// Commands (docs/protocol.md, section 15): an admin's order for one member,
/// signed like a record and never stored, as internal/group/command.go makes
/// them: one sets the receiver's sync mode, another makes the receiver, an
/// admin computer, the group's hub in place of this phone.
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
        public var hub: HubOrder?
    }

    /// What a hub command tells the new hub (section 11, "Moving the
    /// hub"): where its clients reach it and the old hub's clients, with the
    /// keys they have.
    public struct HubOrder: Codable, Equatable, Sendable {
        public struct Forwarder: Codable, Equatable, Sendable {
            public var endpoint: String
            public var key: String
        }

        public var forwarder: Forwarder?
        public var endpoints: [String]?
        public var clients: [PhoneHub.Client]?
    }

    /// The most clients a hub command hands over, as many as a hub keeps.
    public static let maxHubClients = 256

    public enum Failure: Error { case unknownMode(String), badHubOrder }

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

    /// A hub command for the admin computer to: it becomes the group's
    /// hub, reached through the forwarder (endpoint "ip:port" and the pin
    /// of its key) and at endpoints, and takes clients, the old hub's, with
    /// the keys they have. Signed as mode.
    public static func hub(to: String, forwarder: (endpoint: String, pin: String)?, endpoints: [String] = [], clients: [PhoneHub.Client],
                           group: String, by: String, now: Date, signer: CertificateSigner,
                           adminCA: Data? = nil, id: String = newID()) throws -> Member.Record {
        guard forwarder != nil || !endpoints.isEmpty, endpoints.count <= 8, clients.count <= maxHubClients else { throw Failure.badHubOrder }
        let order = HubOrder(forwarder: forwarder.map { HubOrder.Forwarder(endpoint: $0.endpoint, key: $0.pin) },
                             endpoints: endpoints.isEmpty ? nil : endpoints, clients: clients.isEmpty ? nil : clients)
        let ms = Records.ms(now)
        let body = Body(type: "hub", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS, hub: order)
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
