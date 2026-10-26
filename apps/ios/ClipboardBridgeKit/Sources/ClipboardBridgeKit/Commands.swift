// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// Commands (docs/protocol.md, section 15): an admin's order for one member,
/// signed like a record and never stored, as internal/group/command.go makes
/// them: one sets the receiver's sync mode, another makes the receiver, an
/// admin computer, the group's hub in place of this phone; a paste command
/// puts a text where the receiver's focus is, and paste-off turns remote
/// paste off on the receiver (design.md, "Remote paste").
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
        public var enter: Bool?
        public var kind: String?
        public var text: String?
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

    public enum Failure: Error { case unknownMode(String), badHubOrder, badPaste }

    /// The longest text of a paste command, in bytes of UTF-8, and of one
    /// typed key by key.
    public static let maxPasteText = 1 << 20
    public static let maxTypeText = 4 << 10

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

    /// A paste command for the device to: put text where its focus is, by
    /// method "paste" (the clipboard and the paste keys) or "type", then
    /// press Enter when enter is set; kind is "text" or "secret". Signed as
    /// mode.
    public static func paste(to: String, text: String, method: String = "paste", enter: Bool = false, kind: String = "text",
                             group: String, by: String, now: Date, signer: CertificateSigner,
                             adminCA: Data? = nil, id: String = newID()) throws -> Member.Record {
        let limit = method == "paste" ? maxPasteText : method == "type" ? maxTypeText : 0
        guard limit > 0, kind == "text" || kind == "secret", !text.isEmpty, text.utf8.count <= limit else { throw Failure.badPaste }
        let ms = Records.ms(now)
        let body = Body(type: "paste", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS, mode: method,
                        enter: enter ? true : nil, kind: kind, text: text)
        return try sign(body, signer: signer, adminCA: adminCA)
    }

    /// A paste-off command for the device to: it turns remote paste off
    /// there. Signed as mode.
    public static func pasteOff(to: String, group: String, by: String, now: Date, signer: CertificateSigner,
                                adminCA: Data? = nil, id: String = newID()) throws -> Member.Record {
        let ms = Records.ms(now)
        return try sign(Body(type: "paste-off", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS),
                        signer: signer, adminCA: adminCA)
    }

    static func sign(_ body: Body, signer: CertificateSigner, adminCA: Data?) throws -> Member.Record {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try enc.encode(body)
        return Member.Record(body: data, sig: try signer.signature(for: data), chain: adminCA.map { [$0] })
    }

    /// How far ahead of the receiver's clock a command's time may be.
    public static let aheadMS: Int64 = 60_000

    /// The most bytes of a command's body, as Go takes: a hub command
    /// carries up to 256 clients' keys.
    static let maxBody = 64 << 10
    /// A paste command's body may be larger: it carries up to 1 MiB of text.
    static let maxPasteBody = 2 << 20

    /// Why a command was refused, in words for the sender.
    public struct Refused: Error, Equatable { public var reason: String }

    /// Checks command c for the member me at nowMS, as Go's
    /// Records.VerifyCommand: an admin of the group signed it now (records
    /// says), it is for me in this group, it has not expired and was not
    /// signed in the future. The caller keeps the replay cache; a mode
    /// command's mode is not checked against Member.modes here.
    public static func verify(_ c: Member.Record, records: RecordSet, me: String, nowMS: Int64) throws -> Body {
        func refuse(_ reason: String) -> Refused { Refused(reason: reason) }
        guard c.body.count <= maxPasteBody else { throw refuse("the command is too large") }
        guard let b = try? JSONDecoder().decode(Body.self, from: c.body) else { throw refuse("the command is not valid") }
        guard b.type == "paste" || c.body.count <= maxBody else { throw refuse("the command is too large") }
        func hex32(_ s: String) -> Bool { s.utf8.count == 32 && s.allSatisfy { "0123456789abcdef".contains($0) } }
        guard b.v == Records.version else { throw refuse("unknown command version") }
        guard hex32(b.id) else { throw refuse("the command has no valid ID") }
        guard b.type == "paste" || (b.enter == nil && b.kind == nil && b.text == nil) else { throw refuse("a \(b.type) command carries a paste") }
        switch b.type {
        case "mode": guard let m = b.mode, !m.isEmpty, b.hub == nil else { throw refuse("a mode command names no mode") }
        case "hub": guard b.hub != nil, (b.mode ?? "").isEmpty else { throw refuse("a hub command has no order") }
        case "paste-off": guard b.hub == nil, (b.mode ?? "").isEmpty else { throw refuse("a paste-off command carries an order") }
        case "paste":
            let limit = b.mode == "paste" ? maxPasteText : b.mode == "type" ? maxTypeText : 0
            guard limit > 0 else { throw refuse("a paste command's way is not paste or type") }
            guard b.hub == nil else { throw refuse("a paste command carries a hub order") }
            guard b.kind == "text" || b.kind == "secret" else { throw refuse("a paste command's kind is not text or secret") }
            let n = b.text?.utf8.count ?? 0
            guard n > 0 else { throw refuse("a paste command has no text") }
            guard n <= limit else { throw refuse("a paste command's text is longer than \(limit) bytes") }
        default: throw refuse("unknown command type \(b.type)")
        }
        guard hex32(b.to) else { throw refuse("the command names no valid device") }
        guard b.expires_ms > b.time_ms, b.expires_ms - b.time_ms <= lifetimeMS else { throw refuse("the command's lifetime is not valid") }
        guard let ca = records.groupCA else { throw refuse("this device has no records of its group yet") }
        guard b.group == GroupCertificates.tag(groupCA: ca) else { throw refuse("the command is for another group") }
        guard b.to == me else { throw refuse("the command is for another device") }
        guard records.signedByAdmin(c) else { throw refuse("the command's signer is not an admin of the group") }
        guard b.expires_ms > nowMS else { throw refuse("the command expired; check the clocks of both devices") }
        guard b.time_ms <= nowMS + aheadMS else { throw refuse("the command was signed in the future; check the clocks of both devices") }
        return b
    }

    /// The ID in a command's body, or nil when it has none.
    public static func id(of c: Member.Record) -> String? { head(of: c)?.id }

    /// The receiver a command's body names, or nil when it names none.
    static func to(of c: Member.Record) -> String? { head(of: c)?.to }

    /// When a command expires, or nil when its body says not.
    static func expires(of c: Member.Record) -> Int64? { head(of: c)?.expires_ms }

    private struct Head: Decodable { var id: String?, to: String?, expires_ms: Int64? }
    private static func head(of c: Member.Record) -> Head? { try? JSONDecoder().decode(Head.self, from: c.body) }
}
