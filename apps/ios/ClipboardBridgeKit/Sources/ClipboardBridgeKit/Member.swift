// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The member protocol of docs/protocol.md, sections 4 and 5, as the Go side
/// speaks it (internal/node, internal/clip, internal/hlc): frames of a
/// 4-byte big-endian length and a JSON message, a hello first, then events,
/// pings, records and goodbyes.
public enum Member {
    /// The ALPN protocol of member connections.
    public static let alpn = "clipboardbridge/1"
    /// Frames larger than this close the connection.
    public static let maxFrame = 7 << 20
    /// A side that wrote nothing for this long sends a ping.
    public static let pingEvery: TimeInterval = 5
    /// A connection silent for this long is dead.
    public static let timeout: TimeInterval = 15
    /// Texts are at most this many bytes of UTF-8.
    public static let maxText = 1 << 20

    /// What kind of member is at the other end.
    public enum Role: String, Codable, Sendable { case linux, mac, phone, lite }

    /// The kind of a text: a secret is kept only briefly (section 5).
    public enum Kind: String, Codable, Sendable { case text, secret }

    /// How a text reached the member that made the event.
    public enum Via: String, Codable, Sendable {
        case copy
        /// Sent from a phone: the app, or the iPhone shortcut.
        case phone
        case universalClipboard = "universal-clipboard"

        /// Also takes "iphone", the name before phones other than the iPhone.
        public init(from decoder: Decoder) throws {
            let s = try decoder.singleValueContainer().decode(String.self)
            guard let via = Via(rawValue: s == "iphone" ? Via.phone.rawValue : s) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown via \(s)"))
            }
            self = via
        }
    }

    /// A hybrid logical clock timestamp: milliseconds since the Unix epoch
    /// and a counter, written as "<wall>.<logical>".
    public struct Timestamp: Comparable, Hashable, Sendable, Codable, CustomStringConvertible {
        public var wall: UInt64
        public var logical: UInt32
        /// The last millisecond of 9999.
        public static let maxWall: UInt64 = 253_402_300_799_999
        public static let zero = Timestamp(wall: 0, logical: 0)

        public init(wall: UInt64, logical: UInt32) { (self.wall, self.logical) = (wall, logical) }

        /// Parses the text form: two decimal numbers and a dot, no sign or
        /// spaces, the wall time at most maxWall.
        public init?(text: String) {
            let parts = text.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 2, parts.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy { (0x30...0x39).contains($0) } }),
                  let w = UInt64(parts[0]), let l = UInt32(parts[1]), w <= Timestamp.maxWall else { return nil }
            (wall, logical) = (w, l)
        }

        public var description: String { "\(wall).\(logical)" }
        public var isZero: Bool { self == .zero }

        public static func < (a: Timestamp, b: Timestamp) -> Bool {
            a.wall != b.wall ? a.wall < b.wall : a.logical < b.logical
        }

        public init(from decoder: Decoder) throws {
            let s = try decoder.singleValueContainer().decode(String.self)
            guard let t = Timestamp(text: s) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "bad timestamp \(s)"))
            }
            self = t
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.singleValueContainer()
            try c.encode(description)
        }
    }

    /// One copy, as it travels between members.
    public struct Event: Codable, Equatable, Sendable {
        public var id: String
        public var origin: String
        public var via: Via
        public var time: Timestamp
        /// Milliseconds since the copy, as of the moment the frame is written.
        public var ageMS: Int64
        public var kind: Kind
        /// The text; "" only in the mark of a secret.
        public var text: String

        enum CodingKeys: String, CodingKey { case id, origin, via, time, ageMS = "age_ms", kind, text }

        public init(id: String, origin: String, via: Via = .copy, time: Timestamp, ageMS: Int64 = 0, kind: Kind, text: String) {
            (self.id, self.origin, self.via, self.time, self.ageMS, self.kind, self.text) = (id, origin, via, time, ageMS, kind, text)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            origin = try c.decode(String.self, forKey: .origin)
            via = try c.decodeIfPresent(Via.self, forKey: .via) ?? .copy
            time = try c.decode(Timestamp.self, forKey: .time)
            ageMS = try c.decodeIfPresent(Int64.self, forKey: .ageMS) ?? 0
            kind = try c.decode(Kind.self, forKey: .kind)
            text = try c.decodeIfPresent(String.self, forKey: .text) ?? ""
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(id, forKey: .id)
            try c.encode(origin, forKey: .origin)
            if via != .copy { try c.encode(via, forKey: .via) } // absent means copy
            try c.encode(time, forKey: .time)
            try c.encode(ageMS, forKey: .ageMS)
            try c.encode(kind, forKey: .kind)
            try c.encode(text, forKey: .text)
        }

        /// Whether it is the mark of a secret: the event without its text.
        public var isMark: Bool { kind == .secret && text.isEmpty }

        /// The mark of this event: a secret without its text, as a hello
        /// carries it.
        public var mark: Event {
            var m = self
            if kind == .secret { m.text = "" }
            return m
        }

        /// Checks an event received from another member, as Go's
        /// Event.Validate does.
        public var isValid: Bool {
            guard GroupCertificates.isDeviceID(id), GroupCertificates.isDeviceID(origin),
                  !time.isZero, time.wall <= Timestamp.maxWall, ageMS >= 0 else { return false }
            return isMark || (!text.isEmpty && text.utf8.count <= Member.maxText)
        }

        /// Whether it sorts after f: by time, then by ID, so every member
        /// orders any two events the same way.
        public func isLater(than f: Event) -> Bool {
            time != f.time ? time > f.time : id > f.id
        }
    }

    /// The first message of each side.
    public struct Hello: Equatable, Sendable {
        /// The sender's wall clock, milliseconds since the Unix epoch; for
        /// skew reports only.
        public var wallMS: Int64
        /// The sender's current event; a secret only as its mark. nil when
        /// there is none, or when it did not decode.
        public var current: Event?
        /// The digest of the sender's records (section 10).
        public var records: String?
        /// The sender's device name.
        public var name: String?
        /// From a computer that is no admin yet: the SubjectPublicKeyInfo of
        /// its admin key, for the root to certify (section 10, "A computer
        /// as admin").
        public var adminKey: Data?

        public init(wallMS: Int64, current: Event? = nil, records: String? = nil, name: String? = nil, adminKey: Data? = nil) {
            (self.wallMS, self.current, self.records, self.name, self.adminKey) = (wallMS, current, records, name, adminKey)
        }
    }

    /// A signed record of the group (section 10), carried as it came.
    public struct Record: Codable, Equatable, Sendable {
        public var body: Data
        public var sig: Data
        public var chain: [Data]?

        public init(body: Data, sig: Data, chain: [Data]? = nil) { (self.body, self.sig, self.chain) = (body, sig, chain) }
    }

    /// One message of the protocol.
    public enum Message: Equatable, Sendable {
        case hello(Role, Hello)
        /// An event; nil when it did not decode, for example from a newer
        /// version, which is dropped without ending the connection.
        case event(Event?)
        case ping
        case bye
        /// A renewed member certificate for the receiver, DER, and the
        /// admin CA that issued it when an admin phone did.
        case cert(Data, issuer: Data? = nil)
        case records([Record])
        /// From the root: the receiver's admin CA, DER, for the admin key
        /// its hello offered.
        case admin(Data)
        /// A type from a newer version, ignored.
        case unknown(String)
    }

    public enum WireError: Error, Equatable {
        case tooLarge, short, notAMessage, badHello(String)
    }

    /// Encodes a message as a frame: the length, then the JSON.
    public static func encode(_ m: Message) throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
        let body = try enc.encode(WireOut(m))
        guard body.count <= maxFrame else { throw WireError.tooLarge }
        var n = UInt32(body.count).bigEndian
        return Data(bytes: &n, count: 4) + body
    }

    /// The length a frame header announces, or an error when too large.
    public static func length(header: Data) throws -> Int {
        guard header.count == 4 else { throw WireError.short }
        let n = header.reduce(0) { $0 << 8 | Int($1) }
        guard n <= maxFrame else { throw WireError.tooLarge }
        return n
    }

    /// Decodes the body of a frame. A hello whose role is unknown or whose
    /// hello object does not decode is an error; an event that does not
    /// decode is .event(nil).
    public static func decode(body: Data) throws -> Message {
        guard let w = try? JSONDecoder().decode(WireIn.self, from: body) else { throw WireError.notAMessage }
        switch w.t {
        case "hello":
            guard let r = w.role, let role = Role(rawValue: r) else { throw WireError.badHello("unknown role") }
            guard let h = w.hello else { throw WireError.badHello("no hello object") }
            return .hello(role, Hello(wallMS: h.wall_ms ?? 0, current: h.current?.value, records: h.records, name: h.name,
                                      adminKey: h.admin_key))
        case "event": return .event(w.event?.value)
        case "ping": return .ping
        case "bye": return .bye
        case "cert": return .cert(w.cert ?? Data(), issuer: w.issuer)
        case "records": return .records(w.records ?? [])
        case "admin": return .admin(w.admin_ca ?? Data())
        default: return .unknown(w.t)
        }
    }

    /// Keeps a value that may not decode, for parts of a message that a
    /// newer version may change.
    struct Lenient<T: Decodable>: Decodable {
        let value: T?
        init(from decoder: Decoder) throws { value = try? T(from: decoder) }
    }

    struct WireHello: Decodable {
        var wall_ms: Int64?
        var current: Lenient<Event>?
        var records: String?
        var name: String?
        var admin_key: Data?
    }

    struct WireIn: Decodable {
        var t: String
        var role: String?
        var hello: WireHello?
        var event: Lenient<Event>?
        var cert: Data?
        var issuer: Data?
        var records: [Record]?
        var admin_ca: Data?
    }

    struct WireOut: Encodable {
        let m: Message
        init(_ m: Message) { self.m = m }

        enum Keys: String, CodingKey { case t, role, hello, event, cert, issuer, records, admin_ca }
        enum HelloKeys: String, CodingKey { case wall_ms, current, records, name, admin_key }

        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: Keys.self)
            switch m {
            case let .hello(role, h):
                try c.encode("hello", forKey: .t)
                try c.encode(role, forKey: .role)
                var hc = c.nestedContainer(keyedBy: HelloKeys.self, forKey: .hello)
                try hc.encode(h.wallMS, forKey: .wall_ms)
                try hc.encodeIfPresent(h.current, forKey: .current)
                try hc.encodeIfPresent(h.records, forKey: .records)
                try hc.encodeIfPresent(h.name, forKey: .name)
                try hc.encodeIfPresent(h.adminKey, forKey: .admin_key)
            case let .event(e):
                try c.encode("event", forKey: .t)
                try c.encodeIfPresent(e, forKey: .event)
            case .ping: try c.encode("ping", forKey: .t)
            case .bye: try c.encode("bye", forKey: .t)
            case let .cert(d, issuer):
                try c.encode("cert", forKey: .t)
                try c.encode(d, forKey: .cert)
                try c.encodeIfPresent(issuer, forKey: .issuer)
            case let .records(rs):
                try c.encode("records", forKey: .t)
                try c.encode(rs, forKey: .records)
            case let .admin(ca):
                try c.encode("admin", forKey: .t)
                try c.encode(ca, forKey: .admin_ca)
            case let .unknown(t): try c.encode(t, forKey: .t)
            }
        }
    }
}
