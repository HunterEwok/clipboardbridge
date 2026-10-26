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
    /// What a member does: `full` is a computer with the service (Linux,
    /// Windows or macOS); its system is the hello's `os`.
    public enum Role: String, Codable, Sendable { case full, phone, lite }

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
        /// The sender's operating system: "linux", "windows", "macos",
        /// "ios", "android" or "none"; shown, never trusted.
        public var os: String?
        /// From a computer that is no admin yet: the SubjectPublicKeyInfo of
        /// its admin key, for the root to certify (section 10, "A computer
        /// as admin").
        public var adminKey: Data?
        /// The sender's WireGuard public key, 32 bytes, for the group's
        /// hub (section 11).
        public var tunnelKey: Data?
        /// With tunnelKey, the preshared key the sender chose for its
        /// tunnels, 32 bytes, so every hub of the group uses the same one
        /// (section 11, "Several hubs"); nil from an older member.
        public var tunnelPSK: Data?
        /// What the sender says about its device, for showing.
        public var device: DeviceInfo?
        /// The sender's sync mode: "own", "shared", "receive" or "send";
        /// nil from a member without one, which shares.
        public var mode: String?
        /// Where the sender says its keys live: Records.file or
        /// Records.hardware; nil from a member before 0.6.
        public var keyStore: String?

        public init(wallMS: Int64, current: Event? = nil, records: String? = nil, name: String? = nil, os: String? = nil,
                    adminKey: Data? = nil, tunnelKey: Data? = nil, tunnelPSK: Data? = nil, device: DeviceInfo? = nil, mode: String? = nil,
                    keyStore: String? = nil) {
            (self.wallMS, self.current, self.records, self.name, self.os, self.adminKey, self.tunnelKey) =
                (wallMS, current, records, name, os, adminKey, tunnelKey)
            (self.tunnelPSK, self.device, self.mode, self.keyStore) = (tunnelPSK, device, mode, keyStore)
        }
    }

    /// The sync modes (design.md, "Sync modes").
    public static let modes: Set<String> = ["own", "shared", "receive", "send"]

    /// Whether a device in sync mode mode takes the group's copies into its
    /// clipboard by itself; a device without a mode (nil) shares.
    public static func receives(_ mode: String?) -> Bool { mode == nil || mode == "shared" || mode == "receive" }

    /// Whether a device in sync mode mode sends its own copies to the group by itself.
    public static func sends(_ mode: String?) -> Bool { mode == nil || mode == "shared" || mode == "send" }

    /// The answer to a command (section 15): its ID, "done", "refused" or
    /// "failed", and why for the last two.
    public struct CommandResult: Codable, Equatable, Sendable {
        public var id: String
        public var status: String
        public var reason: String?
        /// In the result of a hub command, the new hub's offer without a
        /// preshared key (section 11, "Moving the hub").
        public var tunnel: TunnelOffer?

        public init(id: String, status: String, reason: String? = nil, tunnel: TunnelOffer? = nil) {
            (self.id, self.status, self.reason, self.tunnel) = (id, status, reason, tunnel)
        }

        public var done: Bool { status == "done" }
    }

    /// What a hello says about the sender's device (section 4, "Device"):
    /// its form, its system's version, its own version and its network
    /// card's MAC address. Shown, never trusted; any field may be absent.
    public struct DeviceInfo: Codable, Equatable, Sendable {
        /// The forms a device may name, for its icon.
        public static let forms = ["laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other"]

        public var form: String?
        public var osVersion: String?
        public var version: String?
        public var mac: String?

        enum CodingKeys: String, CodingKey { case form, osVersion = "os_version", version, mac }

        public init(form: String? = nil, osVersion: String? = nil, version: String? = nil, mac: String? = nil) {
            (self.form, self.osVersion, self.version, self.mac) = (form, osVersion, version, mac)
        }

        /// The same without its invalid fields: an unknown form, a version
        /// longer than 32 bytes or with control characters, a MAC address
        /// other than six lowercase hex bytes with colons; nil when nothing
        /// is left.
        public var cleaned: DeviceInfo? {
            func short(_ s: String?) -> String? {
                guard let s, !s.isEmpty, s.utf8.count <= 32, !s.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return nil }
                return s
            }
            let hex = Set("0123456789abcdef")
            let parts = mac?.split(separator: ":", omittingEmptySubsequences: false) ?? []
            let macOK = parts.count == 6 && parts.allSatisfy { $0.count == 2 && $0.allSatisfy(hex.contains) }
            let d = DeviceInfo(form: form.flatMap { Self.forms.contains($0) ? $0 : nil }, osVersion: short(osVersion), version: short(version),
                               mac: macOK ? mac : nil)
            return d == DeviceInfo() ? nil : d
        }
    }

    /// The group's hub's answer to the tunnel key a hello carried (section
    /// 11): the hub's WireGuard public key, this member's own preshared key,
    /// the hub's addresses away from home, "ip:port" or "[ipv6]:port", the
    /// group's obfuscation settings, nil for plain WireGuard, and the way to
    /// the hub's forwarder over VLESS, nil without it.
    public struct TunnelOffer: Codable, Equatable, Sendable {
        public var hubKey: Data
        public var psk: Data
        public var endpoints: [String]
        public var obfuscation: Obfuscation?
        public var vless: VLESS?
        /// In an offer the hub passes on when it hands the hub over, the
        /// device that is the hub now (section 11, "Moving the hub"); nil
        /// when the sender is the hub.
        public var hub: String?
        /// Whether the sender is no hub any more and hands its clients over
        /// to hub: the client forgets the sender's own offer.
        public var moved: Bool

        public init(hubKey: Data, psk: Data, endpoints: [String] = [], obfuscation: Obfuscation? = nil, vless: VLESS? = nil, hub: String? = nil,
                    moved: Bool = false) {
            (self.hubKey, self.psk, self.endpoints, self.obfuscation, self.vless, self.hub) = (hubKey, psk, endpoints, obfuscation, vless, hub)
            self.moved = moved
        }

        /// Whether both keys are 32 bytes, as a tunnel needs.
        public var isValid: Bool { hubKey.count == 32 && psk.count == 32 && endpoints.count <= 8 }

        /// The same offer with another preshared key and hub, and moved set.
        public func with(psk: Data, hub: String?, moved: Bool = false) -> TunnelOffer {
            var o = self
            (o.psk, o.hub, o.moved) = (psk, hub, moved)
            return o
        }

        enum CodingKeys: String, CodingKey { case hub_key, psk, endpoints, obfuscation, vless, hub, moved }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            hubKey = try c.decodeIfPresent(Data.self, forKey: .hub_key) ?? Data()
            psk = try c.decodeIfPresent(Data.self, forKey: .psk) ?? Data()
            endpoints = try c.decodeIfPresent([String].self, forKey: .endpoints) ?? []
            obfuscation = try c.decodeIfPresent(Obfuscation.self, forKey: .obfuscation)
            vless = try c.decodeIfPresent(VLESS.self, forKey: .vless)
            hub = try c.decodeIfPresent(String.self, forKey: .hub)
            moved = try c.decodeIfPresent(Bool.self, forKey: .moved) ?? false
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(hubKey, forKey: .hub_key)
            try c.encode(psk, forKey: .psk)
            if !endpoints.isEmpty { try c.encode(endpoints, forKey: .endpoints) }
            try c.encodeIfPresent(obfuscation, forKey: .obfuscation)
            try c.encodeIfPresent(vless, forKey: .vless)
            try c.encodeIfPresent(hub, forKey: .hub)
            if moved { try c.encode(true, forKey: .moved) }
        }
    }

    /// What a hub tells the group's other hubs (section 11, "Several
    /// hubs"): whether it serves as the hub now, its offer without a
    /// preshared key, and its clients, itself among them, with their keys.
    public struct HubShare: Codable, Equatable, Sendable {
        public var serving: Bool
        public var offer: TunnelOffer?
        public var clients: [PhoneHub.Client]

        public init(serving: Bool = false, offer: TunnelOffer? = nil, clients: [PhoneHub.Client] = []) {
            (self.serving, self.offer, self.clients) = (serving, offer, clients)
        }

        enum CodingKeys: String, CodingKey { case serving, offer, clients }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            serving = try c.decodeIfPresent(Bool.self, forKey: .serving) ?? false
            offer = try c.decodeIfPresent(TunnelOffer.self, forKey: .offer)
            clients = try c.decodeIfPresent([PhoneHub.Client].self, forKey: .clients) ?? []
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            if serving { try c.encode(true, forKey: .serving) }
            try c.encodeIfPresent(offer, forKey: .offer)
            if !clients.isEmpty { try c.encode(clients, forKey: .clients) }
        }
    }

    /// The way to the hub's forwarder over VLESS with REALITY (section 11,
    /// "VLESS"); with it, the only way to the hub. The kit only carries it:
    /// the tunnel in mobile/cbbtun checks and uses it.
    public struct VLESS: Codable, Equatable, Sendable {
        public var endpoint: String
        public var publicKey: Data
        public var shortID: String
        public var serverName: String
        public var id: String

        public init(endpoint: String, publicKey: Data, shortID: String, serverName: String, id: String) {
            (self.endpoint, self.publicKey, self.shortID, self.serverName, self.id) = (endpoint, publicKey, shortID, serverName, id)
        }

        enum CodingKeys: String, CodingKey {
            case endpoint, id
            case publicKey = "public_key"
            case shortID = "short_id"
            case serverName = "server_name"
        }

        /// The settings as JSON, for mobile/cbbtun.
        public func jsonText() throws -> String {
            String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
        }
    }

    /// A group's AmneziaWG settings (section 11, "Obfuscation"), with
    /// AmneziaWG's own names. The kit only carries them: the tunnel in
    /// mobile/cbbtun checks and uses them.
    public struct Obfuscation: Codable, Equatable, Sendable {
        public var jc, jmin, jmax: Int
        public var s1, s2, s3, s4: Int
        public var h1, h2, h3, h4: String
        public var headerProtectionKey: Data

        enum CodingKeys: String, CodingKey {
            case jc, jmin, jmax, s1, s2, s3, s4, h1, h2, h3, h4
            case headerProtectionKey = "header_protection_key"
        }

        /// The settings as JSON, for mobile/cbbtun.
        public func jsonText() throws -> String {
            String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
        }
    }

    /// A signed record of the group (section 10), carried as it came.
    public struct Record: Codable, Equatable, Sendable {
        public var body: Data
        public var sig: Data
        public var chain: [Data]?

        public init(body: Data, sig: Data, chain: [Data]? = nil) { (self.body, self.sig, self.chain) = (body, sig, chain) }
    }

    /// An attestation of one of a device's keys (section 17, "Evidence"):
    /// format android with the Keystore's chain, leaf first, for the key
    /// member, made with the challenge of groupTag (nil outside a group) and
    /// salt.
    public struct Evidence: Codable, Equatable, Sendable {
        public static let android = "android-key"
        public static let member = "member"

        public var format: String
        public var key: String
        public var groupTag: String?
        public var salt: Data
        public var chain: [Data]

        public init(format: String, key: String, groupTag: String?, salt: Data, chain: [Data]) {
            (self.format, self.key, self.groupTag, self.salt, self.chain) = (format, key, groupTag, salt, chain)
        }

        enum CodingKeys: String, CodingKey {
            case format, key, salt, chain
            case groupTag = "group_tag"
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            format = try c.decodeIfPresent(String.self, forKey: .format) ?? ""
            key = try c.decodeIfPresent(String.self, forKey: .key) ?? ""
            groupTag = try c.decodeIfPresent(String.self, forKey: .groupTag).flatMap { $0.isEmpty ? nil : $0 }
            salt = try c.decodeIfPresent(Data.self, forKey: .salt) ?? Data()
            chain = try c.decodeIfPresent([Data].self, forKey: .chain) ?? []
        }
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
        /// From the group's hub: its offer for the tunnel key the
        /// receiver's hello carried; nil when absent or when it did not
        /// decode.
        case tunnel(TunnelOffer?)
        /// Between the group's hubs (section 11, "Several hubs"): whether
        /// the sender serves as the hub, its offer without a preshared key,
        /// and its clients with their keys, so any hub can take them.
        case hubs(HubShare)
        /// From an admin: a command signed for the receiver (section 15).
        case command(Record)
        /// The answer to a command.
        case result(CommandResult)
        /// An attestation of one of the sender's keys (section 17).
        case evidence(Evidence)
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
                                      os: h.os, adminKey: h.admin_key, tunnelKey: h.tunnel_key, tunnelPSK: h.tunnel_psk, device: h.device?.value,
                                      mode: h.mode.flatMap { modes.contains($0) ? $0 : nil },
                                      keyStore: h.key_store.flatMap { $0 == Records.file || $0 == Records.hardware ? $0 : nil }))
        case "event": return .event(w.event?.value)
        case "ping": return .ping
        case "bye": return .bye
        case "cert": return .cert(w.cert ?? Data(), issuer: w.issuer)
        case "records": return .records(w.records ?? [])
        case "admin": return .admin(w.admin_ca ?? Data())
        case "tunnel": return .tunnel(w.tunnel?.value)
        case "hubs": return w.hubs?.value.map { .hubs($0) } ?? .unknown(w.t)
        case "command": return w.command?.value.map { .command($0) } ?? .unknown(w.t)
        case "result": return w.result?.value.map { .result($0) } ?? .unknown(w.t)
        case "evidence": return w.evidence?.value.map { .evidence($0) } ?? .unknown(w.t)
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
        var os: String?
        var admin_key: Data?
        var tunnel_key: Data?
        var tunnel_psk: Data?
        var device: Lenient<DeviceInfo>?
        var mode: String?
        var key_store: String?
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
        var tunnel: Lenient<TunnelOffer>?
        var hubs: Lenient<HubShare>?
        var command: Lenient<Record>?
        var result: Lenient<CommandResult>?
        var evidence: Lenient<Evidence>?
    }

    struct WireOut: Encodable {
        let m: Message
        init(_ m: Message) { self.m = m }

        enum Keys: String, CodingKey { case t, role, hello, event, cert, issuer, records, admin_ca, tunnel, hubs, command, result, evidence }
        enum HelloKeys: String, CodingKey { case wall_ms, current, records, name, os, device, admin_key, tunnel_key, tunnel_psk, mode, key_store }

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
                try hc.encodeIfPresent(h.os, forKey: .os)
                try hc.encodeIfPresent(h.device, forKey: .device)
                try hc.encodeIfPresent(h.adminKey, forKey: .admin_key)
                try hc.encodeIfPresent(h.tunnelKey, forKey: .tunnel_key)
                try hc.encodeIfPresent(h.tunnelPSK, forKey: .tunnel_psk)
                try hc.encodeIfPresent(h.mode, forKey: .mode)
                try hc.encodeIfPresent(h.keyStore, forKey: .key_store)
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
            case let .tunnel(o):
                try c.encode("tunnel", forKey: .t)
                try c.encodeIfPresent(o, forKey: .tunnel)
            case let .hubs(h):
                try c.encode("hubs", forKey: .t)
                try c.encode(h, forKey: .hubs)
            case let .command(r):
                try c.encode("command", forKey: .t)
                try c.encode(r, forKey: .command)
            case let .result(r):
                try c.encode("result", forKey: .t)
                try c.encode(r, forKey: .result)
            case let .evidence(e):
                try c.encode("evidence", forKey: .t)
                try c.encode(e, forKey: .evidence)
            case let .unknown(t): try c.encode(t, forKey: .t)
            }
        }
    }
}
