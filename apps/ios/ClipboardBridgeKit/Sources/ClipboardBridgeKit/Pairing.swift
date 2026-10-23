// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// The pairing messages of docs/protocol.md, section 6, encoded as the Go
/// side encodes them: JSON objects whose byte fields are standard base64,
/// in frames of a 4-byte big-endian length.
public enum Pairing {
    /// The ALPN protocol of pairing connections.
    public static let alpn = "clipboardbridge-pair/1"
    /// The TLS exporter label for the CPace session ID.
    public static let exporterLabel = "EXPERIMENTAL-clipboardbridge-pair-v1"
    /// Frames larger than this are refused.
    public static let maxFrame = 64 << 10
    static let channelPrefix = Array("clipboardbridge pair v1\u{0}".utf8)

    /// One frame of the exchange; each uses some of the fields.
    public struct Frame: Codable, Equatable {
        public var msg: Data?
        public var ad: Data?
        public var tag: Data?
        public var welcome: Welcome?
        public var error: String?
        public var ok: Bool?

        public init(msg: Data? = nil, ad: Data? = nil, tag: Data? = nil, welcome: Welcome? = nil, error: String? = nil, ok: Bool? = nil) {
            (self.msg, self.ad, self.tag, self.welcome, self.error, self.ok) = (msg, ad, tag, welcome, error, ok)
        }
    }

    /// What a new device receives: its member certificate, the group CA
    /// and, for a Linux device in a group rooted in a Linux member, the CA
    /// keys. A phone root never sends keys; it may send a joining phone its
    /// admin CA.
    public struct Welcome: Codable, Equatable {
        public var cert: Data
        /// The admin CA that issued cert and the admitting phone's own
        /// certificate; nil when the group CA did.
        public var issuer: Data?
        /// The group's first root, which names it.
        public var groupCA: Data
        /// The roots that took a phone group over from groupCA, in order;
        /// nil when it was never handed over (section 10, "Roots").
        public var roots: [Data]?
        public var groupCAKey: Data?
        public var phoneCA: Data?
        public var phoneCAKey: Data?
        /// For a phone that joins as an admin: the admin CA the root issued
        /// for the admin key the phone sent in its Info.
        public var adminCA: Data?

        enum CodingKeys: String, CodingKey {
            case cert, issuer, groupCA = "group_ca", roots, groupCAKey = "group_ca_key", phoneCA = "phone_ca", phoneCAKey = "phone_ca_key",
                 adminCA = "admin_ca"
        }

        public init(cert: Data, groupCA: Data, issuer: Data? = nil, adminCA: Data? = nil) {
            (self.cert, self.groupCA, self.issuer, self.adminCA) = (cert, groupCA, issuer, adminCA)
        }
    }

    /// The joiner's CPace associated data.
    public struct Info: Codable, Equatable {
        public var name: String
        public var os: String // "linux", "darwin", or "ios" for a phone with the app
        /// A phone's admin key, a SubjectPublicKeyInfo, for the admin CA the
        /// root may issue it; only with os "ios".
        public var adminKey: Data?

        enum CodingKeys: String, CodingKey { case name, os, adminKey = "admin_key" }

        public init(name: String, os: String, adminKey: Data? = nil) { (self.name, self.os, self.adminKey) = (name, os, adminKey) }

        /// Checks it as the member does: a known OS, a printable name of 1
        /// to 64 bytes, and an admin key only from a phone, a P-256 one.
        public var isValid: Bool {
            guard ["linux", "darwin", "ios"].contains(os), !name.isEmpty, name.utf8.count <= 64,
                  !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return false }
            guard let adminKey else { return true }
            return os == "ios" && (try? P256.Signing.PublicKey(derRepresentation: adminKey)) != nil
        }
    }

    /// The member's CPace associated data.
    public struct MemberAD: Codable, Equatable {
        public var device: String
        public var group: String // the group tag

        public init(device: String, group: String) { (self.device, self.group) = (device, group) }
    }

    /// The error codes that travel in frames. Anything else means "refused".
    public enum ErrorCode: String {
        case wrongCode = "wrong-code", closed, busy, expired, tooMany = "too-many", refused
        public init(wire: String) { self = ErrorCode(rawValue: wire) ?? .refused }
    }

    /// The CPace channel identifier: the prefix, then SHA-256 of the
    /// member's and the joiner's certificate, in that order.
    public static func channelID(memberCert: Data, joinerCert: Data) -> [UInt8] {
        channelPrefix + Array(SHA256.hash(data: memberCert)) + Array(SHA256.hash(data: joinerCert))
    }

    /// The fingerprint a join QR code carries: SHA-256 of the certificate,
    /// in base64url without padding.
    public static func fingerprint(cert: Data) -> String {
        Data(SHA256.hash(data: cert)).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Encodes a frame: the length, then the JSON.
    public static func encode(_ f: Frame) throws -> Data {
        let body = try JSONEncoder().encode(f)
        guard body.count <= maxFrame else { throw FrameError.tooLarge }
        var n = UInt32(body.count).bigEndian
        return Data(bytes: &n, count: 4) + body
    }

    /// Decodes the body of a frame whose length was read already.
    public static func decode(body: Data) throws -> Frame {
        try JSONDecoder().decode(Frame.self, from: body)
    }

    /// The length a frame header announces, or an error when too large.
    public static func length(header: Data) throws -> Int {
        guard header.count == 4 else { throw FrameError.short }
        let n = header.reduce(0) { $0 << 8 | Int($1) }
        guard n <= maxFrame else { throw FrameError.tooLarge }
        return n
    }

    public enum FrameError: Error { case tooLarge, short }
}

/// What the QR code of cbb join carries (docs/protocol.md, section 7):
/// clipboardbridge://join?code=123456&addr=host:port&fp=...
public struct JoinCode: Equatable {
    public var code: String
    public var addrs: [String]
    public var fingerprint: String

    /// At most this many addresses are kept.
    public static let maxAddrs = 4

    public init(code: String, addrs: [String], fingerprint: String) {
        (self.code, self.addrs, self.fingerprint) = (code, addrs, fingerprint)
    }

    /// Parses the text of a join QR code; nil when it is not one. Unknown
    /// fields are ignored, and addresses without a port are dropped.
    public init?(qr text: String) {
        guard let u = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              u.scheme?.lowercased() == "clipboardbridge", u.host?.lowercased() == "join" else { return nil }
        let items = u.queryItems ?? []
        guard let code = items.first(where: { $0.name == "code" })?.value, !code.isEmpty else { return nil }
        self.code = code
        fingerprint = items.first(where: { $0.name == "fp" })?.value ?? ""
        addrs = items.filter { $0.name == "addr" }.compactMap(\.value).filter(JoinCode.hasPort).prefix(JoinCode.maxAddrs).map { $0 }
    }

    /// Whether a host:port, or [IPv6]:port, has a port.
    static func hasPort(_ a: String) -> Bool {
        guard let i = a.lastIndex(of: ":"), let port = UInt16(a[a.index(after: i)...]), port > 0 else { return false }
        let host = a[..<i]
        if host.hasPrefix("[") { return host.hasSuffix("]") }
        return !host.isEmpty && !host.contains(":")
    }

    /// Whether the code is six digits, as the computer expects.
    public var codeIsValid: Bool { code.count == 6 && code.allSatisfy { $0.isASCII && $0.isNumber } }

    /// The text of the QR code, as cbb join shows it.
    public var qrText: String {
        var u = URLComponents()
        (u.scheme, u.host) = ("clipboardbridge", "join")
        u.queryItems = [URLQueryItem(name: "code", value: code)] + addrs.prefix(Self.maxAddrs).map { URLQueryItem(name: "addr", value: $0) }
            + [URLQueryItem(name: "fp", value: fingerprint)]
        return u.string ?? ""
    }

    /// A new six-digit code.
    public static func newCode() -> String {
        String(format: "%06d", Int.random(in: 0..<1_000_000))
    }

    /// host:port, or [IPv6]:port, as a QR code carries an address.
    public static func address(host: String, port: UInt16) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}
