// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Crypto
import Foundation

/// The signed files that describe a release (docs/protocol.md, section 16),
/// checked as internal/release does: keys.json, in which a root key
/// certifies the release keys; release.json, which lists a release's files
/// with their hashes; and a channel file such as stable.json, which names
/// the current release of its channel until it expires.
public enum Releases {
    /// The largest body a file may carry.
    public static let maxBody = 256 << 10
    /// The longest a keys or channel file may stay valid after it was signed.
    public static let maxLifetimeMS: Int64 = 100 * 24 * 3600 * 1000

    public struct Refused: Error, CustomStringConvertible {
        public let description: String
        init(_ s: String) { description = s }
    }

    /// The envelope of every release file; key is SHA-256 of the signer's
    /// SubjectPublicKeyInfo.
    public struct File: Codable, Equatable, Sendable {
        public var body: Data
        public var sig: Data
        public var key: Data

        /// SHA-256 over the body, which names a release.json.
        public var hash: Data { Data(SHA256.hash(data: body)) }

        func verify(_ spkis: [Data]) throws {
            guard body.count <= maxBody else { throw Refused("the file is too large") }
            guard let spki = spkis.first(where: { Data(SHA256.hash(data: $0)) == key }),
                  let pub = P256.Signing.PublicKey(spki: spki),
                  let s = try? P256.Signing.ECDSASignature(derRepresentation: sig),
                  pub.isValidSignature(s, for: body) else { throw Refused("the signature is not valid") }
        }
    }

    public struct Binary: Codable, Equatable, Sendable {
        public var name: String
        public var sha256: String
    }

    public struct Asset: Codable, Equatable, Sendable {
        public var name: String
        public var size: Int64
        public var sha256: String
        public var binaries: [Binary]?
    }

    public struct Docker: Codable, Equatable, Sendable {
        public var image: String
        public var digest: String
    }

    /// The body of release.json.
    public struct Release: Codable, Equatable, Sendable {
        public var version: String
        public var channel: String
        public var time_ms: Int64
        public var min_from: String?
        public var files: [Asset]
        public var docker: Docker?

        /// Whether a device at installed may update to this release in one
        /// step, or must first take min_from.
        public func direct(from installed: String) -> Bool {
            guard let m = min_from, !m.isEmpty else { return true }
            return compare(installed, m) >= 0
        }

        /// Checks that data is the release's file name.
        public func checkFile(_ name: String, _ data: Data) throws {
            guard let a = files.first(where: { $0.name == name }) else { throw Refused("\(name) is not in the release") }
            guard a.size == Int64(data.count), hex(Data(SHA256.hash(data: data))) == a.sha256 else {
                throw Refused("\(name) does not match release.json")
            }
        }
    }

    /// What a device keeps between checks: the highest sequence numbers and
    /// version it has taken.
    public struct Seen: Codable, Equatable, Sendable {
        public var keys_seq: UInt64 = 0
        public var channel_seq: UInt64 = 0
        public var version: String? = nil

        public init(keys_seq: UInt64 = 0, channel_seq: UInt64 = 0, version: String? = nil) {
            self.keys_seq = keys_seq
            self.channel_seq = channel_seq
            self.version = version
        }
    }

    struct Head: Decodable {
        var v: Int?
        var type: String?
    }

    struct Key: Decodable {
        var key: Data
        var name: String
    }

    struct Keys: Decodable {
        var seq: UInt64
        var time_ms: Int64
        var expires_ms: Int64
        var keys: [Key]
    }

    struct Channel: Decodable {
        var channel: String
        var seq: UInt64
        var time_ms: Int64
        var expires_ms: Int64
        var release: String
        var release_sha256: String
    }

    /// X, Y, Z and the release candidate's number, Int.max for a release.
    static func parseVersion(_ s: String) -> [Int]? {
        func number(_ p: Substring, zero: Bool) -> Int? {
            guard !p.isEmpty, p.count <= 6, p.allSatisfy({ $0.isASCII && $0.isNumber }),
                  (p.count == 1 && zero) || !p.hasPrefix("0") else { return nil }
            return Int(p)
        }
        var main = Substring(s)
        var rc = Int.max
        if let r = s.range(of: "-rc.") {
            guard let n = number(s[r.upperBound...], zero: false) else { return nil }
            main = s[..<r.lowerBound]
            rc = n
        }
        let parts = main.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }
        var out: [Int] = []
        for p in parts {
            guard let n = number(p, zero: true) else { return nil }
            out.append(n)
        }
        return out + [rc]
    }

    /// Compares two versions X.Y.Z or X.Y.Z-rc.N as -1, 0 or 1, a release
    /// candidate before its release; a string that is not a version sorts
    /// below every version.
    public static func compare(_ a: String, _ b: String) -> Int {
        switch (parseVersion(a), parseVersion(b)) {
        case (nil, nil): return 0
        case (nil, _): return -1
        case (_, nil): return 1
        case let (pa?, pb?):
            for i in 0..<4 where pa[i] != pb[i] { return pa[i] < pb[i] ? -1 : 1 }
            return 0
        }
    }

    static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    static func matches(_ s: String, _ pattern: String) -> Bool {
        s.range(of: pattern, options: .regularExpression) != nil
    }

    static let sha256RE = "^[0-9a-f]{64}$"
    static let channelRE = "^[a-z][a-z0-9-]{0,31}$"

    static func decode<T: Decodable>(_ body: Data, _ type: String, as: T.Type) throws -> T {
        guard let h = try? JSONDecoder().decode(Head.self, from: body) else { throw Refused("the file is not valid") }
        guard h.type == type else { throw Refused("the file is a \"\(h.type ?? "")\", not a \"\(type)\"") }
        guard h.v == 1 else { throw Refused("unknown version") }
        guard let v = try? JSONDecoder().decode(T.self, from: body) else { throw Refused("the file is not valid") }
        return v
    }

    static func lifetime(_ time: Int64, _ expires: Int64) throws {
        guard expires > time, expires - time <= maxLifetimeMS else { throw Refused("the file's lifetime is out of range") }
    }

    static func decodeKeys(_ body: Data) throws -> Keys {
        let k = try decode(body, "keys", as: Keys.self)
        guard k.seq > 0 else { throw Refused("keys.json has no sequence number") }
        try lifetime(k.time_ms, k.expires_ms)
        guard (1...8).contains(k.keys.count) else { throw Refused("keys.json must hold 1 to 8 keys") }
        for key in k.keys {
            guard !key.name.isEmpty, key.name.utf8.count <= 64 else { throw Refused("a release key has no valid name") }
            guard P256.Signing.PublicKey(spki: key.key) != nil else { throw Refused("a release key is not P-256") }
        }
        return k
    }

    static func decodeRelease(_ body: Data) throws -> Release {
        let r = try decode(body, "release", as: Release.self)
        guard parseVersion(r.version) != nil, (r.min_from ?? "").isEmpty || parseVersion(r.min_from!) != nil else {
            throw Refused("release.json names no valid version")
        }
        guard matches(r.channel, channelRE), (1...256).contains(r.files.count) else { throw Refused("release.json is not valid") }
        var names = Set<String>()
        for a in r.files {
            guard matches(a.name, "^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$"), names.insert(a.name).inserted else {
                throw Refused("\"\(a.name)\" is not a valid file name")
            }
            let bins = a.binaries ?? []
            guard a.size >= 0, matches(a.sha256, sha256RE), bins.count <= 64 else { throw Refused("the entry for \(a.name) is not valid") }
            for b in bins {
                guard matches(b.name, "^[A-Za-z0-9_][A-Za-z0-9._/-]{0,255}$"), !b.name.contains(".."), matches(b.sha256, sha256RE) else {
                    throw Refused("a binary in \(a.name) is not valid")
                }
            }
        }
        if let d = r.docker, d.image.isEmpty || !matches(d.digest, "^sha256:[0-9a-f]{64}$") {
            throw Refused("the Docker image is not valid")
        }
        return r
    }

    static func decodeChannel(_ body: Data) throws -> Channel {
        let c = try decode(body, "channel", as: Channel.self)
        guard matches(c.channel, channelRE), c.seq > 0 else { throw Refused("the channel file is not valid") }
        try lifetime(c.time_ms, c.expires_ms)
        guard parseVersion(c.release) != nil, matches(c.release_sha256, sha256RE) else {
            throw Refused("the channel file names no valid release")
        }
        return c
    }

    static func within<T>(_ file: String, _ f: () throws -> T) throws -> T {
        do { return try f() } catch let e as Refused { throw Refused("\(file): \(e.description)") }
    }

    /// Checks a channel file and the release.json it names: keys.json under
    /// the pinned roots (SubjectPublicKeyInfos, DER), the channel file and
    /// release.json under its release keys, the channel's name, both
    /// expiries, and that nothing is older than seen. Returns the release
    /// and the Seen to keep.
    public static func check(keys: File, channel: File, release: File, roots: [Data], name: String, nowMS: Int64,
                             seen: Seen) throws -> (Release, Seen) {
        let k = try within("keys.json") {
            try keys.verify(roots)
            let k = try decodeKeys(keys.body)
            guard nowMS < k.expires_ms else { throw Refused("the file has expired") }
            guard k.seq >= seen.keys_seq else { throw Refused("the file is older than one already seen") }
            return k
        }
        let spkis = k.keys.map(\.key)
        let c = try within("\(name).json") {
            try channel.verify(spkis)
            let c = try decodeChannel(channel.body)
            guard c.channel == name else { throw Refused("the file is for the channel \"\(c.channel)\"") }
            guard nowMS < c.expires_ms else { throw Refused("the file has expired") }
            guard c.seq >= seen.channel_seq else { throw Refused("the file is older than one already seen") }
            return c
        }
        let r = try within("release.json") {
            try release.verify(spkis)
            guard hex(release.hash) == c.release_sha256 else { throw Refused("it is not the release \(name).json names") }
            let r = try decodeRelease(release.body)
            guard r.version == c.release, r.channel == c.channel else {
                throw Refused("it is \(r.version) on \(r.channel), \(name).json names \(c.release)")
            }
            if let s = seen.version, !s.isEmpty, compare(r.version, s) < 0 { throw Refused("it is older than a release already seen") }
            return r
        }
        var version = r.version
        if let s = seen.version, !s.isEmpty, compare(s, r.version) > 0 { version = s }
        return (r, Seen(keys_seq: k.seq, channel_seq: c.seq, version: version))
    }
}
