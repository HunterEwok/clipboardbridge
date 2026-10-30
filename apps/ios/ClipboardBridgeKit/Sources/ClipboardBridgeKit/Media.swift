// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// The manifest of a media event: images or files (docs/protocol.md,
/// section 4, "Media"), checked as Go's package clip does. The kit takes the
/// event and its plain-text alternative; fetching the content comes later.
public enum Media {
    /// The largest copy, all its parts together, that the group carries.
    public static let maxMedia: Int64 = 1 << 30
    public static let maxParts = 10_000
    public static let maxTypes = 8
    public static let maxPaths = 512 << 10
    public static let maxPath = 4096
    public static let maxName = 255
    /// The largest plain-text alternative of a media event, in bytes of UTF-8.
    public static let maxAltText = 256 << 10
    public static let types: Set<String> = ["image/png", "image/jpeg", "text/html"]

    /// What a media event's content is.
    public struct Manifest: Codable, Equatable, Sendable {
        public var size: Int64
        public var parts: [Part]

        public init(size: Int64, parts: [Part]) { (self.size, self.parts) = (size, parts) }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            size = try c.decodeIfPresent(Int64.self, forKey: .size) ?? 0
            parts = try c.decodeIfPresent([Part].self, forKey: .parts) ?? []
        }

        /// Whether it is a copy of files, not clipboard data.
        public var isFiles: Bool { parts.first?.path != nil }

        /// Whether it passes Go's Manifest.Validate.
        public var isValid: Bool {
            guard !parts.isEmpty, parts.count <= Media.maxParts else { return false }
            let files = isFiles
            if !files && parts.count > Media.maxTypes { return false }
            var total: Int64 = 0
            var paths = 0
            var seen = Set<String>()
            for p in parts {
                let key: String
                if files {
                    guard let path = p.path, p.type == nil, Media.checkPath(path) else { return false }
                    paths += path.utf8.count
                    key = path
                } else {
                    guard let type = p.type, !p.dir, Media.types.contains(type) else { return false }
                    key = type
                }
                guard seen.insert(key).inserted else { return false }
                if p.dir {
                    if p.size != 0 || p.sha256 != nil { return false }
                    continue
                }
                guard p.sha256?.count == 32, p.size >= 0, p.size <= Media.maxMedia else { return false }
                total += p.size
            }
            guard paths <= Media.maxPaths, total == size, total <= Media.maxMedia else { return false }
            if files {
                var dirs: [String: Bool] = [:]
                for p in parts { dirs[p.path!] = p.dir }
                for p in parts {
                    let path = p.path!
                    var i = path.startIndex
                    while let slash = path[i...].firstIndex(of: "/") {
                        if dirs[String(path[..<slash])] == false { return false }
                        i = path.index(after: slash)
                    }
                }
            }
            return true
        }
    }

    /// One item of a manifest: clipboard data of a type, or a file or
    /// folder at a path.
    public struct Part: Codable, Equatable, Sendable {
        public var type: String?
        public var path: String?
        public var dir: Bool
        public var size: Int64
        public var sha256: Data?

        enum CodingKeys: String, CodingKey { case type, path, dir, size, sha256 }

        public init(type: String? = nil, path: String? = nil, dir: Bool = false, size: Int64 = 0, sha256: Data? = nil) {
            (self.type, self.path, self.dir, self.size, self.sha256) = (type, path, dir, size, sha256)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            type = try c.decodeIfPresent(String.self, forKey: .type).flatMap { $0.isEmpty ? nil : $0 }
            path = try c.decodeIfPresent(String.self, forKey: .path).flatMap { $0.isEmpty ? nil : $0 }
            dir = try c.decodeIfPresent(Bool.self, forKey: .dir) ?? false
            size = try c.decodeIfPresent(Int64.self, forKey: .size) ?? 0
            // An empty hash stays: a folder has none, as in Go, not even an empty one.
            sha256 = try c.decodeIfPresent(Data.self, forKey: .sha256)
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encodeIfPresent(type, forKey: .type)
            try c.encodeIfPresent(path, forKey: .path)
            if dir { try c.encode(true, forKey: .dir) }
            if size != 0 { try c.encode(size, forKey: .size) }
            try c.encodeIfPresent(sha256, forKey: .sha256)
        }
    }

    /// Whether path is names joined by "/", each one checkName takes, at
    /// most maxPath bytes.
    public static func checkPath(_ path: String) -> Bool {
        !path.isEmpty && path.utf8.count <= maxPath && path.split(separator: "/", omittingEmptySubsequences: false).allSatisfy { checkName(String($0)) }
    }

    /// Whether a name of a path is one every system can hold, as Go's
    /// clip.CheckName decides: 1 to 255 bytes, not "." or "..", no control
    /// characters, separators or characters Windows does not allow, no dot
    /// or space at the end, no name Windows reserves.
    public static func checkName(_ name: String) -> Bool {
        let n = name.utf8.count
        guard n > 0, n <= maxName, name != ".", name != ".." else { return false }
        if name.unicodeScalars.contains(where: { "/\\:*?\"<>|".unicodeScalars.contains($0) || $0.value < 0x20 || (0x7f...0x9f).contains($0.value) }) {
            return false
        }
        if name.hasSuffix(".") || name.hasSuffix(" ") { return false }
        return !reserved(name)
    }

    /// Whether name, before its first dot, is a device name of Windows:
    /// CON, PRN, AUX, NUL, COM1 to COM9 and LPT1 to LPT9, in any case.
    static func reserved(_ name: String) -> Bool {
        let base = String(name.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false).first ?? "").uppercased()
        if ["CON", "PRN", "AUX", "NUL"].contains(base) { return true }
        return base.utf8.count == 4 && (base.hasPrefix("COM") || base.hasPrefix("LPT")) && (0x31...0x39).contains(base.utf8.last ?? 0)
    }

    /// A name that checkName takes, made of one a system gave, as Go's
    /// clip.CleanName: the characters it does not allow become "_", a
    /// reserved name gets "_" after its base and one that ends in a dot or
    /// a space gets "_" after it.
    public static func cleanName(_ given: String) -> String {
        var scalars = String.UnicodeScalarView()
        for u in given.unicodeScalars {
            let bad = u.value < 0x20 || (0x7f...0x9f).contains(u.value) || "/\\:*?\"<>|".unicodeScalars.contains(u)
            scalars.append(bad ? "_" : u)
        }
        while String(scalars).utf8.count > maxName { scalars.removeLast() }
        var name = String(scalars)
        if name.isEmpty || name == "." || name == ".." { return "_" }
        if name.utf8.count == maxName {
            scalars.removeLast()
            name = String(scalars)
        }
        if reserved(name) {
            // CON.txt becomes CON_.txt: Windows reserves the base with any
            // extension.
            if let dot = name.firstIndex(of: ".") {
                name = String(name[..<dot]) + "_" + String(name[dot...])
            } else {
                name += "_"
            }
        }
        if name.hasSuffix(".") || name.hasSuffix(" ") { name += "_" }
        return name
    }
}
