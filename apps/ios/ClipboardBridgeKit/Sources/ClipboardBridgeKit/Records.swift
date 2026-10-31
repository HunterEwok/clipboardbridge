// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// The group's signed device, revocation and root records (docs/protocol.md,
/// section 10), as internal/group/records.go makes and reads them. The root
/// phone signs them with the root key, without a chain; an admin phone
/// signs them with its admin CA key, and the chain holds the admin CA.
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
        public var os: String?
        public var key: Data?
        public var admin: Data?
        /// Where the device's keys live: "file", "hardware" or "proven" (store(_:role:)).
        public var store: String?
        /// With a checked attestation: the kind of hardware and the hex
        /// SHA-256 of the attestation's leaf.
        public var kind: String?
        public var proof: String?
        // revoke
        public var keys: [Data]?
        public var keep: [Data]?
        // root
        public var root: Data?
        // freeze: the records of the frozen admins that still count; thaw:
        // the freeze records it ends. Both are record IDs.
        public var records: [Data]?

        public init(type: String, group: String, timeMS: Int64, by: String?) {
            (self.type, self.group, self.time_ms, self.by) = (type, group, timeMS, by)
        }

        /// The members every record's body has.
        static let fields = ["v", "type", "group", "time_ms"]
        /// A body is at most this long.
        static let maxBody = 8 << 10

        /// The body in data, or nil when it does not decode or is not
        /// valid: in the strict form of signed bodies, checked as Go's
        /// RecordBody.check.
        public static func decode(_ data: Data) -> Body? {
            guard data.count <= maxBody, Strict.ok(data, required: fields), let b = try? JSONDecoder().decode(Body.self, from: data),
                  let raw = try? JSONDecoder().decode(Raw.self, from: data), raw.canonical, b.valid else { return nil }
            return b
        }

        /// The bytes of a body as their strings, to check their form.
        private struct Raw: Decodable {
            var key, admin, root: String?
            var keys, keep, records: [String]?

            var canonical: Bool {
                ([key, admin, root].compactMap { $0 } + (keys ?? []) + (keep ?? []) + (records ?? [])).allSatisfy { Strict.base64($0) != nil }
            }
        }

        /// Whether the fields its type needs are there and valid, as Go's
        /// RecordBody.check.
        var valid: Bool {
            guard v == Records.version else { return false }
            let hashes = [key, admin].compactMap { $0 } + (keys ?? []) + (keep ?? []) + (records ?? [])
            guard hashes.allSatisfy({ $0.count == 32 }) else { return false }
            switch type {
            case "device":
                let os = os ?? ""
                return key != nil && Records.isDeviceID(device) && Records.validName(name) && Records.roles.contains(Records.role(role))
                    && (os.isEmpty || Records.systems.contains(os))
            case "revoke", "freeze": return !(keys ?? []).isEmpty
            case "root": return !(root ?? Data()).isEmpty
            case "thaw": return !(records ?? []).isEmpty
            default: return false
            }
        }
    }

    /// The roles of device records, after role(_:).
    static let roles: Set<String> = ["full", "phone", "lite", "shortcut", "watch"]

    /// The systems device records name.
    static let systems: Set<String> = ["linux", "windows", "macos", "ios", "android", "watchos", "wearos", "none"]

    /// Whether s is a device ID: 32 of 0-9 and a-f.
    static func isDeviceID(_ s: String?) -> Bool {
        guard let s, s.utf8.count == 32 else { return false }
        return s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    /// Whether s is a device name: 1 to 64 bytes of UTF-8 without control
    /// characters.
    static func validName(_ s: String?) -> Bool {
        guard let s, !s.isEmpty, s.utf8.count <= 64 else { return false }
        return !s.unicodeScalars.contains { $0.value < 0x20 || (0x7f...0x9f).contains($0.value) }
    }

    /// The hash that names a key in records: SHA-256 over a
    /// SubjectPublicKeyInfo.
    public static func keyHash(spki: Data) -> Data { Data(SHA256.hash(data: spki)) }

    /// The hash of the key a certificate certifies.
    public static func keyHash(cert: Data) throws -> Data { keyHash(spki: try CertificateInfo(der: cert).publicKey) }

    public static let file = "file"
    public static let hardware = "hardware"
    /// A key in hardware whose attestation a signer checked.
    public static let proven = "proven"
    /// A rootless install's keys: in a file every program of its user may
    /// read, so the device is never the root, an admin or a hub (D-79).
    public static let rootless = "rootless"

    /// Where a device's keys live, as its record's store field says
    /// (docs/protocol.md, section 17): file, hardware, proven or rootless. Without
    /// one, as before 0.6, or with one this version does not know, a
    /// phone's and a watch's keys are in hardware and any other device's in
    /// a file.
    public static func store(_ store: String?, role: String) -> String {
        switch store {
        case let s? where s == file || s == hardware || s == proven || s == rootless: s
        default: role == "phone" || role == "watch" ? hardware : file
        }
    }

    /// The role a record names, with the roles of earlier records read as
    /// today's.
    static func role(_ r: String?) -> String {
        switch r {
        case "linux", "mac": "full"
        case "iphone": "shortcut"
        default: r ?? ""
        }
    }

    /// The system a record names, or the one its earlier role implies.
    static func os(_ b: Body) -> String? {
        if let os = b.os { return os }
        switch b.role {
        case "mac": return "macos"
        case "iphone", "shortcut": return "ios"
        default: return nil
        }
    }

    /// A record's ID: SHA-256 over its body.
    public static func id(_ r: Member.Record) -> Data { Data(SHA256.hash(data: r.body)) }

    /// Signs a body with the group CA key (the phone's root), or with an
    /// admin CA key when adminCA is that CA's certificate.
    public static func sign(_ body: Body, with signer: CertificateSigner, adminCA: Data? = nil) throws -> Member.Record {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try enc.encode(body)
        return Member.Record(body: data, sig: try signer.signature(for: data), chain: adminCA.map { [$0] })
    }

    /// A device record. admin is the key hash of the device's admin CA, for
    /// an admin phone.
    public static func device(_ device: String, name: String, role: String, os: String? = nil, key: Data, admin: Data? = nil,
                              store: String? = nil, kind: String? = nil, proof: String? = nil, group: String, by: String, now: Date,
                              signer: CertificateSigner, adminCA: Data? = nil) throws -> Member.Record {
        var b = Body(type: "device", group: group, timeMS: ms(now), by: by)
        (b.device, b.name, b.role, b.os, b.key, b.admin, b.store) = (device, name, role, os, key, admin, store)
        (b.kind, b.proof) = (kind, proof)
        return try sign(b, with: signer, adminCA: adminCA)
    }

    /// A revocation record for keys; keep names the keys of devices that
    /// a revoked admin admitted and that stay.
    public static func revoke(_ keys: [Data], keep: [Data]? = nil, group: String, by: String, now: Date,
                              signer: CertificateSigner, adminCA: Data? = nil) throws -> Member.Record {
        var b = Body(type: "revoke", group: group, timeMS: ms(now), by: by)
        (b.keys, b.keep) = (keys, keep)
        return try sign(b, with: signer, adminCA: adminCA)
    }

    /// A freeze record for the admin CAs with key hashes keys (docs/protocol.md,
    /// section 10, rule 4); records names what they signed until now, which
    /// keeps counting.
    public static func freeze(_ keys: [Data], records: [Data], group: String, by: String, now: Date,
                              signer: CertificateSigner, adminCA: Data? = nil) throws -> Member.Record {
        var b = Body(type: "freeze", group: group, timeMS: ms(now), by: by)
        (b.keys, b.records) = (keys, records)
        return try sign(b, with: signer, adminCA: adminCA)
    }

    /// A thaw record that ends the freeze records with the IDs freezes
    /// (docs/protocol.md, section 10, rule 4).
    public static func thaw(_ freezes: [Data], group: String, by: String, now: Date, signer: CertificateSigner,
                            adminCA: Data? = nil) throws -> Member.Record {
        var b = Body(type: "thaw", group: group, timeMS: ms(now), by: by)
        b.records = freezes
        return try sign(b, with: signer, adminCA: adminCA)
    }

    /// A root record that hands the group to newRoot, a phone's root CA.
    public static func root(_ newRoot: Data, group: String, by: String, now: Date, signer: CertificateSigner,
                            adminCA: Data? = nil) throws -> Member.Record {
        var b = Body(type: "root", group: group, timeMS: ms(now), by: by)
        b.root = newRoot
        return try sign(b, with: signer, adminCA: adminCA)
    }

    static func ms(_ d: Date) -> Int64 { Int64((d.timeIntervalSince1970 * 1000).rounded(.down)) }
}

/// The record set of a group: verified records, which only grow, and what
/// they say. Like the Go side, what it says depends on the set alone.
public struct RecordSet: Codable, Equatable, Sendable {
    public private(set) var records: [Member.Record] = []
    /// The group's first root, which names it; the first add sets it.
    public internal(set) var groupCA: Data?

    /// Records beyond this many are refused.
    public static let max = 4096
    /// Records one signer (an admin CA, or a root's own key) signs at most,
    /// so a stolen admin cannot fill the set and shut the others out; past
    /// max the set still takes this many records from a path root's own
    /// key, so it takes the root's removal of an admin that filled it.
    public static let maxPerAdmin = 1024

    /// The roots records may be signed under: the group CA and the new root
    /// of every root record that may make it a known root (mayBeKnown); the
    /// other root records wait in pending, as Go's group.Records.
    private var rootList: [Data] = []
    private var pending: [Pending] = []
    /// For each root, the admin CAs that device records its own key signed
    /// name (namedPhone, namedWatch or namedOther), and the roles of its
    /// own device records.
    private var named: [Data: [Data: Int]] = [:]
    private var own: [Data: Int] = [:]
    /// The records each signer signed (maxPerAdmin).
    private var perSigner: [Data: Int] = [:]
    /// The ID and the signer's key hash of each record: a body that several
    /// signers signed is a record for each, so which signer's copy came
    /// first changes nothing.
    private var envelopes = Set<Data>()

    private struct Pending: Sendable {
        var root: Data
        var anchor: Data
        var signer: Data
    }

    private static let namedPhone = 1, namedOther = 2, namedWatch = 4

    private enum CodingKeys: String, CodingKey { case records, groupCA }

    public init() {}

    /// A set read back adds its records again, so that what it keeps of
    /// them follows the same rules as for records from the peers.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let rs = try c.decode([Member.Record].self, forKey: .records)
        if let ca = try c.decodeIfPresent(Data.self, forKey: .groupCA) {
            addAll(rs, groupCA: ca)
            groupCA = ca
        } else {
            records = rs // a set saved before root records; its owner adds them again with the group CA
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(records, forKey: .records)
        try c.encodeIfPresent(groupCA, forKey: .groupCA)
    }

    public static func == (a: RecordSet, b: RecordSet) -> Bool { a.records == b.records && a.groupCA == b.groupCA }

    /// A device as the list shows it.
    public struct Device: Equatable, Sendable, Identifiable {
        public var id: String
        public var name: String
        /// "full", "phone", "lite", "shortcut" or "watch"; earlier records'
        /// "linux" and "mac" read as "full", "iphone" as "shortcut".
        public var role: String
        /// Its operating system; nil when its record does not tell.
        public var os: String?
        public var key: Data
        /// Whether it is an admin phone whose admin CA is not revoked.
        public var admin = false
        /// The key hash of its admin CA, for an admin phone.
        public var adminKey: Data?
        /// An admin computer another admin froze: no admin until the root
        /// or an admin phone unfreezes it, and refused.
        public var frozen = false
        /// Every key that a counting device record names for it and that is
        /// not revoked, key among them: what removing it revokes.
        public var keys: [Data] = []
        /// Where its keys live: Records.file, Records.hardware, Records.proven
        /// or Records.rootless.
        public var store = Records.file
        /// The kind of hardware and the hash of the attestation the root
        /// checked, if any.
        public var kind: String?
        public var proof: String?
    }

    /// Adds a record signed under one of the group's roots, by the root's
    /// key or by an admin CA the root certified (its chain holds that CA),
    /// unless it is known; reports whether it was new. Records of another
    /// group are refused, and so is a record signed under a root that no
    /// root record in the set may make known yet. The limits are checked
    /// after the signature: maxPerAdmin for each signer, and past max only
    /// records a path root's own key signed, up to maxPerAdmin more.
    @discardableResult
    public mutating func add(_ r: Member.Record, groupCA: Data) -> Bool {
        if self.groupCA == nil { self.groupCA = groupCA }
        if rootList.isEmpty { rootList = [groupCA] }
        let id = Records.id(r)
        guard self.groupCA == groupCA, !holds(r),
              let body = Records.Body.decode(r.body),
              body.v == Records.version, body.group == GroupCertificates.tag(groupCA: groupCA),
              let anchor = Self.anchor(r, roots: rootList), let anchorKey = try? Records.keyHash(cert: anchor.root) else { return false }
        if body.type == "root" {
            guard (try? ParsedCertificate(der: anchor.root))?.pathLength == 1, let root = body.root,
                  (try? GroupCertificates.checkRoot(root)) != nil else { return false }
        }
        let signer = anchor.signer, n = perSigner[signer] ?? 0
        guard !envelopes.contains(id + signer), n < Self.maxPerAdmin else { return false }
        if records.count >= Self.max {
            guard records.count < Self.max + Self.maxPerAdmin, signer == anchorKey, Eval(self).onPath.contains(anchorKey) else { return false }
        }
        perSigner[signer] = n + 1
        envelopes.insert(id + signer)
        records.append(r)
        if body.type == "device" && signer == anchorKey {
            let bit = switch Records.role(body.role) {
            case "phone": Self.namedPhone
            case "watch": Self.namedWatch
            default: Self.namedOther
            }
            if let a = body.admin { named[anchorKey, default: [:]][a, default: 0] |= bit }
            if body.device != nil && body.device == body.by { own[anchorKey, default: 0] |= bit }
        }
        if body.type == "root", let root = body.root { pending.append(Pending(root: root, anchor: anchorKey, signer: signer)) }
        promote()
        return true
    }

    /// Whether the set holds exactly r: its body with the same signature
    /// and chain.
    private func holds(_ r: Member.Record) -> Bool {
        records.contains { $0.body == r.body && $0.sig == r.sig && ($0.chain ?? []) == (r.chain ?? []) }
    }

    /// Moves the root records of pending that may make their new root known
    /// into rootList, until none does.
    private mutating func promote() {
        var grew = true
        while grew {
            grew = false
            var rest: [Pending] = []
            for p in pending {
                guard mayBeKnown(p) else {
                    rest.append(p)
                    continue
                }
                if !rootList.contains(p.root) {
                    rootList.append(p.root)
                    grew = true
                }
            }
            pending = rest
        }
    }

    /// Whether a root record may make its new root a known root, leaving
    /// out the revocations and freezes that can still stop it: the root's
    /// own key signed it, or an admin CA that a phone's device record from
    /// that root's own key names, or one a computer's names when that root
    /// is a computer. A root that a computer's admin CA names in a phone's
    /// group is never known, so nothing signed under it enters the set.
    private func mayBeKnown(_ p: Pending) -> Bool {
        let n = named[p.anchor]?[p.signer] ?? 0
        return p.signer == p.anchor || n & Self.namedPhone != 0 || (n & Self.namedOther != 0 && own[p.anchor] == Self.namedOther)
    }

    /// Adds every record of rs that is valid, until nothing new is added,
    /// so that a record signed under a new root is taken together with the
    /// records that make that root known, in any order; returns the new
    /// ones.
    @discardableResult
    public mutating func addAll(_ rs: [Member.Record], groupCA: Data) -> [Member.Record] {
        var fresh: [Member.Record] = [], pending = rs
        while true {
            var rest: [Member.Record] = []
            let roots = rootList.count
            for r in pending {
                if add(r, groupCA: groupCA) {
                    fresh.append(r)
                } else if !holds(r) {
                    rest.append(r)
                }
            }
            if rootList.count == roots || rest.isEmpty { return fresh }
            pending = rest
        }
    }

    /// The roots records may be signed under (rootList).
    private func knownRoots(_ groupCA: Data) -> [Data] { rootList.isEmpty ? [groupCA] : rootList }

    /// The root a record was signed under and the key hash of its signer:
    /// a root's own key without a chain, an admin CA under a root with one;
    /// nil when the signature is not valid under any of roots.
    private static func anchor(_ r: Member.Record, roots: [Data]) -> (root: Data, signer: Data)? {
        guard let sig = try? P256.Signing.ECDSASignature(derRepresentation: r.sig) else { return nil }
        func verifies(_ spki: Data) -> Bool {
            P256.Signing.PublicKey(spki: spki)?.isValidSignature(sig, for: r.body) ?? false
        }
        switch r.chain ?? [] {
        case []:
            for root in roots {
                if let spki = try? CertificateInfo(der: root).publicKey, verifies(spki) { return (root, Records.keyHash(spki: spki)) }
            }
            return nil
        case let c where c.count == 1:
            guard let root = roots.first(where: { (try? GroupCertificates.checkAdminCA(c[0], root: $0)) != nil }),
                  let spki = try? CertificateInfo(der: c[0]).publicKey, verifies(spki) else { return nil }
            return (root, Records.keyHash(spki: spki))
        default: return nil
        }
    }

    /// Entries by ID and then signer, as Go sorts records.
    private static func byEnvelope(_ a: Entry, _ b: Entry) -> Bool {
        a.id == b.id ? a.signer.lexicographicallyPrecedes(b.signer) : a.id.lexicographicallyPrecedes(b.id)
    }

    private struct Entry {
        var record: Member.Record
        var body: Records.Body
        /// The record ID.
        var id: Data
        /// The key hash of the signer: a root, or an admin CA.
        var signer: Data
        /// The key hash of the root it was signed under.
        var anchor: Data
    }

    /// What the set says, worked out once for a question: the records with
    /// their signers, the revoked keys and the path of roots. Revocations
    /// are worked out in strata that do not depend on each other in a
    /// circle, as Go's group.Records.eval (docs/protocol.md, section 10,
    /// rules 2 and 3).
    private struct Eval {
        var entries: [Entry] = []
        var revoked: Set<Data> = []
        /// The records that revoked each key, by record ID.
        var revokers: [Data: [Data]] = [:]
        /// The admin CAs of admin phones, which a root recorded.
        var phoneAdmin: Set<Data> = []
        /// The admin CAs of watches, which a root recorded (rule 8).
        var watch: Set<Data> = []
        /// The known roots: the group CA and the new roots that a known
        /// root or an admin phone under one handed the group to, or an
        /// admin computer under a root that is a computer.
        var known: Set<Data> = []
        /// The freezes that count, for each frozen admin CA (rule 4).
        var freezes: [Data: [Entry]] = [:]
        /// The device keys of the frozen admins.
        var frozenKeys: Set<Data> = []
        /// The roots from the group CA to the current one, DER.
        var path: [Data] = []
        var onPath: Set<Data> = []
        /// The root records that lead along path, one for each root after
        /// the group CA.
        var steps: [Entry] = []

        init(_ set: RecordSet) {
            guard let groupCA = set.groupCA else { return }
            let roots = set.knownRoots(groupCA)
            entries = set.records.compactMap { r in
                guard let b = Records.Body.decode(r.body),
                      let a = RecordSet.anchor(r, roots: roots), let anchor = try? Records.keyHash(cert: a.root) else { return nil }
                return Entry(record: r, body: b, id: Records.id(r), signer: a.signer, anchor: anchor)
            }
            evaluate(groupCA: groupCA, roots: roots)
            // From each root, the root record under it that counts and
            // whose new root has the smallest SHA-256 leads to the next.
            path = [groupCA]
            onPath = [(try? Records.keyHash(cert: groupCA)) ?? Data()]
            while let cur = path.last.flatMap({ try? Records.keyHash(cert: $0) }) {
                let next = entries.compactMap { e -> (Data, Data, Entry)? in
                    guard e.body.type == "root", e.anchor == cur, let root = e.body.root, let k = try? Records.keyHash(cert: root),
                          !onPath.contains(k), !revoked.contains(e.signer), fromRoot(e), mayHandOver(e) else { return nil }
                    return (root, k, e)
                }.min { Data(SHA256.hash(data: $0.0)).lexicographicallyPrecedes(Data(SHA256.hash(data: $1.0))) }
                guard let next else { break }
                path.append(next.0)
                onPath.insert(next.1)
                steps.append(next.2)
            }
        }

        /// Whether a known root's own key signed e.
        func rootSigned(_ e: Entry) -> Bool { e.signer == e.anchor && known.contains(e.anchor) }

        /// Whether the signer of a root record may hand the group over: a
        /// known root's own key, an admin phone's admin CA, or a computer's
        /// admin CA when the root it replaces is a computer too
        /// (computerHandOver).
        func mayHandOver(_ e: Entry) -> Bool {
            rootSigned(e) || (phoneAdmin.contains(e.signer) && known.contains(e.anchor))
                || (known.contains(e.anchor) && Self.computerHandOver(e, entries))
        }

        /// Whether e, a root record, was signed by the admin CA of a
        /// computer under its anchor, a root that is a computer itself, and
        /// only that root's own records stop it: a revocation of the admin
        /// CA, or a freeze of it that the root or another admin CA it
        /// certified (and did not revoke) signed and the root did not thaw,
        /// as Go's group.Records.computerHandOver (docs/protocol.md, section
        /// 10, rule 2).
        private static func computerHandOver(_ e: Entry, _ entries: [Entry]) -> Bool {
            guard e.body.root != nil, e.signer != e.anchor else { return false }
            let root = e.anchor
            var admins: Set<Data> = [], freezers: Set<Data> = [], revoked: Set<Data> = [], thawed: Set<Data> = []
            var computer = false
            for o in entries where o.signer == root && o.anchor == root {
                let b = o.body
                switch b.type {
                case "revoke": revoked.formUnion(b.keys ?? [])
                case "thaw": thawed.formUnion(b.records ?? [])
                case "device":
                    let own = b.device != nil && b.device == b.by
                    if own && Records.role(b.role) == "phone" { return false }
                    if own && Records.role(b.role) == "full" { computer = true }
                    // A watch freezes an admin computer as any admin does,
                    // but never takes the group over.
                    if let a = b.admin, Records.role(b.role) != "phone" {
                        freezers.insert(a)
                        if Records.role(b.role) != "watch" { admins.insert(a) }
                    }
                default: break
                }
            }
            guard computer, admins.contains(e.signer), !revoked.contains(e.signer) else { return false }
            return !entries.contains { o in
                o.body.type == "freeze" && o.anchor == root && (o.body.keys ?? []).contains(e.signer) && !thawed.contains(o.id)
                    && (o.signer == root || (freezers.contains(o.signer) && !revoked.contains(o.signer)))
            }
        }

        /// The admin CA key that e, a device record of a phone signed by the
        /// own key of one of roots, names; nil for any other record.
        /// The roots the group CA hands on to: by the roots' own keys, by
        /// the admin computers, and by the admin phones under these roots
        /// that are not in removed; with nil by no phone (Go's handedOn).
        private static func handedOn(_ entries: [Entry], _ ca: Set<Data>, removed: Set<Data>?) -> Set<Data> {
            var known = ca
            var grew = true
            while grew {
                grew = false
                let phones = removed == nil ? [] : phoneAdmins(entries, known)
                for e in entries where e.body.type == "root" && known.contains(e.anchor) {
                    let byPhone = phones.contains(e.signer) && !(removed?.contains(e.signer) ?? true)
                    guard e.signer == e.anchor || computerHandOver(e, entries) || byPhone else { continue }
                    if let root = e.body.root, let rk = try? Records.keyHash(cert: root), known.insert(rk).inserted { grew = true }
                }
            }
            return known
        }

        /// The admin CAs of the phones that the own keys of roots certified.
        private static func phoneAdmins(_ entries: [Entry], _ roots: Set<Data>) -> Set<Data> {
            Set(entries.compactMap { phoneAdmin(of: $0, roots: roots) })
        }

        /// The keys that a revoke from the own key of one of roots names,
        /// and those that a revoke from an admin phone under them names when
        /// no such revoke names that phone, each with the IDs of the records
        /// that name it (Go's removals).
        private static func removals(_ entries: [Entry], _ roots: Set<Data>) -> [Data: [Data]] {
            let phones = phoneAdmins(entries, roots)
            var out: [Data: [Data]] = [:]
            for e in entries where e.body.type == "revoke" && e.signer == e.anchor && roots.contains(e.anchor) {
                for key in e.body.keys ?? [] { out[key, default: []].append(Records.id(e.record)) }
            }
            let byRoot = Set(out.keys)
            for e in entries where e.body.type == "revoke" && phones.contains(e.signer) && roots.contains(e.anchor) && !byRoot.contains(e.signer) {
                for key in e.body.keys ?? [] { out[key, default: []].append(Records.id(e.record)) }
            }
            return out
        }

        private static func phoneAdmin(of e: Entry, roots: Set<Data>) -> Data? {
            guard e.body.type == "device", Records.role(e.body.role) == "phone", e.signer == e.anchor, roots.contains(e.signer) else {
                return nil
            }
            return e.body.admin
        }

        private mutating func evaluate(groupCA: Data, roots: [Data]) {
            let all = Set(roots.compactMap { try? Records.keyHash(cert: $0) })
            // The roots that surely count and those that may count, in turns
            // until neither changes, as Go's knownRoots: a root counts only
            // when it surely counts, and an admin phone that a root that may
            // count removes is removed when no root that counts removes it.
            let ca = Set([try? Records.keyHash(cert: groupCA)].compactMap { $0 })
            var k = Self.handedOn(entries, ca, removed: nil)
            var disputed: [Data: [Data]] = [:]
            while true {
                let may = Self.handedOn(entries, ca, removed: Set(Self.removals(entries, k).keys))
                let next = Self.handedOn(entries, ca, removed: Set(Self.removals(entries, may).keys))
                if next.count == k.count {
                    let removed = Self.removals(entries, k)
                    let phones = Self.phoneAdmins(entries, k)
                    for (key, ids) in Self.removals(entries, may) where phones.contains(key) && removed[key] == nil {
                        disputed[key] = ids
                    }
                    break
                }
                k = next
            }
            known = k
            var byRoot: [Data: [Entry]] = [:]
            var privileged = all
            for e in entries {
                if e.body.type == "revoke" && rootSigned(e) {
                    for key in e.body.keys ?? [] { byRoot[key, default: []].append(e) }
                } else if e.body.type == "device", rootSigned(e), let a = e.body.admin {
                    // Only a root's own record makes a key an admin's.
                    privileged.insert(a)
                }
                if e.signer != e.anchor { privileged.insert(e.signer) }
            }
            func standsForRoots(_ issuer: Data, _ key: Data) -> Bool {
                (byRoot[issuer] ?? []).allSatisfy { ($0.body.keep ?? []).contains(key) }
            }
            for e in entries {
                if let a = Self.phoneAdmin(of: e, roots: known), standsForRoots(e.signer, a) { phoneAdmin.insert(a) }
                if e.body.type == "device", Records.role(e.body.role) == "watch", rootSigned(e), let a = e.body.admin { watch.insert(a) }
            }
            // An admin phone whose removal is in dispute is removed, by the
            // records that would remove it.
            var disabled: Set<Data> = []
            for (key, ids) in disputed {
                phoneAdmin.remove(key)
                disabled.insert(key)
                revoked.insert(key)
                revokers[key] = ids
            }
            for e in entries where e.body.type == "revoke" && (rootSigned(e) || (phoneAdmin.contains(e.signer) && known.contains(e.anchor))) {
                for key in e.body.keys ?? [] where privileged.contains(key) && (rootSigned(e) || !known.contains(key)) {
                    disabled.insert(key)
                    revoked.insert(key)
                    revokers[key, default: []].append(Records.id(e.record))
                }
            }
            // The device keys of each computer's admin CA, and the freezes
            // that a root or an admin phone ended.
            var computers: [Data: [Data]] = [:]
            var thawed: Set<Data> = []
            for e in entries {
                let b = e.body
                if b.type == "device", let a = b.admin, let key = b.key, Records.role(b.role) != "phone", rootSigned(e), !phoneAdmin.contains(a) {
                    computers[a, default: []].append(key)
                } else if b.type == "thaw",
                          rootSigned(e) || (phoneAdmin.contains(e.signer) && known.contains(e.anchor) && !disabled.contains(e.signer)) {
                    thawed.formUnion(b.records ?? [])
                }
            }
            // A frozen admin's freezes still count, so two admins that freeze
            // each other both stay frozen until the root or an admin phone
            // decides.
            for e in entries where e.body.type == "freeze" && !thawed.contains(e.id) && known.contains(e.anchor) {
                if e.signer != e.anchor && (disabled.contains(e.signer) || !standsForRoots(e.anchor, e.signer)) { continue }
                let keys = e.body.keys ?? []
                guard !keys.isEmpty, keys.allSatisfy({ computers[$0] != nil }) else { continue }
                for key in keys {
                    freezes[key, default: []].append(e)
                    frozenKeys.formUnion(computers[key] ?? [])
                }
            }
            for e in entries where e.body.type == "revoke" && kept(e) {
                let keys = e.body.keys ?? []
                let counts: Bool
                if e.signer == e.anchor {
                    counts = known.contains(e.anchor)
                } else {
                    counts = known.contains(e.anchor) && !disabled.contains(e.signer) && standsForRoots(e.anchor, e.signer)
                        && !keys.contains { known.contains($0) || (privileged.contains($0) && !phoneAdmin.contains(e.signer)) }
                }
                guard counts else { continue }
                let id = Records.id(e.record)
                for key in keys where !(revokers[key] ?? []).contains(id) {
                    revokers[key, default: []].append(id)
                    revoked.insert(key)
                }
            }
        }

        /// Whether every freeze of e's signer names e, as for the records of
        /// an admin that is not frozen.
        func kept(_ e: Entry) -> Bool {
            (freezes[e.signer] ?? []).allSatisfy { ($0.body.records ?? []).contains(e.id) }
        }

        /// Whether a key is frozen: a frozen admin CA, or the device key of a
        /// frozen admin.
        func frozen(_ k: Data) -> Bool { freezes[k] != nil || frozenKeys.contains(k) }

        /// Whether a device record counts; a watch's admits nobody (rule 8).
        func counts(_ e: Entry) -> Bool {
            onPath.contains(e.anchor) && fromRoot(e) && issued(e.signer, e.body.key ?? Data()) && kept(e) && !watch.contains(e.signer)
        }

        /// Whether issuer is revoked only by records that keep the key k, as
        /// when an admin is removed and the devices it admitted stay.
        func kept(_ issuer: Data, _ k: Data) -> Bool {
            guard let ids = revokers[issuer], !ids.isEmpty else { return false }
            return entries.filter { ids.contains(Records.id($0.record)) }.allSatisfy { ($0.body.keep ?? []).contains(k) }
        }

        /// Whether what issuer certified, the key k, still stands.
        func issued(_ issuer: Data, _ k: Data) -> Bool { !revoked.contains(issuer) || kept(issuer, k) }

        /// Whether the admin CA that signed a record still stands under its
        /// root; a root's own signature always does.
        func fromRoot(_ e: Entry) -> Bool { e.signer == e.anchor || issued(e.anchor, e.signer) }
    }

    /// The revoked keys (docs/protocol.md, section 10, rule 3).
    public var revoked: Set<Data> { Eval(self).revoked }

    /// Whether a command (docs/protocol.md, section 15) is signed by an
    /// admin of the group now: a root on the path, or an admin CA under one
    /// that is neither revoked nor frozen, as Go's Records.VerifyCommand.
    public func signedByAdmin(_ c: Member.Record) -> Bool {
        guard let groupCA, let a = RecordSet.anchor(c, roots: knownRoots(groupCA)),
              let anchor = try? Records.keyHash(cert: a.root) else { return false }
        let ev = Eval(self)
        return ev.onPath.contains(anchor) && !ev.revoked.contains(a.signer) && !ev.frozen(a.signer)
            && (a.signer == anchor || ev.issued(anchor, a.signer))
    }

    /// The device whose admin key signed command c, as Go's
    /// Records.CommandSigner: the device that holds the group's root when
    /// the root's own key signed it, or the device whose record names the
    /// admin CA that did. nil when no listed device holds the key, as for an
    /// admin phone whose own record is not here yet.
    public func signerDevice(_ c: Member.Record) -> String? {
        guard let groupCA, let a = RecordSet.anchor(c, roots: knownRoots(groupCA)),
              let anchor = try? Records.keyHash(cert: a.root) else { return nil }
        if a.signer == anchor {
            guard let id = rootMember()?.device else { return nil }
            return devices.first { $0.id == id }?.id
        }
        return devices.first { $0.adminKey == a.signer }?.id
    }

    /// Whether a watch's admin CA signed the record or command c
    /// (docs/protocol.md, section 10, rule 8), whose powers are few.
    public func signedByWatch(_ c: Member.Record) -> Bool {
        guard let groupCA, let a = RecordSet.anchor(c, roots: knownRoots(groupCA)) else { return false }
        return isWatch(a.signer)
    }

    /// Whether a key hash is a watch's admin CA (rule 8): one that a device
    /// record of a watch, signed by a known root's own key, names.
    public func isWatch(_ keyHash: Data) -> Bool { Eval(self).watch.contains(keyHash) }

    /// Whether a key hash is frozen (docs/protocol.md, section 10, rule 4): a
    /// computer's admin CA that a freeze names, or such an admin's device
    /// key.
    public func isFrozen(_ keyHash: Data) -> Bool { Eval(self).frozen(keyHash) }

    /// The IDs of the freezes of the admin CA with key hash admin that
    /// count: what a thaw of it ends.
    public func freezes(of admin: Data) -> [Data] {
        (Eval(self).freezes[admin] ?? []).map(\.id).sorted { $0.lexicographicallyPrecedes($1) }
    }

    /// The roots that took the group over from the group CA, in order, DER;
    /// the last is the current root. Empty when it was never handed over.
    public var roots: [Data] { Array(Eval(self).path.dropFirst()) }

    /// Why a member certificate chain (leaf first, then its admin CA when
    /// one issued it) is refused, or nil; the chain is verified already. A
    /// certificate is refused when its key is revoked, or its issuer's key
    /// is revoked and not every record that revoked the issuer keeps it:
    /// for the leaf and, when an admin CA issued it, for that admin CA under
    /// its root.
    public func refused(chain: [Data]) -> String? {
        guard let leafCert = chain.first, var leaf = try? Records.keyHash(cert: leafCert) else { return "no certificate" }
        let ev = Eval(self)
        if ev.revoked.contains(leaf) { return "the device was removed from the group" }
        if ev.frozen(leaf) { return "the device is a frozen admin" }
        var top = leafCert
        // The issuer is the certificate that signed the leaf, wherever it is
        // in the chain: a peer may add certificates it does not need.
        if !ev.path.contains(where: { GroupCertificates.signed(leafCert, by: $0) }) {
            guard let issuer = chain.dropFirst().first(where: { GroupCertificates.signed(leafCert, by: $0) }),
                  let admin = try? Records.keyHash(cert: issuer) else {
                return "the certificate's issuer is not in its chain"
            }
            if ev.watch.contains(admin) { return "a watch certifies no devices" }
            if !ev.issued(admin, leaf) { return "the admin that admitted the device was removed" }
            // A frozen admin's certificates hold only for devices the records
            // already list.
            if ev.frozen(admin) && !ev.entries.contains(where: { $0.body.type == "device" && $0.body.key == leaf && ev.counts($0) }) {
                return "the admin that certified the device is frozen"
            }
            (top, leaf) = (issuer, admin)
        }
        // The chain must end at a root on the path: a root that only the
        // identity trusts, as one a Welcome named, is no anchor.
        guard let root = ev.path.first(where: { GroupCertificates.signed(top, by: $0) }) else {
            return "the certificate is not from a root of the group"
        }
        if let rk = try? Records.keyHash(cert: root), !ev.issued(rk, leaf) {
            return "the certificate is from a root that handed the group over"
        }
        return nil
    }

    /// The records that lead to the path: each root record on it and, for
    /// one an admin CA signed, the device records its root's own key signed
    /// that name that admin CA or the root's own device, as Go's
    /// Records.PathRecords. A new member gets them in the Welcome's records
    /// (docs/protocol.md, section 5).
    public var pathRecords: [Member.Record] {
        let ev = Eval(self)
        var out: [Member.Record] = []
        for st in ev.steps {
            out.append(st.record)
            if st.signer == st.anchor { continue }
            out += ev.entries.filter { e in
                let b = e.body
                return b.type == "device" && e.signer == st.anchor && e.anchor == st.anchor
                    && ((b.device != nil && b.device == b.by) || b.admin == st.signer)
            }.sorted(by: Self.byEnvelope).map(\.record)
        }
        return out
    }

    /// The records that say who governs the group, as Go's
    /// Records.AuthorityRecords: the path records, every record that is no
    /// device record (revocations, freezes, thaws, roots), and of the device
    /// records a root signed with its own key those of a root's own device
    /// and of every device that one of them ever made an admin, all of them,
    /// so that a later one that demotes it counts. A phone hub sends them to
    /// its forwarder (docs/protocol.md, section 13); the other devices'
    /// records, with their names, stay in the group.
    public var authorityRecords: [Member.Record] {
        var seen = Set<Data>()
        var out: [Member.Record] = []
        func add(_ r: Member.Record) {
            if seen.insert(Records.id(r) + r.sig).inserted { out.append(r) }
        }
        pathRecords.forEach(add)
        let ev = Eval(self)
        let governs = Set(ev.entries.compactMap { e -> String? in
            let b = e.body
            guard b.type == "device", e.signer == e.anchor, b.admin != nil || (b.device != nil && b.device == b.by) else { return nil }
            return b.device
        })
        for e in ev.entries.sorted(by: Self.byEnvelope) {
            if e.body.type != "device" || (e.signer == e.anchor && e.body.device.map(governs.contains) == true) { add(e.record) }
        }
        return out
    }

    /// The devices list: the latest device record that counts for each
    /// device (by time, then record ID) among those whose key is not
    /// revoked, sorted by name. A device record counts when it was signed
    /// under a root on the path, by an admin CA that still stands under it,
    /// and its signer is not revoked, or every revocation of the signer
    /// keeps the device's key. A device whose records name more than one
    /// key stays listed while any of them is not revoked, as Go's
    /// Records.Devices: one whose signer is not revoked comes after one
    /// whose signer is, and a device is an admin, with that record's role
    /// and store, only by the latest of its records a known root's own key
    /// signed.
    public var devices: [Device] {
        let ev = Eval(self)
        var latest: [String: Entry] = [:]
        var certified: [String: Entry] = [:] // the latest a known root's own key signed
        var keys: [String: [Data]] = [:]
        func newer(_ e: Entry, _ cur: Entry) -> Bool {
            e.body.time_ms != cur.body.time_ms ? e.body.time_ms > cur.body.time_ms : Self.byEnvelope(cur, e)
        }
        // By record ID, as Go, so the keys come in the same order.
        for e in ev.entries.sorted(by: Self.byEnvelope) where e.body.type == "device" {
            guard ev.counts(e), let d = e.body.device, let k = e.body.key, !ev.revoked.contains(k) else { continue }
            if !(keys[d] ?? []).contains(k) { keys[d, default: []].append(k) }
            if ev.rootSigned(e), certified[d].map({ newer(e, $0) }) ?? true { certified[d] = e }
            let stands = !ev.revoked.contains(e.signer)
            if let cur = latest[d] {
                let curStands = !ev.revoked.contains(cur.signer)
                if !(stands && !curStands || stands == curStands && newer(e, cur)) { continue }
            }
            latest[d] = e
        }
        return latest.compactMap { d, e -> Device? in
            let b = e.body
            guard let key = b.key else { return nil }
            // a is the record that says what powers the device has: only a
            // root's own record makes it an admin.
            let c = certified[d].flatMap { $0.body.admin == nil ? nil : $0.body }
            let a = c ?? b
            let admin = c?.admin
            return Device(id: d, name: b.name ?? d, role: Records.role(a.role), os: Records.os(b), key: key,
                          admin: admin.map { !ev.revoked.contains($0) && !ev.frozen($0) } ?? false, adminKey: admin,
                          frozen: ev.frozen(key) || admin.map(ev.frozen) ?? false, keys: keys[d] ?? [key],
                          store: Records.store(a.store, role: Records.role(a.role)), kind: a.kind, proof: a.proof)
        }.sorted { ($0.name, $0.id) < ($1.name, $1.id) }
    }

    /// The keys that revocations signed by the admin CA with key hash admin
    /// revoked and that count: what the record that removes that admin
    /// names again, so its removals stand once its own records no longer
    /// count (section 10).
    public func revokedBy(_ admin: Data) -> [Data] {
        let ev = Eval(self)
        var keys: [Data] = []
        for e in ev.entries where e.body.type == "revoke" && e.signer == admin {
            let id = Records.id(e.record)
            for k in e.body.keys ?? [] where (ev.revokers[k] ?? []).contains(id) && !keys.contains(k) { keys.append(k) }
        }
        return keys
    }

    /// The IDs of the records the CA with key hash admin signed: what a
    /// freeze of it keeps counting, as Go's Records.SignedBy.
    public func signed(by admin: Data) -> [Data] {
        Eval(self).entries.filter { $0.signer == admin }.map { Records.id($0.record) }
    }

    /// The keys of the devices whose records the CA with key hash admin
    /// signed (an admin CA, or a root's own key): the devices it admitted,
    /// which stay when it is removed.
    public func admitted(by admin: Data) -> [Data] {
        var keys: [Data] = []
        let ev = Eval(self)
        for e in ev.entries where e.body.type == "device" && e.signer == admin && ev.kept(e) {
            if let k = e.body.key, !keys.contains(k) { keys.append(k) }
        }
        return keys
    }

    /// The keys a revocation of the CA with key hash admin keeps: those of
    /// the devices it admitted, and those of every listed device, whose
    /// certificate it may have renewed; and the keys of the admin CAs
    /// removed earlier whose removals keep one of those devices, since their
    /// certificates for it hold only while their admin CA stands under its
    /// root, which a takeover removes (section 10), as Go's
    /// Records.Staying. The caller drops the keys the revocation names.
    public func staying(by admin: Data) -> [Data] {
        var keys = admitted(by: admin)
        for d in devices {
            for k in d.keys where !keys.contains(k) { keys.append(k) }
        }
        let ev = Eval(self)
        let removed = ev.revokers.keys.filter { r in !keys.contains(r) && keys.contains { ev.kept(r, $0) } }
        return keys + removed.sorted { $0.lexicographicallyPrecedes($1) }
    }

    /// Whether a valid device record names the device ID, with any key and
    /// whether or not it counts: an ID a new device may not take (section
    /// 6).
    public func knows(_ device: String) -> Bool {
        records.contains { Records.Body.decode($0.body).map { $0.type == "device" && $0.device == device } ?? false }
    }

    /// The phone that holds the root: the one whose own record the current
    /// root's key signed (a phone records itself when it makes the group,
    /// and again when it takes the group over).
    public var rootDevice: String? {
        let ev = Eval(self)
        guard let cur = ev.path.last.flatMap({ try? Records.keyHash(cert: $0) }) else { return nil }
        return ev.entries.filter {
            $0.signer == cur && $0.body.type == "device" && $0.body.role == "phone" && $0.body.device != nil && $0.body.device == $0.body.by
        }.max { $0.body.time_ms < $1.body.time_ms }?.body.device
    }

    /// Whether device may be the group's hub for sync away from home: the
    /// root (a device whose own record the current root's key signed, a
    /// phone or a computer, as Go's Records.RootMember) or a device listed as
    /// an admin whose admin CA is not revoked, other than a watch, which never
    /// connects to the group (docs/protocol.md, section 11).
    /// Only by device ID: MemberNode passes on an offer only from a peer that
    /// mayHost(_:chain:) takes, which also checks the key.
    public func mayHost(_ device: String) -> Bool {
        if devices.contains(where: { $0.id == device && $0.admin && $0.role != "watch" }) { return true }
        guard let root = rootMember() else { return false }
        return root.device == device && !Eval(self).revoked.contains(root.key)
    }

    /// mayHost for a peer whose verified certificate chain (leaf first) is
    /// chain: the record that makes it the root or an admin must name the
    /// key of its certificate, since a device ID alone is what a joining
    /// device picks itself.
    public func mayHost(_ device: String, chain: [Data]) -> Bool {
        guard let leaf = chain.first, let key = try? Records.keyHash(cert: leaf) else { return false }
        if devices.contains(where: { $0.id == device && $0.admin && $0.role != "watch" && $0.key == key }) { return true }
        guard let root = rootMember() else { return false }
        return root.device == device && root.key == key && !Eval(self).revoked.contains(key)
    }

    /// The devices that may be the group's hub, highest first, as Go's
    /// Records.HubOrder (docs/protocol.md, section 11, "Several hubs"):
    /// phones before computers, within each the root first, then by device
    /// ID.
    public var hubOrder: [String] {
        let root = rootMember().flatMap { Eval(self).revoked.contains($0.key) ? nil : $0.device }
        return devices.filter { $0.id == root || ($0.admin && $0.role != "watch") }
            .sorted { a, b in
                if (a.role == "phone") != (b.role == "phone") { return a.role == "phone" }
                if (a.id == root) != (b.id == root) { return a.id == root }
                return a.id < b.id
            }
            .map(\.id)
    }

    /// The root's own device and its key: the newest full or phone device
    /// record the current root signed for itself.
    func rootMember() -> (device: String, key: Data)? {
        let ev = Eval(self)
        guard let cur = ev.path.last.flatMap({ try? Records.keyHash(cert: $0) }) else { return nil }
        let own = ev.entries.filter {
            $0.signer == cur && $0.body.type == "device" && ["phone", "full"].contains(Records.role($0.body.role)) &&
                $0.body.device != nil && $0.body.device == $0.body.by
        }.max { $0.body.time_ms < $1.body.time_ms }
        guard let own, let id = own.body.device, let key = own.body.key else { return nil }
        return (device: id, key: key)
    }

    /// SHA-256 over each record's ID and signer's key hash, sorted by ID and
    /// then signer, base64, as the hello carries it; nil for an empty set.
    public var digest: String? {
        guard !records.isEmpty else { return nil }
        let ids = Eval(self).entries.map { $0.id + $0.signer }.sorted { $0.lexicographicallyPrecedes($1) }
        var h = SHA256()
        for id in ids { h.update(data: id) }
        return Data(h.finalize()).base64EncodedString()
    }
}
