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
    }

    /// The hash that names a key in records: SHA-256 over a
    /// SubjectPublicKeyInfo.
    public static func keyHash(spki: Data) -> Data { Data(SHA256.hash(data: spki)) }

    /// The hash of the key a certificate certifies.
    public static func keyHash(cert: Data) throws -> Data { keyHash(spki: try CertificateInfo(der: cert).publicKey) }

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
                              group: String, by: String, now: Date, signer: CertificateSigner,
                              adminCA: Data? = nil) throws -> Member.Record {
        var b = Body(type: "device", group: group, timeMS: ms(now), by: by)
        (b.device, b.name, b.role, b.os, b.key, b.admin) = (device, name, role, os, key, admin)
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
    /// Records one admin CA signs at most, so a stolen admin cannot fill
    /// the set and shut the others out.
    public static let maxPerAdmin = 1024

    public init() {}

    /// A device as the list shows it.
    public struct Device: Equatable, Sendable, Identifiable {
        public var id: String
        public var name: String
        /// "full", "phone", "lite" or "shortcut"; earlier records' "linux"
        /// and "mac" read as "full", "iphone" as "shortcut".
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
    }

    /// Adds a record signed under one of the group's roots, by the root's
    /// key or by an admin CA the root certified (its chain holds that CA),
    /// unless it is known; reports whether it was new. Records of another
    /// group are refused, and so is a record signed under a root that no
    /// root record in the set names yet.
    @discardableResult
    public mutating func add(_ r: Member.Record, groupCA: Data) -> Bool {
        if self.groupCA == nil { self.groupCA = groupCA }
        let id = Records.id(r)
        guard self.groupCA == groupCA, !records.contains(where: { Records.id($0) == id }), records.count < Self.max,
              let body = try? JSONDecoder().decode(Records.Body.self, from: r.body),
              body.v == Records.version, body.group == GroupCertificates.tag(groupCA: groupCA),
              let anchor = Self.anchor(r, roots: knownRoots(groupCA)) else { return false }
        if body.type == "root" {
            guard (try? ParsedCertificate(der: anchor.root))?.pathLength == 1, let root = body.root,
                  (try? GroupCertificates.checkRoot(root)) != nil else { return false }
        }
        if let admin = r.chain?.first, records.lazy.filter({ $0.chain?.first == admin }).count >= Self.maxPerAdmin { return false }
        records.append(r)
        return true
    }

    /// Adds every record of rs that is valid, until nothing new is added,
    /// so that a record signed under a new root is taken together with the
    /// root record that names it, in any order; returns the new ones.
    @discardableResult
    public mutating func addAll(_ rs: [Member.Record], groupCA: Data) -> [Member.Record] {
        var fresh: [Member.Record] = [], pending = rs
        while true {
            var rest: [Member.Record] = [], rooted = false
            for r in pending {
                if add(r, groupCA: groupCA) {
                    fresh.append(r)
                    rooted = rooted || (try? JSONDecoder().decode(Records.Body.self, from: r.body))?.type == "root"
                } else if !records.contains(where: { Records.id($0) == Records.id(r) }) {
                    rest.append(r)
                }
            }
            if !rooted || rest.isEmpty { return fresh }
            pending = rest
        }
    }

    /// The roots records may be signed under: the group CA and the new root
    /// of every root record in the set.
    private func knownRoots(_ groupCA: Data) -> [Data] {
        var roots = [groupCA]
        for r in records {
            if let b = try? JSONDecoder().decode(Records.Body.self, from: r.body), b.type == "root", let root = b.root,
               !roots.contains(root) { roots.append(root) }
        }
        return roots
    }

    /// The root a record was signed under and the key hash of its signer:
    /// a root's own key without a chain, an admin CA under a root with one;
    /// nil when the signature is not valid under any of roots.
    private static func anchor(_ r: Member.Record, roots: [Data]) -> (root: Data, signer: Data)? {
        guard let sig = try? P256.Signing.ECDSASignature(derRepresentation: r.sig) else { return nil }
        func verifies(_ spki: Data) -> Bool {
            (try? P256.Signing.PublicKey(derRepresentation: spki))?.isValidSignature(sig, for: r.body) ?? false
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

        init(_ set: RecordSet) {
            guard let groupCA = set.groupCA else { return }
            let roots = set.knownRoots(groupCA)
            entries = set.records.compactMap { r in
                guard let b = try? JSONDecoder().decode(Records.Body.self, from: r.body),
                      let a = RecordSet.anchor(r, roots: roots), let anchor = try? Records.keyHash(cert: a.root) else { return nil }
                return Entry(record: r, body: b, id: Records.id(r), signer: a.signer, anchor: anchor)
            }
            evaluate(groupCA: groupCA, roots: roots)
            // From each root, the root record under it that counts and
            // whose new root has the smallest SHA-256 leads to the next.
            path = [groupCA]
            onPath = [(try? Records.keyHash(cert: groupCA)) ?? Data()]
            while let cur = path.last.flatMap({ try? Records.keyHash(cert: $0) }) {
                let next = entries.compactMap { e -> (Data, Data)? in
                    guard e.body.type == "root", e.anchor == cur, let root = e.body.root, let k = try? Records.keyHash(cert: root),
                          !onPath.contains(k), !revoked.contains(e.signer), fromRoot(e), mayHandOver(e) else { return nil }
                    return (root, k)
                }.min { Data(SHA256.hash(data: $0.0)).lexicographicallyPrecedes(Data(SHA256.hash(data: $1.0))) }
                guard let next else { break }
                path.append(next.0)
                onPath.insert(next.1)
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
            var admins: Set<Data> = [], revoked: Set<Data> = [], thawed: Set<Data> = []
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
                    if let a = b.admin, Records.role(b.role) != "phone" { admins.insert(a) }
                default: break
                }
            }
            guard computer, admins.contains(e.signer), !revoked.contains(e.signer) else { return false }
            return !entries.contains { o in
                o.body.type == "freeze" && o.anchor == root && (o.body.keys ?? []).contains(e.signer) && !thawed.contains(o.id)
                    && (o.signer == root || (admins.contains(o.signer) && !revoked.contains(o.signer)))
            }
        }

        /// The admin CA key that e, a device record of a phone signed by the
        /// own key of one of roots, names; nil for any other record.
        private static func phoneAdmin(of e: Entry, roots: Set<Data>) -> Data? {
            guard e.body.type == "device", Records.role(e.body.role) == "phone", e.signer == e.anchor, roots.contains(e.signer) else {
                return nil
            }
            return e.body.admin
        }

        private mutating func evaluate(groupCA: Data, roots: [Data]) {
            let all = Set(roots.compactMap { try? Records.keyHash(cert: $0) })
            // The known roots, until nothing is added.
            var k: Set<Data> = Set([try? Records.keyHash(cert: groupCA)].compactMap { $0 })
            while true {
                let phones = Set(entries.compactMap { Self.phoneAdmin(of: $0, roots: k) })
                var grew = false
                for e in entries where e.body.type == "root" && k.contains(e.anchor)
                    && (e.signer == e.anchor || phones.contains(e.signer) || Self.computerHandOver(e, entries)) {
                    if let root = e.body.root, let rk = try? Records.keyHash(cert: root), k.insert(rk).inserted { grew = true }
                }
                if !grew { break }
            }
            known = k
            var byRoot: [Data: [Entry]] = [:]
            var privileged = all
            for e in entries {
                if e.body.type == "revoke" && rootSigned(e) {
                    for key in e.body.keys ?? [] { byRoot[key, default: []].append(e) }
                } else if e.body.type == "device", let a = e.body.admin {
                    privileged.insert(a)
                }
                if e.signer != e.anchor { privileged.insert(e.signer) }
            }
            func standsForRoots(_ issuer: Data, _ key: Data) -> Bool {
                (byRoot[issuer] ?? []).allSatisfy { ($0.body.keep ?? []).contains(key) }
            }
            for e in entries {
                if let a = Self.phoneAdmin(of: e, roots: known), standsForRoots(e.signer, a) { phoneAdmin.insert(a) }
            }
            var disabled: Set<Data> = []
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

        /// Whether a device record counts.
        func counts(_ e: Entry) -> Bool {
            onPath.contains(e.anchor) && fromRoot(e) && issued(e.signer, e.body.key ?? Data()) && kept(e)
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
            if !ev.issued(admin, leaf) { return "the admin that admitted the device was removed" }
            // A frozen admin's certificates hold only for devices the records
            // already list.
            if ev.frozen(admin) && !ev.entries.contains(where: { $0.body.type == "device" && $0.body.key == leaf && ev.counts($0) }) {
                return "the admin that certified the device is frozen"
            }
            (top, leaf) = (issuer, admin)
        }
        if let root = ev.path.first(where: { GroupCertificates.signed(top, by: $0) }), let rk = try? Records.keyHash(cert: root),
           !ev.issued(rk, leaf) {
            return "the certificate is from a root that handed the group over"
        }
        return nil
    }

    /// The devices list: the latest device record that counts for each
    /// device (by time, then record ID), less the revoked keys, sorted by
    /// name. A device record counts when it was signed under a root on the
    /// path, by an admin CA that still stands under it, and its signer is
    /// not revoked, or every revocation of the signer keeps the device's
    /// key.
    public var devices: [Device] {
        let ev = Eval(self)
        var latest: [String: (Member.Record, Records.Body)] = [:]
        for e in ev.entries where e.body.type == "device" {
            let (r, b) = (e.record, e.body)
            guard ev.counts(e), let d = b.device else { continue }
            if let cur = latest[d] {
                let newer = b.time_ms != cur.1.time_ms ? b.time_ms > cur.1.time_ms
                    : Records.id(r).lexicographicallyPrecedes(Records.id(cur.0)) == false
                if !newer { continue }
            }
            latest[d] = (r, b)
        }
        return latest.compactMap { d, rb -> Device? in
            guard let key = rb.1.key, !ev.revoked.contains(key) else { return nil }
            return Device(id: d, name: rb.1.name ?? d, role: Records.role(rb.1.role), os: Records.os(rb.1), key: key,
                          admin: rb.1.admin.map { !ev.revoked.contains($0) && !ev.frozen($0) } ?? false, adminKey: rb.1.admin,
                          frozen: ev.frozen(key) || rb.1.admin.map(ev.frozen) ?? false)
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
    /// phone or a computer, as Go's Records.RootDevice) or a device listed as
    /// an admin whose admin CA is not revoked (docs/protocol.md, section 11).
    public func mayHost(_ device: String) -> Bool {
        if devices.contains(where: { $0.id == device && $0.admin }) { return true }
        let ev = Eval(self)
        guard let cur = ev.path.last.flatMap({ try? Records.keyHash(cert: $0) }) else { return false }
        let own = ev.entries.filter {
            $0.signer == cur && $0.body.type == "device" && ["phone", "full"].contains(Records.role($0.body.role)) &&
                $0.body.device != nil && $0.body.device == $0.body.by
        }.max { $0.body.time_ms < $1.body.time_ms }
        guard let own, own.body.device == device, let key = own.body.key else { return false }
        return !ev.revoked.contains(key)
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
