// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// A phone group (docs/protocol.md, sections 9 and 10) as this phone holds
/// it: the group CA, the phone's own member certificate, the computers it
/// admitted and the records. The phone is the root, which made the group,
/// an admin with an admin CA under the root, or a member without either.
/// The keys stay outside: the signing key (the root key, or the admin key)
/// in the Secure Enclave, the member key in the keychain. It is saved as
/// JSON next to the app's other data.
public struct PhoneGroup: Codable, Equatable, Sendable {
    /// This phone's device ID.
    public var device: String
    /// The group root CA, DER; path length 1. The group's first root, which
    /// names it for good.
    public var groupCA: Data
    /// The roots that took the group over from groupCA, in order, DER; the
    /// last is the current root (docs/protocol.md, section 10, "Roots").
    public var roots: [Data] = []
    /// This phone's member certificate, DER, from one of the roots or from
    /// memberIssuer.
    public var memberCert: Data
    /// The admin CA that issued memberCert, which the phone sends after it
    /// in TLS handshakes; nil when the group CA did.
    public var memberIssuer: Data?
    /// Whether this phone holds the current root's key: it made the group,
    /// or took it over.
    public var isRoot = true
    /// This phone's admin CA when it is an admin but not the root.
    public var adminCA: Data?
    public var computers: [Computer]
    /// The group's signed device and revocation records; admin phones sign
    /// them, and they spread to every member.
    public var records = RecordSet()
    /// The admin CAs this phone, as the root, issued to computers, DER, by
    /// device ID: sent again to a computer that offers the same admin key
    /// (section 10, "A computer as admin").
    public var computerAdmins: [String: Data] = [:]

    enum CodingKeys: String, CodingKey {
        case device, groupCA, roots, memberCert, memberIssuer, isRoot, adminCA, computers, records, computerAdmins
    }

    init(device: String, groupCA: Data, memberCert: Data, computers: [Computer]) {
        (self.device, self.groupCA, self.memberCert, self.computers) = (device, groupCA, memberCert, computers)
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        device = try c.decode(String.self, forKey: .device)
        groupCA = try c.decode(Data.self, forKey: .groupCA)
        roots = try c.decodeIfPresent([Data].self, forKey: .roots) ?? []
        memberCert = try c.decode(Data.self, forKey: .memberCert)
        memberIssuer = try c.decodeIfPresent(Data.self, forKey: .memberIssuer)
        // Files saved before phones could join belong to a root.
        isRoot = try c.decodeIfPresent(Bool.self, forKey: .isRoot) ?? true
        adminCA = try c.decodeIfPresent(Data.self, forKey: .adminCA)
        computers = try c.decode([Computer].self, forKey: .computers)
        records = try c.decodeIfPresent(RecordSet.self, forKey: .records) ?? RecordSet()
        computerAdmins = try c.decodeIfPresent([String: Data].self, forKey: .computerAdmins) ?? [:]
        // Sets saved before root records do not name their group CA.
        if records.groupCA == nil, !records.records.isEmpty {
            var set = RecordSet()
            set.addAll(records.records, groupCA: groupCA)
            records = set
        }
    }

    /// Whether this phone may admit devices, renew certificates and remove
    /// devices: the root and the admins.
    public var isAdmin: Bool { isRoot || adminCA != nil }

    /// The certificate chain this phone presents in TLS, leaf first.
    public var memberChain: [Data] { [memberCert] + (memberIssuer.map { [$0] } ?? []) }

    /// The current root: the last of roots, or the group CA.
    public var currentRoot: Data { roots.last ?? groupCA }

    /// Every root the group had, the group CA first: member certificates
    /// and admin CAs from any of them verify.
    public var trusted: [Data] { [groupCA] + roots }

    /// The CA whose key signs for this phone: the current root, or its
    /// admin CA.
    var signingCA: Data { adminCA ?? currentRoot }

    /// A computer this phone admitted.
    public struct Computer: Codable, Equatable, Sendable, Identifiable {
        public var device: String
        public var name: String
        /// "linux", "windows" or "macos", as its pairing Info says.
        public var os: String
        public var cert: Data
        public var admitted: Date
        /// Its addresses on the home network from the QR code, the one that
        /// answered first: dialed when mDNS does not find it, as in another
        /// subnet (docs/protocol.md, section 9). nil in files saved before.
        public var addrs: [String]?
        public var id: String { device }
    }

    /// The home network addresses of the computers this phone admitted, by
    /// device ID, best first.
    public var addresses: [String: [String]] {
        var out: [String: [String]] = [:]
        for c in computers { if let a = c.addrs?.filter(JoinCode.isHome), !a.isEmpty { out[c.device] = a } }
        return out
    }

    /// The group tag the computers publish.
    public var tag: String { GroupCertificates.tag(groupCA: groupCA) }

    /// Creates a group: a root CA for caSigner's key, a member certificate
    /// for this phone's member key (a SubjectPublicKeyInfo), and the phone's
    /// own device record under name.
    public static func create(caSigner: CertificateSigner, memberKey: Data, name: String = "iPhone", now: Date) throws -> PhoneGroup {
        let ca = try GroupCertificates.groupCA(signer: caSigner, now: now, pathLength: 1)
        let device = SyncEngine.newID()
        let cert = try GroupCertificates.member(device: device, publicKey: memberKey, ca: ca, caSigner: caSigner, now: now)
        var g = PhoneGroup(device: device, groupCA: ca, memberCert: cert, computers: [])
        _ = try g.record(device: device, name: Self.validName(name), role: "phone", os: "ios", key: Records.keyHash(spki: memberKey),
                         store: Records.hardware, caSigner: caSigner, now: now)
        return g
    }

    /// A name that the records accept: 1 to 64 bytes without control
    /// characters, or "iPhone".
    public static func validName(_ s: String) -> String {
        var out = ""
        for ch in s where !ch.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) {
            if (out + String(ch)).utf8.count > 64 { break }
            out.append(ch)
        }
        return out.isEmpty ? "iPhone" : out
    }

    /// The group a phone joins, from the welcome the admitting phone sent
    /// and PairingJoiner checked: a member of it, and an admin when the
    /// welcome carries its admin CA. The records arrive from the computers.
    public static func joined(_ j: PairingJoiner.Joined) -> PhoneGroup {
        var g = PhoneGroup(device: j.device, groupCA: j.welcome.groupCA, memberCert: j.welcome.cert, computers: [])
        (g.memberIssuer, g.isRoot, g.adminCA) = (j.welcome.issuer, false, j.welcome.adminCA)
        // The records that lead to the roots stay with the group, so the
        // roots are those its records name.
        g.records.addAll(j.welcome.records ?? [], groupCA: j.welcome.groupCA)
        g.roots = g.records.roots
        return g
    }

    /// fileKey: the computer keeps its keys in a file, which a thief with
    /// it can copy and then act as an admin; the user allows it after a
    /// warning (docs/protocol.md, section 17).
    public enum Failure: Error, Equatable {
        case cannotRemoveItself, unknownDevice, notAdmin, cannotRemoveRoot, notRoot, notAComputer, frozen, notFrozen, invalidName, fileKey
    }

    /// Adds records from other members, then follows the roots they lead
    /// to when they differ from this phone's; returns the new records.
    @discardableResult
    public mutating func add(_ rs: [Member.Record]) -> [Member.Record] {
        let fresh = records.addAll(rs, groupCA: groupCA)
        adoptRoots()
        return fresh
    }

    /// Takes the roots of the records when they differ from roots,
    /// compared by content, so a root the records do not name never stays
    /// trusted; an empty set says nothing yet.
    mutating func adoptRoots() {
        let path = records.roots
        if !records.records.isEmpty, path != roots { roots = path }
    }

    /// Signs and adds a device record.
    mutating func record(device: String, name: String, role: String, os: String? = nil, key: Data, admin: Data? = nil,
                         store: String? = nil, kind: String? = nil, proof: String? = nil, caSigner: CertificateSigner,
                         now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        let r = try Records.device(device, name: name, role: role, os: os, key: key, admin: admin, store: store, kind: kind, proof: proof,
                                   group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA)
        records.add(r, groupCA: groupCA)
        return r
    }

    /// Hands the group to this admin phone when the root phone lost is gone
    /// (section 10, "Handing the group over"): a new root for rootSigner's
    /// key, a root record signed with this phone's admin CA (adminSigner),
    /// then, as the new root, a revocation of the old root's key and the
    /// lost phone that keeps everything else the old root certified, and
    /// this phone's own record under the new root. It returns the records
    /// to send; this phone is the root afterwards.
    public mutating func takeOver(from lost: String, adminSigner: CertificateSigner, rootSigner: CertificateSigner,
                                  now: Date) throws -> [Member.Record] {
        guard let myCA = adminCA, !isRoot else { throw Failure.notAdmin }
        guard lost == records.rootDevice, lost != device else { throw Failure.notRoot }
        let list = devices
        guard let d = list.first(where: { $0.id == lost }), let me = list.first(where: { $0.id == device }) else {
            throw Failure.unknownDevice
        }
        let oldRoot = try Records.keyHash(cert: currentRoot)
        let newRoot = try GroupCertificates.groupCA(signer: rootSigner, now: now, pathLength: 1)
        var keep = records.admitted(by: oldRoot)
        for other in list where other.id != lost {
            if let k = other.adminKey, !keep.contains(k) { keep.append(k) }
        }
        keep.removeAll { d.keys.contains($0) || $0 == d.adminKey }
        var out = [try Records.root(newRoot, group: tag, by: device, now: now, signer: adminSigner, adminCA: myCA)]
        records.add(out[0], groupCA: groupCA)
        out.append(try Records.revoke([oldRoot] + d.keys + (d.adminKey.map { [$0] } ?? []), keep: keep, group: tag, by: device, now: now,
                                      signer: rootSigner))
        out.append(try Records.device(device, name: me.name, role: "phone", os: me.os ?? "ios", key: me.key, admin: me.adminKey, group: tag, by: device,
                                      now: now, signer: rootSigner))
        for r in out.dropFirst() { records.add(r, groupCA: groupCA) }
        adoptRoots()
        guard currentRoot == newRoot else { throw Failure.notRoot }
        (isRoot, adminCA) = (true, nil)
        return out
    }

    /// Renews this phone's own member certificate when it is due; reports
    /// whether it did, after which the TLS identity must be made again. An
    /// admin issues it from its own admin CA, a phone without one cannot.
    public mutating func renewOwnCertificate(caSigner: CertificateSigner, now: Date) throws -> Bool {
        guard isAdmin, GroupCertificates.isDue(memberCert, groupCA: signingCA, now: now),
              (try? GroupCertificates.verifyMember(chain: memberChain, roots: trusted, now: now)) == device else { return false }
        memberCert = try GroupCertificates.member(device: device, publicKey: CertificateInfo(der: memberCert).publicKey, ca: signingCA,
                                                  caSigner: caSigner, now: now)
        memberIssuer = adminCA
        return true
    }

    /// A renewed certificate for a peer's chain (leaf first) when it is due
    /// and this phone is an admin: the root issues it from its root, an
    /// admin from its admin CA, which the cert message carries, whoever
    /// issued the old one (as a removed admin did).
    public func renewal(chain: [Data], caSigner: CertificateSigner, now: Date) -> MemberNode.Renewal? {
        guard isAdmin, let cert = try? GroupCertificates.renewal(chain: chain, roots: trusted, caSigner: caSigner, adminCA: adminCA, now: now)
        else { return nil }
        return MemberNode.Renewal(cert: cert, issuer: adminCA)
    }

    /// The devices of the group, from the records.
    public var devices: [RecordSet.Device] { records.devices }

    /// A command that sets the sync mode of the member device to (section
    /// 15), signed with this phone's root or admin key; only an admin phone
    /// signs one.
    public func modeCommand(to device: String, mode: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        return try Commands.mode(to: device, mode: mode, group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA)
    }

    /// A hub command that makes the admin computer to the group's hub in
    /// place of this phone (section 11, "Moving the hub"), signed with this
    /// phone's root or admin key, with the hub's clients and its forwarder.
    public func hubCommand(to device: String, forwarder: (endpoint: String, pin: String)?, clients: [PhoneHub.Client],
                           caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin, records.mayHost(device) else { throw Failure.notAdmin }
        return try Commands.hub(to: device, forwarder: forwarder, clients: clients.filter { $0.device != device }, group: tag, by: self.device,
                                now: now, signer: caSigner, adminCA: adminCA)
    }

    /// Removes a device from the group: signs a revocation of its key,
    /// which every member then refuses, and returns the record to send. For
    /// an admin phone it revokes its admin key too and keeps the devices
    /// that phone admitted, so they stay in the group (section 10). The
    /// root phone is removed with takeOver instead.
    public mutating func revoke(device: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        guard device != self.device else { throw Failure.cannotRemoveItself }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        guard device != records.rootDevice else { throw Failure.cannotRemoveRoot }
        // Every key the device had in the group goes, so none of them stays
        // a member nobody sees.
        var keys = d.keys, keep: [Data]?
        if let admin = d.adminKey {
            keys.append(admin)
            // Its own removals stop counting with it, so this record names them again.
            for k in records.revokedBy(admin) where !keys.contains(k) { keys.append(k) }
            keep = records.admitted(by: admin).filter { !keys.contains($0) }
        }
        let r = try Records.revoke(keys, keep: keep, group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA)
        records.add(r, groupCA: groupCA)
        computers.removeAll { $0.device == device }
        computerAdmins[device] = nil
        return r
    }

    /// Gives a device another name: a device record like its newest one with
    /// that name, which names it everywhere, since the newest record of a
    /// device counts (section 10). An admin renames any device, itself and
    /// the root included. name is trimmed; it must have 1 to 64 bytes and
    /// no control characters.
    public mutating func rename(device: String, to name: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, Self.validName(name) == name else { throw Failure.invalidName }
        return try record(device: device, name: name, role: d.role, os: d.os, key: d.key, admin: d.adminKey,
                          store: d.store, kind: d.kind, proof: d.proof, caSigner: caSigner, now: now)
    }

    /// Unfreezes an admin computer that another admin froze (section 10,
    /// rule 4): a thaw record that ends every freeze of it. The root and the
    /// admin phones do it; Remove takes the computer out for good instead.
    public mutating func thaw(device: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        guard d.frozen, let admin = d.adminKey else { throw Failure.notFrozen }
        let r = try Records.thaw(records.freezes(of: admin), group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA)
        records.add(r, groupCA: groupCA)
        return r
    }

    /// Makes a computer an admin (section 10, "A computer as admin"): the
    /// root issues an admin CA for the admin key the computer's hello
    /// offered (a SubjectPublicKeyInfo) and signs its device record again,
    /// naming that CA. It returns the admin CA, for the admin message, and
    /// the record to send. Only the root makes admins. keyStore is where
    /// the computer's hello says its keys live; one that keeps them in a
    /// file becomes an admin only with allowFileKey, else Failure.fileKey.
    public mutating func makeAdmin(device: String, adminKey: Data, rootSigner: CertificateSigner, now: Date,
                                   keyStore: String? = nil, allowFileKey: Bool = false) throws -> (adminCA: Data, record: Member.Record) {
        guard isRoot else { throw Failure.notRoot }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        guard d.role == "full" else { throw Failure.notAComputer }
        guard !d.frozen else { throw Failure.frozen }
        let proven = d.store == Records.proven
        let store = proven ? d.store : Records.store(keyStore, role: d.role)
        guard store != Records.file || allowFileKey else { throw Failure.fileKey }
        let ca = try GroupCertificates.adminCA(device: device, publicKey: adminKey, root: currentRoot, rootSigner: rootSigner)
        let r = try record(device: device, name: d.name, role: d.role, os: d.os, key: d.key, admin: Records.keyHash(cert: ca),
                           store: store, kind: proven ? d.kind : nil, proof: proven ? d.proof : nil, caSigner: rootSigner, now: now)
        computerAdmins[device] = ca
        return (ca, r)
    }

    /// Checks the attestation a device sent of its member key (section 17,
    /// "Evidence") and, on the root, returns a new device record with what
    /// it shows when that differs from the device's record; nil when there
    /// is nothing to record. chain is the certificate chain the device
    /// presented, leaf first. Throws AndroidAttestation.Invalid for a proof
    /// of nothing.
    public mutating func evidence(device: String, chain: [Data], _ e: Member.Evidence, rootSigner: CertificateSigner, now: Date,
                                  roots: [Data]? = nil) throws -> Member.Record? {
        guard isRoot, let leaf = chain.first, e.format == Member.Evidence.android, e.key == Member.Evidence.member else { return nil }
        let key = try Records.keyHash(cert: leaf)
        guard let d = devices.first(where: { $0.id == device && $0.key == key }) else { return nil }
        if let t = e.groupTag, t != tag { throw AndroidAttestation.Invalid(reason: "an attestation made for another group") }
        let challenge: Data
        do {
            challenge = try Attestation.challenge(groupTag: e.groupTag ?? "", memberKey: Data(), salt: e.salt)
        } catch {
            throw AndroidAttestation.Invalid(reason: "\(error)")
        }
        let r = try AndroidAttestation.check(chain: e.chain, spki: try CertificateInfo(der: leaf).publicKey, challenge: challenge,
                                             policy: AndroidAttestation.Policy(roots: roots))
        if d.store == r.store, (d.kind ?? "") == r.kind { return nil }
        guard let first = e.chain.first else { return nil }
        let proof = SHA256.hash(data: first).map { String(format: "%02x", $0) }.joined()
        return try record(device: device, name: d.name, role: d.role, os: d.os, key: d.key, admin: d.adminKey, store: r.store,
                          kind: r.kind.isEmpty ? nil : r.kind, proof: proof, caSigner: rootSigner, now: now)
    }

    /// The admin CA this phone issued for an admin key a computer offers,
    /// while that computer is still listed as an admin.
    public func computerAdminCA(for adminKey: Data) -> Data? {
        let listed = Set(devices.filter(\.admin).map(\.id))
        return computerAdmins.first { listed.contains($0.key) && (try? CertificateInfo(der: $0.value).publicKey) == adminKey }?.value
    }

    /// Admits a listening device over a pairing connection whose TLS
    /// handshake is done (section 6, "The joiner listens"): joinerCert is
    /// the device's certificate, already checked against the QR code's
    /// fingerprint, and sessionID the TLS exporter's output. The device
    /// gets a member certificate from this phone's CA and the group CA,
    /// never a key. A phone that sent an admin key becomes an admin when
    /// this phone is the root and makeAdmin is set: it gets an admin CA for
    /// that key. On success a computer is in computers, where one admitted
    /// again replaces its entry, and every device has its record. A
    /// computer keeps those of addrs that are on a home network, where the
    /// phone dialed it. With invitation, the device dialed this phone, the
    /// hub, with a remote invitation (section 12): code is unused and the
    /// device never becomes an admin.
    public mutating func admit(over t: FrameTransport, code: String, joinerCert: Data, sessionID: [UInt8],
                               caSigner: CertificateSigner, makeAdmin: Bool = true, addrs: [String] = [],
                               invitation: PairingMember.Invitation? = nil, now: Date) async throws -> PairingMember.Admitted {
        guard isAdmin else { throw Failure.notAdmin }
        let (first, later, root, ca, issuer) = (groupCA, roots, currentRoot, signingCA, adminCA)
        let canMakeAdmins = isRoot && invitation == nil
        let pathRecords = later.isEmpty ? nil : records.pathRecords
        var adminKey: Data?
        let admitted = try await PairingMember.admit(
            over: t, code: code, memberCert: memberCert, joinerCert: joinerCert, sessionID: sessionID,
            memberAD: Pairing.MemberAD(device: device, group: tag), taken: { [device, records] in $0 == device || records.knows($0) },
            invitation: invitation
        ) { dev, publicKey, info in
            var w = Pairing.Welcome(cert: try GroupCertificates.member(device: dev, publicKey: publicKey, ca: ca, caSigner: caSigner, now: now),
                                    groupCA: first, issuer: issuer)
            (w.roots, w.records) = (later.isEmpty ? nil : later, pathRecords)
            if info.isPhone, let key = info.adminKey, makeAdmin, canMakeAdmins {
                w.adminCA = try GroupCertificates.adminCA(device: dev, publicKey: key, root: root, rootSigner: caSigner)
                adminKey = key
            }
            return w
        }
        let name = Self.validName(admitted.info.name), key = try Records.keyHash(cert: admitted.cert)
        if admitted.info.isPhone {
            _ = try record(device: admitted.device, name: name, role: "phone", os: admitted.info.os, key: key,
                           admin: adminKey.map(Records.keyHash(spki:)), store: Records.hardware,
                           caSigner: caSigner, now: now)
            return admitted
        }
        computers.removeAll { $0.device == admitted.device }
        computers.append(Computer(device: admitted.device, name: admitted.info.name, os: admitted.info.os, cert: admitted.cert, admitted: now,
                                  addrs: addrs.filter(JoinCode.isHome)))
        _ = try record(device: admitted.device, name: name, role: admitted.info.role == Pairing.Info.lite ? "lite" : "full",
                       os: admitted.info.os, key: key, caSigner: caSigner, now: now)
        return admitted
    }

    /// Reads a saved group; nil when there is none.
    public static func load(from url: URL) throws -> PhoneGroup? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try JSONDecoder().decode(PhoneGroup.self, from: Data(contentsOf: url))
    }

    /// Saves the group in one step, so a crash leaves the old file or the new one.
    public func save(to url: URL) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try enc.encode(self).write(to: url, options: [.atomic])
    }
}
