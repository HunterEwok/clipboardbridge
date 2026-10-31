// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// Root records (docs/protocol.md, section 10, "Roots" and "Handing the
/// group over"): the root phone is lost, and admin phone B takes the group
/// over with a new root.
final class RootTests: XCTestCase {
    let t0 = Date()

    /// A computer: its device ID, key and member certificate.
    struct Computer {
        let device = SyncEngine.newID()
        let key = SoftwareSigner()
        var cert = Data()
        var keyHash: Data { (try? Records.keyHash(cert: cert)) ?? Data() }
    }

    /// The group before the loss: the root phone, which admitted computer
    /// one itself, and admin phone B, which admitted computer two.
    struct Group {
        var root: PhoneGroup, b: PhoneGroup
        let rootKey: SoftwareSigner, adminKey: SoftwareSigner, newRootKey = SoftwareSigner()
        /// B's admin CA, under the old root.
        let adminCA: Data
        let one: Computer, two: Computer

        init(now: Date) throws {
            let rootKey = SoftwareSigner(), adminKey = SoftwareSigner()
            var root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, name: "Lost", now: now)
            let bDevice = SyncEngine.newID(), bKey = SoftwareSigner()
            let adminCA = try GroupCertificates.adminCA(device: bDevice, publicKey: adminKey.publicKeyDER, root: root.groupCA,
                                                        rootSigner: rootKey)
            let bCert = try GroupCertificates.member(device: bDevice, publicKey: bKey.publicKeyDER, ca: root.groupCA, caSigner: rootKey, now: now)
            _ = try root.record(device: bDevice, name: "B", role: "phone", key: Records.keyHash(cert: bCert),
                                admin: Records.keyHash(cert: adminCA), caSigner: rootKey, now: now)
            var one = Computer(), two = Computer()
            one.cert = try GroupCertificates.member(device: one.device, publicKey: one.key.publicKeyDER, ca: root.groupCA,
                                                    caSigner: rootKey, now: now)
            _ = try root.record(device: one.device, name: "one", role: "linux", key: one.keyHash, caSigner: rootKey, now: now)
            var b = PhoneGroup(device: bDevice, groupCA: root.groupCA, memberCert: bCert, computers: [])
            (b.isRoot, b.adminCA) = (false, adminCA)
            b.add(root.records.records)
            two.cert = try GroupCertificates.member(device: two.device, publicKey: two.key.publicKeyDER, ca: adminCA, caSigner: adminKey, now: now)
            _ = try b.record(device: two.device, name: "two", role: "linux", key: two.keyHash, caSigner: adminKey, now: now)
            root.add(b.records.records)
            (self.root, self.b, self.rootKey, self.adminKey, self.adminCA, self.one, self.two) = (root, b, rootKey, adminKey, adminCA, one, two)
        }
    }

    /// What a phone hub shows its forwarder: the records of the root's own
    /// device and of the admins, and every record that is no device record,
    /// never the records that name the computers.
    func testAuthorityRecords() throws {
        var g = try Group(now: t0)
        func names(_ rs: [Member.Record]) -> Set<String> {
            Set(rs.compactMap { try? JSONDecoder().decode(Records.Body.self, from: $0.body) }.filter { $0.type == "device" }.compactMap(\.name))
        }
        XCTAssertEqual(names(g.root.records.authorityRecords), ["Lost", "B"])
        let rs = try g.b.takeOver(from: g.root.device, adminSigner: g.adminKey, rootSigner: g.newRootKey, now: t0)
        let after = g.b.records.authorityRecords
        XCTAssertEqual(names(after), ["Lost", "B"])
        let ids = Set(after.map(Records.id))
        XCTAssertTrue(rs.allSatisfy { ids.contains(Records.id($0)) }, "the takeover's records")
        XCTAssertTrue(g.b.records.pathRecords.allSatisfy { ids.contains(Records.id($0)) }, "the path")
        XCTAssertEqual(ids.count, after.count)
        // A forwarder that knows only these sees the same roots and the lost phone removed.
        var forwarder = RecordSet()
        forwarder.addAll(after.shuffled(), groupCA: g.root.groupCA)
        XCTAssertEqual(forwarder.roots, g.b.roots)
        XCTAssertNotNil(forwarder.refused(chain: [g.root.memberCert]))
    }

    func testTakeOver() throws {
        var g = try Group(now: t0)
        let lost = g.root.device
        XCTAssertEqual(g.b.records.rootDevice, lost)
        let rs = try g.b.takeOver(from: lost, adminSigner: g.adminKey, rootSigner: g.newRootKey, now: t0)
        XCTAssertEqual(rs.count, 3)
        XCTAssertTrue(g.b.isRoot)
        XCTAssertNil(g.b.adminCA)
        XCTAssertEqual(g.b.roots.count, 1)
        XCTAssertEqual(g.b.records.roots, g.b.roots)
        XCTAssertEqual(g.b.tag, g.root.tag, "the group keeps its tag")
        XCTAssertEqual(g.b.records.rootDevice, g.b.device)
        XCTAssertEqual(g.b.devices.map(\.name), ["B", "one", "two"])
        XCTAssertEqual(g.b.devices.first { $0.name == "B" }?.admin, true)
        let set = g.b.records
        XCTAssertNotNil(set.refused(chain: [g.root.memberCert]), "the lost phone")
        XCTAssertNil(set.refused(chain: [g.one.cert]), "the computer the old root admitted")
        XCTAssertNil(set.refused(chain: [g.two.cert, g.adminCA]), "the computer B admitted")
        XCTAssertNil(set.refused(chain: g.b.memberChain), "B itself")

        // A computer that gets the records in any order sees the same.
        var shuffled = g.b.records.records.shuffled()
        shuffled.append(contentsOf: rs.shuffled())
        var computer = RecordSet()
        computer.addAll(shuffled, groupCA: g.root.groupCA)
        XCTAssertEqual(computer.digest, g.b.records.digest)
        XCTAssertEqual(computer.roots, g.b.roots)
        XCTAssertEqual(computer.devices.map(\.name), ["B", "one", "two"])

        // The new root admits and renews.
        var three = Computer()
        three.cert = try GroupCertificates.member(device: three.device, publicKey: three.key.publicKeyDER, ca: g.b.currentRoot,
                                                  caSigner: g.newRootKey, now: t0)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: [three.cert], roots: g.b.trusted, now: t0), three.device)
        XCTAssertNil(set.refused(chain: [three.cert]))
        let later = t0.addingTimeInterval(500 * 24 * 3600)
        let renewed = try XCTUnwrap(g.b.renewal(chain: [g.one.cert], caSigner: g.newRootKey, now: later)).cert
        XCTAssertEqual(try GroupCertificates.verifyMember(renewed, groupCA: g.b.currentRoot, now: later), g.one.device)
    }

    func testOldRootKeyAfterTakeOver() throws {
        var g = try Group(now: t0)
        _ = try g.b.takeOver(from: g.root.device, adminSigner: g.adminKey, rootSigner: g.newRootKey, now: t0)
        var set = g.b.records
        // Whoever has the lost phone's root key signs a computer, an admin
        // CA, a device record and a root record: none counts.
        var stolen = Computer()
        stolen.cert = try GroupCertificates.member(device: stolen.device, publicKey: stolen.key.publicKeyDER, ca: g.root.groupCA,
                                                   caSigner: g.rootKey, now: t0)
        let thiefKey = SoftwareSigner()
        let thiefCA = try GroupCertificates.adminCA(device: SyncEngine.newID(), publicKey: thiefKey.publicKeyDER, root: g.root.groupCA,
                                                    rootSigner: g.rootKey)
        let viaThief = try GroupCertificates.member(device: SyncEngine.newID(), publicKey: SoftwareSigner().publicKeyDER, ca: thiefCA,
                                                    caSigner: thiefKey, now: t0)
        XCTAssertNotNil(set.refused(chain: [stolen.cert]))
        XCTAssertNotNil(set.refused(chain: [viaThief, thiefCA]))
        let otherRoot = try GroupCertificates.groupCA(signer: SoftwareSigner(), now: t0, pathLength: 1)
        let thirdRoot = try GroupCertificates.groupCA(signer: SoftwareSigner(), now: t0, pathLength: 1)
        for r in [
            try Records.device(stolen.device, name: "stolen", role: "linux", key: stolen.keyHash, group: g.b.tag, by: g.root.device,
                               now: t0, signer: g.rootKey),
            try Records.root(otherRoot, group: g.b.tag, by: g.root.device, now: t0, signer: g.rootKey),
            try Records.root(thirdRoot, group: g.b.tag, by: g.root.device, now: t0, signer: thiefKey, adminCA: thiefCA),
        ] { XCTAssertTrue(set.add(r, groupCA: g.root.groupCA)) }
        XCTAssertEqual(set.devices.map(\.name), ["B", "one", "two"])
        XCTAssertEqual(set.roots, g.b.roots)
    }

    func testTakeOverRefused() throws {
        var g = try Group(now: t0)
        XCTAssertThrowsError(try g.b.takeOver(from: g.one.device, adminSigner: g.adminKey, rootSigner: g.newRootKey, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notRoot)
        }
        XCTAssertThrowsError(try g.root.takeOver(from: g.root.device, adminSigner: g.rootKey, rootSigner: g.newRootKey, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notAdmin)
        }
        // A root record in a computer's group, or naming no phone root, is
        // not taken.
        let pcCA = try GroupCertificates.groupCA(signer: g.rootKey, now: t0)
        var set = RecordSet()
        XCTAssertFalse(set.add(try Records.root(pcCA, group: g.root.tag, by: g.root.device, now: t0, signer: g.rootKey), groupCA: g.root.groupCA))
        XCTAssertFalse(set.add(try Records.root(try XCTUnwrap(g.b.adminCA), group: g.root.tag, by: g.root.device, now: t0, signer: g.rootKey),
                               groupCA: g.root.groupCA))
    }

    /// A welcome after the takeover names the new root, and a phone that
    /// joins checks it.
    func testWelcomeAfterTakeOver() throws {
        var g = try Group(now: t0)
        _ = try g.b.takeOver(from: g.root.device, adminSigner: g.adminKey, rootSigner: g.newRootKey, now: t0)
        let joiner = SyncEngine.newID(), key = SoftwareSigner()
        let selfSigned = try GroupCertificates.selfSigned(device: joiner, signer: key)
        var w = Pairing.Welcome(cert: try GroupCertificates.member(device: joiner, publicKey: key.publicKeyDER, ca: g.b.currentRoot,
                                                                   caSigner: g.newRootKey, now: t0), groupCA: g.b.groupCA)
        (w.roots, w.records) = (g.b.roots, g.b.records.pathRecords)
        XCTAssertLessThan(g.b.records.pathRecords.count, g.b.records.records.count, "the welcome carries more than the path needs")
        let j = PairingJoiner.Joined(device: joiner, welcome: w, member: .init(device: g.b.device, group: g.b.tag))
        let info = Pairing.Info(name: "C", os: "ios")
        XCTAssertNoThrow(try PairingJoiner.check(j, info: info, memberCert: g.b.memberCert, joinerCert: selfSigned, now: t0))
        var bad = j
        bad.welcome.roots = nil
        XCTAssertThrowsError(try PairingJoiner.check(bad, info: info, memberCert: g.b.memberCert, joinerCert: selfSigned, now: t0))
        // A root that no record leads to, as one an admin made up and named
        // in the Welcome, is refused.
        var made = j
        made.welcome.records = nil
        XCTAssertThrowsError(try PairingJoiner.check(made, info: info, memberCert: g.b.memberCert, joinerCert: selfSigned, now: t0))
        XCTAssertEqual(PhoneGroup.joined(j).roots, g.b.roots)
    }

    /// Reads testdata/interop/go-root.json, a handover that Go's
    /// TestGoRootVectors wrote, and expects what Go makes of it.
    func testGoHandover() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            struct Device: Decodable { var id: String, name: String, admin: Bool }
            struct Chain: Decodable { var name: String, chain: [Data], refused: Bool }
            var group_ca: Data
            var records: [Member.Record]
            var roots: [Data]
            var devices: [Device]
            var chains: [Chain]
            var digest: String
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-root.json")))
        var set = RecordSet()
        XCTAssertEqual(set.addAll(v.records, groupCA: v.group_ca).count, v.records.count)
        XCTAssertEqual(set.digest, v.digest)
        XCTAssertEqual(set.roots, v.roots)
        XCTAssertEqual(set.devices.map(\.id), v.devices.map(\.id))
        XCTAssertEqual(set.devices.map(\.name), v.devices.map(\.name))
        XCTAssertEqual(set.devices.map(\.admin), v.devices.map(\.admin))
        for c in v.chains { XCTAssertEqual(set.refused(chain: c.chain) != nil, c.refused, c.name) }
    }

    /// Reads testdata/interop/go-hubs.json, from Go's TestGoHubVectors: the
    /// order of the group's hubs.
    func testGoHubOrder() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            var group_ca: Data
            var records: [Member.Record]
            var hub_order: [String]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-hubs.json")))
        var set = RecordSet()
        XCTAssertEqual(set.addAll(v.records, groupCA: v.group_ca).count, v.records.count)
        XCTAssertEqual(set.hubOrder, v.hub_order)
    }

    /// Reads testdata/interop/go-admins.json, from Go's TestGoAdminVectors:
    /// a computer's admin CA removes a device but neither the admin phone
    /// nor the root, nor hands the group over, and nothing it signs after
    /// the admin phone removed it counts.
    func testGoAdminPowers() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            struct Device: Decodable { var id: String, name: String, admin: Bool }
            struct Key: Decodable { var name: String, key: Data, revoked: Bool }
            struct Chain: Decodable { var name: String, chain: [Data], refused: Bool }
            var group_ca: Data
            var records: [Member.Record]
            var devices: [Device]
            var keys: [Key]
            var chains: [Chain]
            var digest: String
            var dropped: Int?
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-admins.json")))
        var set = RecordSet()
        // The record signed under the root the computer admin named is
        // dropped: that root is never known.
        XCTAssertEqual(v.dropped, 1)
        XCTAssertEqual(set.addAll(v.records.reversed(), groupCA: v.group_ca).count, v.records.count - (v.dropped ?? 0))
        XCTAssertEqual(set.digest, v.digest)
        XCTAssertTrue(set.roots.isEmpty, "a computer admin handed the group over")
        XCTAssertEqual(set.devices.map(\.name), v.devices.map(\.name))
        XCTAssertEqual(set.devices.map(\.admin), v.devices.map(\.admin))
        for k in v.keys { XCTAssertEqual(set.revoked.contains(k.key), k.revoked, k.name) }
        for c in v.chains { XCTAssertEqual(set.refused(chain: c.chain) != nil, c.refused, c.name) }
    }

    /// Reads testdata/interop/go-envelopes.json, from Go's
    /// TestEnvelopeVectors: one body signed by two signers is two records,
    /// and the set says the same whichever came first; the root's removal of
    /// an admin phone counts though a computer admin's copy came first.
    func testGoEnvelopes() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            struct Key: Decodable { var name: String, key: Data, revoked: Bool }
            var group_ca: Data
            var records: [Member.Record]
            var keys: [Key]
            var digest: String
            var count: Int
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-envelopes.json")))
        for (name, recs) in [("as written", v.records), ("reversed", v.records.reversed()), ("the computer admin's copy only", Array(v.records.prefix(3)))] {
            var set = RecordSet()
            for r in recs { XCTAssertTrue(set.add(r, groupCA: v.group_ca), name) }
            for r in recs { XCTAssertFalse(set.add(r, groupCA: v.group_ca), "\(name): a record held already was new again") }
            let full = recs.count == v.records.count
            for k in v.keys { XCTAssertEqual(set.revoked.contains(k.key), k.revoked && full, "\(name): \(k.name)") }
            if full {
                XCTAssertEqual(set.records.count, v.count, name)
                XCTAssertEqual(set.digest, v.digest, name)
            }
        }
    }

    /// Reads testdata/interop/go-removed-admin.json, from Go's
    /// TestRemovedAdminVectors: an admin phone that the root removed signs a
    /// root record afterwards, for a root of its own that revokes the
    /// group's root and admins; that root is not known, so none of it
    /// counts, in any order.
    func testGoRemovedAdmin() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            struct Key: Decodable { var name: String, key: Data, revoked: Bool }
            var group_ca: Data
            var records: [Member.Record]
            var keys: [Key]
            var roots: Int
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-removed-admin.json")))
        for (name, recs) in [("as written", v.records), ("reversed", v.records.reversed())] {
            var set = RecordSet()
            for r in recs { _ = set.add(r, groupCA: v.group_ca) }
            XCTAssertEqual(set.roots.count, v.roots, name)
            for k in v.keys { XCTAssertEqual(set.revoked.contains(k.key), k.revoked, "\(name): \(k.name)") }
        }
    }

    /// Reads testdata/interop/go-authority.json, from Go's
    /// TestGoAuthorityVectors: a device is an admin, with the role and store
    /// of that record, only by a record a root's own key signed, and a
    /// removed admin's records no longer decide a device's entry.
    func testGoAuthority() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            struct Device: Decodable { var id: String, name: String, admin: Bool, admin_key: Data?, role: String, store: String }
            var group_ca: Data
            var records: [Member.Record]
            var devices: [Device]
            var other: Data
            var other_revoked: Bool
            var later: [Member.Record]
            var devices_later: [Device]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-authority.json")))
        var set = RecordSet()
        func check(_ want: [V.Device]) {
            let got = set.devices
            XCTAssertEqual(got.map(\.id), want.map(\.id))
            for (g, w) in zip(got, want) {
                XCTAssertEqual(g.name, w.name)
                XCTAssertEqual(g.admin, w.admin, g.name)
                XCTAssertEqual(g.adminKey, w.admin_key, g.name)
                XCTAssertEqual(g.role, w.role, g.name)
                XCTAssertEqual(g.store, w.store, g.name)
            }
        }
        XCTAssertEqual(set.addAll(v.records, groupCA: v.group_ca).count, v.records.count)
        check(v.devices)
        XCTAssertEqual(set.revoked.contains(v.other), v.other_revoked)
        XCTAssertEqual(set.addAll(v.later, groupCA: v.group_ca).count, v.later.count)
        check(v.devices_later)
    }

    /// An admin computer freezing another (go-freeze.json, docs/protocol.md
    /// section 10, rule 4), as Go's TestGoFreezeVectors writes it.
    func testGoFreeze() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            struct Device: Decodable { var id: String, name: String, admin: Bool }
            struct Key: Decodable { var name: String, key: Data, frozen: Bool }
            struct Chain: Decodable { var name: String, chain: [Data], refused: Bool }
            var group_ca: Data
            var records: [Member.Record]
            var devices: [Device]
            var keys: [Key]
            var chains: [Chain]
            var digest: String
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-freeze.json")))
        var set = RecordSet()
        XCTAssertEqual(set.addAll(v.records.reversed(), groupCA: v.group_ca).count, v.records.count)
        XCTAssertEqual(set.digest, v.digest)
        XCTAssertEqual(set.devices.map(\.name), v.devices.map(\.name))
        XCTAssertEqual(set.devices.map(\.admin), v.devices.map(\.admin))
        for k in v.keys {
            XCTAssertEqual(set.isFrozen(k.key), k.frozen, k.name)
            XCTAssertFalse(set.revoked.contains(k.key), k.name)
        }
        for c in v.chains { XCTAssertEqual(set.refused(chain: c.chain) != nil, c.refused, c.name) }
    }

    /// testdata/interop/go-takeover.json, from Go's TestGoTakeoverVectors:
    /// an admin computer hands over a group whose root is a computer, but
    /// not a phone's group, not while another admin computer has frozen it,
    /// and not once the old root removed it.
    func testGoTakeover() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            struct Key: Decodable { var name: String, key: Data, revoked: Bool }
            struct Case: Decodable {
                var name: String
                var group_ca: Data
                var records: [Member.Record]
                var roots: [Data]?
                var keys: [Key]
                var digest: String
                var dropped: Int?
            }
            var cases: [Case]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-takeover.json")))
        XCTAssertEqual(v.cases.count, 4)
        for c in v.cases {
            var set = RecordSet()
            XCTAssertEqual(c.dropped ?? 0, c.name == "phone root" ? 1 : 0, c.name)
            XCTAssertEqual(set.addAll(c.records.reversed(), groupCA: c.group_ca).count, c.records.count - (c.dropped ?? 0), c.name)
            XCTAssertEqual(set.digest, c.digest, c.name)
            XCTAssertEqual(set.roots, c.roots ?? [], c.name)
            for k in c.keys { XCTAssertEqual(set.revoked.contains(k.key), k.revoked, "\(c.name): \(k.name)") }
        }
    }

    /// Watches (go-watch.json, from Go's TestGoWatchVectors; docs/protocol.md
    /// section 10, rule 8): a watch freezes and removes as a computer's admin
    /// CA does, but admits nobody, never makes a root, is never a hub and
    /// signs only the commands that turn things off and action.
    func testGoWatch() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            struct Device: Decodable { var id: String, name: String, role: String, admin: Bool }
            struct Key: Decodable { var name: String, key: Data, revoked: Bool, frozen: Bool, watch: Bool }
            struct Chain: Decodable { var name: String, chain: [Data], refused: Bool }
            struct Command: Decodable { var name: String, command: Member.Record, ok: Bool }
            struct Case: Decodable {
                var name: String
                var group_ca: Data
                var records: [Member.Record]
                var dropped: Int?
                var devices: [Device]
                var keys: [Key]
                var chains: [Chain]?
                var hubs: [String]
                var `self`: String?
                var now_ms: Int64?
                var commands: [Command]?
                var digest: String
            }
            var cases: [Case]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-watch.json")))
        XCTAssertEqual(v.cases.count, 3)
        for c in v.cases {
            var set = RecordSet()
            XCTAssertEqual(set.addAll(c.records.reversed(), groupCA: c.group_ca).count, c.records.count - (c.dropped ?? 0), c.name)
            XCTAssertEqual(set.digest, c.digest, c.name)
            XCTAssertEqual(set.roots, [], c.name)
            XCTAssertEqual(set.devices.map { "\($0.id) \($0.name) \($0.role) \($0.admin)" },
                           c.devices.map { "\($0.id) \($0.name) \($0.role) \($0.admin)" }, c.name)
            for k in c.keys {
                XCTAssertEqual(set.revoked.contains(k.key), k.revoked, "\(c.name): \(k.name) revoked")
                XCTAssertEqual(set.isFrozen(k.key), k.frozen, "\(c.name): \(k.name) frozen")
                XCTAssertEqual(set.isWatch(k.key), k.watch, "\(c.name): \(k.name) watch")
            }
            for ch in c.chains ?? [] { XCTAssertEqual(set.refused(chain: ch.chain) != nil, ch.refused, "\(c.name): \(ch.name)") }
            XCTAssertEqual(set.hubOrder, c.hubs, c.name)
            for d in set.devices where d.role == "watch" { XCTAssertFalse(set.mayHost(d.id), c.name) }
            for cmd in c.commands ?? [] {
                let ok = (try? Commands.verify(cmd.command, records: set, me: c.`self` ?? "", nowMS: c.now_ms ?? 0)) != nil
                XCTAssertEqual(ok, cmd.ok, "\(c.name): \(cmd.name)")
            }
        }
    }

    /// Writes swift-root.json for internal/group's TestSwiftRoot: a takeover
    /// as this kit signs it.
    func testTakeOverForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        var g = try Group(now: t0)
        _ = try g.b.takeOver(from: g.root.device, adminSigner: g.adminKey, rootSigner: g.newRootKey, now: t0)
        struct Out: Encodable {
            var group_ca: Data
            var records: [Member.Record]
            var roots: [Data]
            var devices: [String]
            var digest: String
            var lost, kept: Data // member certificates: the lost phone's, and the computer the old root admitted
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let out = Out(group_ca: g.root.groupCA, records: g.b.records.records.reversed(), roots: g.b.roots,
                      devices: g.b.devices.map(\.id), digest: g.b.records.digest ?? "", lost: g.root.memberCert, kept: g.one.cert)
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-root.json"))
    }
}
