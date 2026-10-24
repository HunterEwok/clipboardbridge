// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// A computer as admin (docs/protocol.md, section 10): the root phone
/// certifies the admin key that a computer's hello offers.
final class ComputerAdminTests: XCTestCase {
    let t0 = Date()
    /// Later than t0, so that the admin record replaces the computer's first.
    var t1: Date { t0.addingTimeInterval(1) }

    /// The root phone's group with one computer, pi, in its list.
    func group() throws -> (g: PhoneGroup, root: SoftwareSigner, pi: String, piKey: Data) {
        let root = SoftwareSigner()
        var g = try PhoneGroup.create(caSigner: root, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let pi = SyncEngine.newID()
        let cert = try GroupCertificates.member(device: pi, publicKey: SoftwareSigner().publicKeyDER, ca: g.groupCA, caSigner: root, now: t0)
        let key = try Records.keyHash(cert: cert)
        _ = try g.record(device: pi, name: "pi", role: "linux", key: key, caSigner: root, now: t0)
        return (g, root, pi, key)
    }

    func testWire() throws {
        let key = SoftwareSigner().publicKeyDER
        let hello = Member.Message.hello(.full, Member.Hello(wallMS: 1, name: "pi", adminKey: key))
        let body = Data(try Member.encode(hello).dropFirst(4))
        XCTAssertTrue(String(decoding: body, as: UTF8.self).contains("\"admin_key\""))
        XCTAssertEqual(try Member.decode(body: body), hello)
        let admin = Member.Message.admin(Data([1, 2, 3]))
        let adminBody = Data(try Member.encode(admin).dropFirst(4))
        XCTAssertEqual(String(decoding: adminBody, as: UTF8.self), #"{"admin_ca":"AQID","t":"admin"}"#)
        XCTAssertEqual(try Member.decode(body: adminBody), admin)
        guard case let .hello(_, h) = try Member.decode(body: Data(#"{"t":"hello","role":"full","hello":{"wall_ms":0}}"#.utf8)) else {
            return XCTFail("not a hello")
        }
        XCTAssertNil(h.adminKey)
    }

    func testMakeAdmin() throws {
        let t = try group()
        var g = t.g
        let (root, pi, piKey) = (t.root, t.pi, t.piKey)
        let adminKey = SoftwareSigner()
        let (ca, r) = try g.makeAdmin(device: pi, adminKey: adminKey.publicKeyDER, rootSigner: root, now: t1)
        XCTAssertEqual(try CertificateInfo(der: ca).publicKey, adminKey.publicKeyDER)
        let d = try XCTUnwrap(g.devices.first { $0.id == pi })
        XCTAssertTrue(d.admin)
        XCTAssertEqual(d.adminKey, try Records.keyHash(cert: ca))
        XCTAssertEqual(d.key, piKey)
        XCTAssertTrue(g.records.records.contains(r))
        XCTAssertEqual(g.computerAdminCA(for: adminKey.publicKeyDER), ca)
        XCTAssertNil(g.computerAdminCA(for: SoftwareSigner().publicKeyDER))

        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? FileManager.default.removeItem(at: url) }
        try g.save(to: url)
        XCTAssertEqual(try PhoneGroup.load(from: url)?.computerAdmins, g.computerAdmins)

        XCTAssertThrowsError(try g.makeAdmin(device: g.device, adminKey: adminKey.publicKeyDER, rootSigner: root, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notAComputer)
        }
        XCTAssertThrowsError(try g.makeAdmin(device: SyncEngine.newID(), adminKey: adminKey.publicKeyDER, rootSigner: root, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .unknownDevice)
        }
        var notRoot = g
        notRoot.isRoot = false
        XCTAssertThrowsError(try notRoot.makeAdmin(device: pi, adminKey: adminKey.publicKeyDER, rootSigner: root, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notRoot)
        }

        // The admin computer admits the deck; removing the computer keeps it.
        let deck = SyncEngine.newID()
        let deckCert = try GroupCertificates.member(device: deck, publicKey: SoftwareSigner().publicKeyDER, ca: ca, caSigner: adminKey, now: t0)
        g.add([try Records.device(deck, name: "deck", role: "linux", key: Records.keyHash(cert: deckCert), group: g.tag, by: pi, now: t0,
                                  signer: adminKey, adminCA: ca)])
        XCTAssertTrue(g.devices.contains { $0.id == deck })
        _ = try g.revoke(device: pi, caSigner: root, now: t0)
        XCTAssertEqual(Set(g.devices.map(\.id)), [g.device, deck])
        XCTAssertNil(g.computerAdmins[pi])
        XCTAssertNil(g.computerAdminCA(for: adminKey.publicKeyDER))
    }

    /// Reads the next message from the phone, at most ten tries, until one
    /// is what want accepts.
    func next(from t: Pipe, _ want: (Member.Message) -> Bool) async throws -> Member.Message? {
        for _ in 0..<10 {
            let n = try Member.length(header: try await t.read(exactly: 4))
            let m = try Member.decode(body: try await t.read(exactly: n))
            if want(m) { return m }
        }
        return nil
    }

    func testNodeSendsTheAdminCA() async throws {
        let key = SoftwareSigner().publicKeyDER, ca = Data([7, 7])
        let phone = MemberNode(engine: SyncEngine(device: SyncEngine.newID(), clock: HybridClock()), name: "iPhone",
                               adminCA: { $0 == key ? ca : nil })
        let pi = SyncEngine.newID()
        let (a, b) = Pipe.pair()
        let task = Task { try await phone.serve(a, peer: pi) }
        try await b.write(Member.encode(.hello(.full, Member.Hello(wallMS: 0, adminKey: key))))
        let first = try await next(from: b) { if case .admin = $0 { true } else { false } }
        XCTAssertEqual(first, .admin(ca), "the root sends the admin CA it issued for the offered key")
        let offered = await phone.offeredAdminKeys
        XCTAssertEqual(offered, [pi: key])
        await phone.send(adminCA: Data([8]), to: pi)
        let second = try await next(from: b) { if case .admin = $0 { true } else { false } }
        XCTAssertEqual(second, .admin(Data([8])))
        await phone.closeAll()
        try await task.value
    }

    /// Writes the root's admin CA for a computer's admin key and the records
    /// that list it as an admin, for the Go side (internal/group,
    /// TestSwiftComputerAdmin), when CBB_INTEROP_OUT names a
    /// directory.
    func testComputerAdminForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        let t = try group()
        var g = t.g
        let (root, pi) = (t.root, t.pi)
        let adminKey = SoftwareSigner()
        let (ca, _) = try g.makeAdmin(device: pi, adminKey: adminKey.publicKeyDER, rootSigner: root, now: t1)
        struct Out: Encodable {
            var group_ca: Data
            var device: String
            var admin_key: Data
            var admin_ca: Data
            var records: [Member.Record]
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let out = Out(group_ca: g.groupCA, device: pi, admin_key: adminKey.publicKeyDER, admin_ca: ca, records: g.records.records)
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-computer-admin.json"))
    }
}
