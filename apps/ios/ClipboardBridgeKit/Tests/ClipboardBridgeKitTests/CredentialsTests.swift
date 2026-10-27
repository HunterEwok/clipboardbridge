// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import ClipboardBridgeKit
import Crypto
import Foundation
import XCTest

final class CredentialsTests: XCTestCase {
    typealias Credential = ServerCredentials.Credential

    /// Reads testdata/interop/go-credentials.json, from Go's
    /// TestGoCredentialVectors.
    func testGoCredentials() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct Lists: Decodable {
            var Hubs: [Data]
            var Admins: [Data]
            var Members: [Data]
        }
        struct Bad: Decodable {
            var name: String
            var set: [Credential]
        }
        struct V: Decodable {
            var group_ca: Data
            var records: [Member.Record]
            var lists: Lists
            var period: Credential
            var servers: [Credential]
            var hubs: Credential
            var members: Credential
            var now_ms: Int64
            var pseudonym: String
            var bad: [Bad]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-credentials.json")))
        var s = RecordSet()
        _ = s.addAll(v.records, groupCA: v.group_ca)
        let l = ServerCredentials.lists(s)
        XCTAssertEqual(l.hubs, v.lists.Hubs)
        XCTAssertEqual(l.admins, v.lists.Admins)
        XCTAssertEqual(l.members, v.lists.Members)

        let root = try CertificateInfo(der: v.group_ca).publicKey
        let devices = s.devices
        let isMember = { (k: Data) in devices.contains { $0.keys.contains(k) } }
        var store = CredentialStore(groupCA: v.group_ca)
        let (fresh, errs) = store.add(root: root, isMember: isMember, [v.period, v.hubs, v.members] + v.servers)
        XCTAssertEqual(errs, [])
        XCTAssertEqual(fresh.count, 3 + v.servers.count)
        let hb = try XCTUnwrap(store.hubs).1
        XCTAssertEqual(ServerCredentials.pseudonym(hb.hubs[0]), v.pseudonym)
        XCTAssertEqual(store.serverKeys(l.hubs), Array(hb.hubs.prefix(l.hubs.count)))
        XCTAssertFalse(store.listStale(hb.hubs, want: store.serverKeys(l.hubs), ordered: true))
        XCTAssertFalse(store.listStale(hb.admins, want: store.serverKeys(l.admins), ordered: false))
        // Again: nothing new.
        XCTAssertEqual(store.add(root: root, isMember: isMember, [v.period, v.hubs]).fresh.count, 0)

        let p = try ServerCredentials.checkPresented([v.hubs, v.members, v.period], nowMS: v.now_ms)
        XCTAssertNotNil(p.members)
        XCTAssertNotNil(p.period)
        for b in v.bad {
            XCTAssertThrowsError(try ServerCredentials.checkPresented(b.set, nowMS: v.now_ms), b.name)
        }
        var forged = v.hubs
        forged.body[10] ^= 1
        XCTAssertThrowsError(try forged.open())
    }

    /// Credentials the kit signs, as a root phone does for its period, are
    /// what the store and a server take.
    func testSigned() throws {
        let rootKey = SoftwareSigner()
        let ca = try GroupCertificates.groupCA(signer: rootKey, now: Date(timeIntervalSince1970: 1_790_000_000))
        let tag = GroupCertificates.tag(groupCA: ca)
        let now: Int64 = 1_792_000_000_000
        let periodKey = SoftwareSigner(), member = SoftwareSigner(), server = SoftwareSigner()
        let period = try ServerCredentials.signPeriod(groupTag: tag, tag: ServerCredentials.newPeriodTag(), periodKey: periodKey.publicKeyDER,
                                                      version: 1, nowMS: now, root: rootKey)
        let p = try period.open()
        let srv = try ServerCredentials.signServer(p, serverKey: server.publicKeyDER, version: 1, member: member)
        let serverHash = Data(SHA256.hash(data: server.publicKeyDER))
        let hubs = try ServerCredentials.signHubs(p, hubs: [serverHash], admins: [], version: 2, periodKey: periodKey)
        let members = try ServerCredentials.signMembers(p, members: [serverHash], version: 3, key: periodKey)
        XCTAssertEqual(try hubs.open().hubs.count, 4)
        XCTAssertEqual(try hubs.open().admins.count, 4)

        var store = CredentialStore(groupCA: ca)
        let memberHash = Data(SHA256.hash(data: member.publicKeyDER))
        let isMember = { (k: Data) in k == memberHash }
        let (fresh, errs) = store.add(root: rootKey.publicKeyDER, isMember: isMember, [members, hubs, srv, period])
        XCTAssertEqual(errs, [])
        XCTAssertEqual(fresh.count, 4)
        XCTAssertEqual(store.server(member: memberHash), serverHash)
        XCTAssertEqual(store.memberOfServer(serverHash), memberHash)
        XCTAssertFalse(store.periodStale(root: rootKey.publicKeyDER, isMember: isMember, nowMS: now + 1000))
        XCTAssertTrue(store.periodStale(root: rootKey.publicKeyDER, isMember: isMember, nowMS: now + ServerCredentials.periodRenewMS))
        // A removal: the member that signed a server key is gone.
        XCTAssertTrue(store.periodStale(root: rootKey.publicKeyDER, isMember: { _ in false }, nowMS: now + 1000))
        XCTAssertNotNil(try ServerCredentials.checkPresented([hubs, members], nowMS: now + 1000).members)

        // A period another key signed is not the group's.
        let stranger = try ServerCredentials.signPeriod(groupTag: tag, tag: ServerCredentials.newPeriodTag(), periodKey: periodKey.publicKeyDER,
                                                        version: 9, nowMS: now, root: SoftwareSigner())
        XCTAssertEqual(store.add(root: rootKey.publicKeyDER, isMember: { _ in true }, [stranger]).errors.count, 1)
        // A newer period with another tag drops the rest.
        let next = try ServerCredentials.signPeriod(groupTag: tag, tag: ServerCredentials.newPeriodTag(), periodKey: periodKey.publicKeyDER,
                                                    version: 5, nowMS: now, root: rootKey)
        XCTAssertEqual(store.add(root: rootKey.publicKeyDER, isMember: { _ in true }, [next]).fresh.count, 1)
        XCTAssertNil(store.hubs)
        XCTAssertNil(store.server(member: memberHash))
        XCTAssertEqual(store.all.count, 1)
        XCTAssertEqual(ServerCredentials.nextVersion(5, nowMS: now), now / 1000)
    }
}
