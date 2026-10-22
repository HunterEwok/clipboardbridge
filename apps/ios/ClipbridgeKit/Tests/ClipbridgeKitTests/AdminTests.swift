// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipbridgeKit
import Foundation
import XCTest

/// Admin CAs under a phone's root (docs/protocol.md, section 10): the
/// certificates they issue and the records they sign.
final class AdminTests: XCTestCase {
    struct Group {
        let t0 = Date()
        let root = SoftwareSigner(), admin = SoftwareSigner()
        let rootCA: Data, adminCA: Data, adminDevice = SyncEngine.newID()

        init() throws {
            rootCA = try GroupCertificates.groupCA(signer: root, now: t0, pathLength: 1)
            adminCA = try GroupCertificates.adminCA(device: adminDevice, publicKey: admin.publicKeyDER, root: rootCA, rootSigner: root)
        }

        var tag: String { GroupCertificates.tag(groupCA: rootCA) }

        /// A member certificate from the admin CA, or from the root.
        func member(byAdmin: Bool = true) throws -> (device: String, key: SoftwareSigner, cert: Data) {
            let key = SoftwareSigner(), dev = SyncEngine.newID()
            let cert = try GroupCertificates.member(device: dev, publicKey: key.publicKeyDER, ca: byAdmin ? adminCA : rootCA,
                                                    caSigner: byAdmin ? admin : root, now: t0)
            return (dev, key, cert)
        }
    }

    func testAdminCA() throws {
        let g = try Group()
        XCTAssertNoThrow(try GroupCertificates.checkAdminCA(g.adminCA, root: g.rootCA))
        let m = try g.member()
        XCTAssertEqual(try GroupCertificates.verifyMember(m.cert, groupCA: g.rootCA, issuer: g.adminCA, now: g.t0), m.device)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: [m.cert, g.adminCA], groupCA: g.rootCA, now: g.t0), m.device)
        XCTAssertThrowsError(try GroupCertificates.verifyMember(m.cert, groupCA: g.rootCA, now: g.t0), "without its issuer")
        XCTAssertThrowsError(try GroupCertificates.verifyMember(chain: [m.cert], groupCA: g.rootCA, now: g.t0))
        let byRoot = try g.member(byAdmin: false)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: [byRoot.cert], groupCA: g.rootCA, now: g.t0), byRoot.device)

        // A member certificate is no admin CA, and a computer's group CA
        // (path length 0) certifies none.
        XCTAssertThrowsError(try GroupCertificates.checkAdminCA(byRoot.cert, root: g.rootCA))
        XCTAssertThrowsError(try GroupCertificates.verifyMember(m.cert, groupCA: g.rootCA, issuer: byRoot.cert, now: g.t0))
        let flat = try GroupCertificates.groupCA(signer: g.root, now: g.t0)
        let under = try GroupCertificates.adminCA(device: g.adminDevice, publicKey: g.admin.publicKeyDER, root: flat, rootSigner: g.root)
        XCTAssertThrowsError(try GroupCertificates.checkAdminCA(under, root: flat))
        // Another group's admin CA does not count.
        let other = try Group()
        XCTAssertThrowsError(try GroupCertificates.checkAdminCA(other.adminCA, root: g.rootCA))
    }

    func testRecordsThroughAdminCA() throws {
        let g = try Group()
        let pc = try g.member(), phone = try g.member(byAdmin: false)
        let adminKey = try Records.keyHash(cert: g.adminCA)
        var set = RecordSet()
        let adminRecord = try Records.device(g.adminDevice, name: "Second", role: "phone", key: Records.keyHash(spki: g.admin.publicKeyDER),
                                             admin: adminKey, group: g.tag, by: g.adminDevice, now: g.t0, signer: g.root)
        let pcRecord = try Records.device(pc.device, name: "Desk", role: "linux", key: Records.keyHash(cert: pc.cert),
                                          group: g.tag, by: g.adminDevice, now: g.t0, signer: g.admin, adminCA: g.adminCA)
        let phoneRecord = try Records.device(phone.device, name: "Phone", role: "phone", key: Records.keyHash(cert: phone.cert),
                                             group: g.tag, by: g.adminDevice, now: g.t0, signer: g.root)
        XCTAssertTrue(set.add(adminRecord, groupCA: g.rootCA))
        XCTAssertTrue(set.add(pcRecord, groupCA: g.rootCA))
        XCTAssertTrue(set.add(phoneRecord, groupCA: g.rootCA))
        XCTAssertEqual(set.devices.map(\.name), ["Desk", "Phone", "Second"])
        XCTAssertEqual(set.devices.first { $0.name == "Second" }?.admin, true)
        XCTAssertNil(set.refused(chain: [pc.cert, g.adminCA]))

        // Signed by the admin key without its chain, or with a chain that
        // is not an admin CA, a record is refused.
        let noChain = try Records.device(pc.device, name: "X", role: "linux", key: Records.keyHash(cert: pc.cert),
                                         group: g.tag, by: g.adminDevice, now: g.t0, signer: g.admin)
        XCTAssertFalse(set.add(noChain, groupCA: g.rootCA))
        let badChain = try Records.device(pc.device, name: "X", role: "linux", key: Records.keyHash(cert: pc.cert),
                                          group: g.tag, by: g.adminDevice, now: g.t0, signer: pc.key, adminCA: pc.cert)
        XCTAssertFalse(set.add(badChain, groupCA: g.rootCA))

        // The admin phone is lost: the root revokes its admin CA and its
        // key, keeping the computer it admitted.
        var keep = set
        let lost = [adminKey, try Records.keyHash(spki: g.admin.publicKeyDER)]
        XCTAssertTrue(keep.add(try Records.revoke(lost, keep: [Records.keyHash(cert: pc.cert)], group: g.tag, by: phone.device,
                                                  now: g.t0, signer: g.root), groupCA: g.rootCA))
        XCTAssertEqual(keep.devices.map(\.name), ["Desk", "Phone"])
        XCTAssertNil(keep.refused(chain: [pc.cert, g.adminCA]))
        // Without keeping it, the computer goes too.
        var drop = set
        XCTAssertTrue(drop.add(try Records.revoke(lost, group: g.tag, by: phone.device, now: g.t0, signer: g.root), groupCA: g.rootCA))
        XCTAssertEqual(drop.devices.map(\.name), ["Phone"])
        XCTAssertNotNil(drop.refused(chain: [pc.cert, g.adminCA]))
        // Records the lost admin signs after that count for nothing.
        let late = try g.member()
        XCTAssertTrue(drop.add(try Records.device(late.device, name: "Late", role: "linux", key: Records.keyHash(cert: late.cert),
                                                  group: g.tag, by: g.adminDevice, now: g.t0, signer: g.admin, adminCA: g.adminCA),
                               groupCA: g.rootCA))
        XCTAssertEqual(drop.devices.map(\.name), ["Phone"])
    }

    func testRenewalOfAdminIssued() throws {
        let g = try Group()
        let m = try g.member()
        let later = g.t0.addingTimeInterval(500 * 24 * 3600)
        XCTAssertNil(try GroupCertificates.renewal(of: m.cert, groupCA: g.rootCA, caSigner: g.root, now: later), "without its issuer")
        let renewed = try XCTUnwrap(GroupCertificates.renewal(of: m.cert, groupCA: g.rootCA, issuer: g.adminCA, caSigner: g.root, now: later))
        XCTAssertEqual(try GroupCertificates.verifyMember(renewed, groupCA: g.rootCA, now: later), m.device)
    }

    func testWelcomeIssuer() throws {
        let g = try Group()
        let m = try g.member()
        let f = Pairing.Frame(welcome: Pairing.Welcome(cert: m.cert, groupCA: g.rootCA, issuer: g.adminCA))
        let json = try JSONSerialization.jsonObject(with: Pairing.encode(f).dropFirst(4)) as? [String: Any]
        let w = try XCTUnwrap(json?["welcome"] as? [String: Any])
        XCTAssertEqual(w["issuer"] as? String, g.adminCA.base64EncodedString())
        let plain = try Pairing.encode(Pairing.Frame(welcome: Pairing.Welcome(cert: m.cert, groupCA: g.rootCA)))
        XCTAssertFalse(String(decoding: plain, as: UTF8.self).contains("issuer"))
    }

    /// Writes swift-admin.json for internal/group's TestSwiftAdmin.
    func testAdminForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CLIPBRIDGE_INTEROP_OUT"] else { return }
        let g = try Group()
        let pc = try g.member()
        let adminKey = try Records.keyHash(cert: g.adminCA)
        let records = [
            try Records.device(g.adminDevice, name: "Second", role: "phone", key: Records.keyHash(spki: g.admin.publicKeyDER),
                               admin: adminKey, group: g.tag, by: g.adminDevice, now: g.t0, signer: g.root),
            try Records.device(pc.device, name: "Desk", role: "linux", key: Records.keyHash(cert: pc.cert),
                               group: g.tag, by: g.adminDevice, now: g.t0, signer: g.admin, adminCA: g.adminCA),
        ]
        var set = RecordSet()
        for r in records { XCTAssertTrue(set.add(r, groupCA: g.rootCA)) }
        struct Out: Encodable {
            var group_ca, admin_ca, cert, key: Data
            var device: String
            var records: [Member.Record]
            var devices: [String]
            var digest: String
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let out = Out(group_ca: g.rootCA, admin_ca: g.adminCA, cert: pc.cert, key: pc.key.key.derRepresentation, device: pc.device,
                      records: records, devices: set.devices.map(\.id), digest: set.digest ?? "")
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-admin.json"))
    }
}
