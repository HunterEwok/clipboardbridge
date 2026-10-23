// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// A second phone joins a phone group and becomes an admin (docs/protocol.md,
/// sections 6 and 10), then admits, renews and is removed.
final class PhoneJoinTests: XCTestCase {
    let t0 = Date()
    let sid = (0..<32).map { _ in UInt8.random(in: .min ... .max) }

    /// A device that listens for pairing: its device ID, member key and
    /// self-signed certificate.
    struct Listener {
        let device = SyncEngine.newID()
        let key = SoftwareSigner()
        let cert: Data
        init() throws { cert = try GroupCertificates.selfSigned(device: device, signer: key) }
    }

    /// Runs one pairing: the admitting phone dials the listener, which
    /// answers with joinerCode (code when nil).
    func pair(_ admitter: PhoneGroup, signer: CertificateSigner, _ l: Listener, info: Pairing.Info, code: String = "123456",
              joinerCode: String? = nil, makeAdmin: Bool = true, now: Date? = nil)
        async -> (member: Result<(PhoneGroup, PairingMember.Admitted), Error>, joiner: Result<PairingJoiner.Joined, Error>) {
        let now = now ?? t0
        let (m, j) = Pipe.pair()
        let sid = sid
        let memberSide = Task { () async throws -> (PhoneGroup, PairingMember.Admitted) in
            var g = admitter
            let a = try await g.admit(over: m, code: code, joinerCert: l.cert, sessionID: sid, caSigner: signer, makeAdmin: makeAdmin, now: now)
            return (g, a)
        }
        let joined: Result<PairingJoiner.Joined, Error>
        do {
            joined = .success(try await PairingJoiner.accept(over: j, code: joinerCode ?? code, info: info, memberCert: admitter.memberCert,
                                                             joinerCert: l.cert, sessionID: sid, now: now) { _ in })
        } catch {
            joined = .failure(error)
        }
        j.close()
        let member: Result<(PhoneGroup, PairingMember.Admitted), Error>
        do { member = .success(try await memberSide.value) } catch { member = .failure(error) }
        return (member, joined)
    }

    func testSecondPhoneBecomesAdmin() async throws {
        let rootKey = SoftwareSigner()
        var root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, name: "First", now: t0)
        XCTAssertEqual(root.records.rootDevice, root.device)

        // The second phone joins with an admin key and gets its admin CA.
        let second = try Listener(), adminKey = SoftwareSigner()
        let r = await pair(root, signer: rootKey, second, info: .init(name: "Second", os: "ios", adminKey: adminKey.publicKeyDER))
        let joined = try r.joiner.get()
        let (rootAfter, admitted) = try r.member.get()
        root = rootAfter
        XCTAssertTrue(admitted.confirmed)
        XCTAssertEqual(joined.device, second.device)
        let adminCA = try XCTUnwrap(joined.welcome.adminCA)
        XCTAssertNoThrow(try GroupCertificates.checkAdminCA(adminCA, root: root.groupCA))
        XCTAssertTrue(root.computers.isEmpty, "a phone is no computer")
        let listed = try XCTUnwrap(root.devices.first { $0.id == second.device })
        XCTAssertEqual(listed.role, "phone")
        XCTAssertTrue(listed.admin)

        var admin = PhoneGroup.joined(joined)
        XCTAssertFalse(admin.isRoot)
        XCTAssertTrue(admin.isAdmin)
        XCTAssertEqual(admin.tag, root.tag)
        XCTAssertEqual(admin.memberChain, [joined.welcome.cert])
        // The records reach it through the computers.
        for rec in root.records.records { admin.records.add(rec, groupCA: admin.groupCA) }
        XCTAssertEqual(admin.records.rootDevice, root.device)

        // The admin admits a computer from its own admin CA.
        let pc = try Listener()
        let r2 = await pair(admin, signer: adminKey, pc, info: .init(name: "pi", os: "linux"))
        let pcJoined = try r2.joiner.get()
        (admin, _) = try r2.member.get()
        XCTAssertEqual(pcJoined.welcome.issuer, adminCA)
        XCTAssertNil(pcJoined.welcome.adminCA)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: [pcJoined.welcome.cert, adminCA], groupCA: root.groupCA, now: t0), pc.device)
        XCTAssertEqual(admin.computers.map(\.device), [pc.device])
        for rec in admin.records.records { root.records.add(rec, groupCA: root.groupCA) }
        XCTAssertTrue(root.devices.contains { $0.id == pc.device }, "a record signed through the admin CA counts")

        // Renewals: an admin renews what it issued, the root renews any.
        let later = t0.addingTimeInterval(500 * 24 * 3600)
        let pcChain = [pcJoined.welcome.cert, adminCA]
        let byAdmin = try XCTUnwrap(admin.renewal(chain: pcChain, caSigner: adminKey, now: later))
        XCTAssertEqual(byAdmin.issuer, adminCA)
        XCTAssertEqual(try GroupCertificates.verifyMember(byAdmin.cert, groupCA: root.groupCA, issuer: adminCA, now: later), pc.device)
        // An admin renews what the root issued too, from its own admin CA.
        let rootsOne = try XCTUnwrap(admin.renewal(chain: [root.memberCert], caSigner: adminKey, now: later))
        XCTAssertEqual(try GroupCertificates.verifyMember(rootsOne.cert, groupCA: root.groupCA, issuer: adminCA, now: later), root.device)
        let byRoot = try XCTUnwrap(root.renewal(chain: pcChain, caSigner: rootKey, now: later)).cert
        XCTAssertEqual(try GroupCertificates.verifyMember(byRoot, groupCA: root.groupCA, now: later), pc.device)
        XCTAssertTrue(try admin.renewOwnCertificate(caSigner: adminKey, now: later))
        XCTAssertEqual(admin.memberIssuer, adminCA)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: admin.memberChain, groupCA: root.groupCA, now: later), admin.device)

        // The admin cannot remove the root; the root removes the admin and
        // keeps the computer it admitted.
        XCTAssertThrowsError(try admin.revoke(device: root.device, caSigner: adminKey, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .cannotRemoveRoot)
        }
        let revocation = try root.revoke(device: second.device, caSigner: rootKey, now: t0)
        let body = try JSONDecoder().decode(Records.Body.self, from: revocation.body)
        XCTAssertEqual(Set(body.keys ?? []), [listed.key, try Records.keyHash(cert: adminCA)])
        XCTAssertEqual(body.keep, [try Records.keyHash(cert: pcJoined.welcome.cert)])
        XCTAssertFalse(root.devices.contains { $0.id == second.device })
        XCTAssertTrue(root.devices.contains { $0.id == pc.device })
        XCTAssertNil(root.records.refused(chain: pcChain))
        XCTAssertNotNil(root.records.refused(chain: [joined.welcome.cert]))
    }

    func testPhoneWithoutAdmin() async throws {
        let rootKey = SoftwareSigner()
        let root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let l = try Listener()
        let r = await pair(root, signer: rootKey, l, info: .init(name: "Third", os: "ios", adminKey: SoftwareSigner().publicKeyDER),
                           makeAdmin: false)
        let joined = try r.joiner.get()
        XCTAssertNil(joined.welcome.adminCA)
        let (after, _) = try r.member.get()
        XCTAssertEqual(after.devices.first { $0.id == l.device }?.admin, false)
        var g = PhoneGroup.joined(joined)
        XCTAssertFalse(g.isAdmin)
        XCTAssertThrowsError(try g.revoke(device: root.device, caSigner: rootKey, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notAdmin)
        }
        XCTAssertFalse(try g.renewOwnCertificate(caSigner: rootKey, now: t0.addingTimeInterval(500 * 24 * 3600)))

        // An admin that is not the root makes no admins.
        let adminKey = SoftwareSigner(), l2 = try Listener()
        let r2 = await pair(root, signer: rootKey, l2, info: .init(name: "Admin", os: "ios", adminKey: adminKey.publicKeyDER))
        let admin = PhoneGroup.joined(try r2.joiner.get())
        let l3 = try Listener()
        let r3 = await pair(admin, signer: adminKey, l3, info: .init(name: "Fourth", os: "android", adminKey: SoftwareSigner().publicKeyDER))
        XCTAssertNil(try r3.joiner.get().welcome.adminCA)
    }

    func testWrongCode() async throws {
        let rootKey = SoftwareSigner()
        let root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let r = await pair(root, signer: rootKey, try Listener(), info: .init(name: "Second", os: "ios"), joinerCode: "654321")
        XCTAssertThrowsError(try r.joiner.get()) { XCTAssertEqual($0 as? PairingJoiner.Failure, .refused(.wrongCode)) }
        XCTAssertThrowsError(try r.member.get()) { XCTAssertEqual($0 as? PairingMember.Failure, .refused(.wrongCode)) }
    }

    func testJoinerRefusesAWelcomeForAnotherKey() async throws {
        let rootKey = SoftwareSigner()
        let root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let l = try Listener()
        let (m, j) = Pipe.pair()
        let (sid, t0) = (sid, t0)
        let memberSide = Task {
            try await PairingMember.admit(over: m, code: "123456", memberCert: root.memberCert, joinerCert: l.cert, sessionID: sid,
                                          memberAD: .init(device: root.device, group: root.tag)) { dev, _, _ in
                Pairing.Welcome(cert: try GroupCertificates.member(device: dev, publicKey: SoftwareSigner().publicKeyDER, ca: root.groupCA,
                                                                   caSigner: rootKey, now: t0), groupCA: root.groupCA)
            }
        }
        do {
            _ = try await PairingJoiner.accept(over: j, code: "123456", info: .init(name: "Second", os: "ios"), memberCert: root.memberCert,
                                               joinerCert: l.cert, sessionID: sid, now: t0) { _ in XCTFail("stored a bad welcome") }
            XCTFail("took a certificate for another key")
        } catch {
            guard case .badWelcome = error as? PairingJoiner.Failure else { return XCTFail("\(error)") }
        }
        let admitted = try await memberSide.value
        XCTAssertFalse(admitted.confirmed)
    }

    func testInfo() throws {
        let key = SoftwareSigner().publicKeyDER
        XCTAssertTrue(Pairing.Info(name: "iPhone", os: "ios", adminKey: key).isValid)
        XCTAssertTrue(Pairing.Info(name: "iPhone", os: "ios").isValid)
        XCTAssertFalse(Pairing.Info(name: "pi", os: "linux", adminKey: key).isValid, "only a phone sends an admin key")
        XCTAssertFalse(Pairing.Info(name: "iPhone", os: "ios", adminKey: Data([1, 2, 3])).isValid)
        XCTAssertFalse(Pairing.Info(name: "pc", os: "windows").isValid)
        XCTAssertTrue(Pairing.Info(name: "Pixel", os: "android", adminKey: key).isValid, "an Android phone joins as a phone")
        XCTAssertTrue(Pairing.Info(name: "router", os: "linux", role: Pairing.Info.lite).isValid, "a lite member")
        XCTAssertFalse(Pairing.Info(name: "router", os: "linux", role: "full").isValid)
        // A computer's Info is encoded as before, without the admin key.
        let json = String(decoding: try JSONEncoder().encode(Pairing.Info(name: "pi", os: "linux")), as: UTF8.self)
        XCTAssertFalse(json.contains("admin_key"))

        let l = try Listener()
        let info = try CertificateInfo(der: l.cert)
        XCTAssertEqual(info.commonName, l.device)
        XCTAssertEqual(info.publicKey, l.key.publicKeyDER)
        XCTAssertEqual(info.notBefore, Date(timeIntervalSince1970: 0))
    }

    func testJoinCodeText() {
        let jc = JoinCode(code: "246802", addrs: ["192.168.1.20:8767", JoinCode.address(host: "fd00::5", port: 8767)], fingerprint: "abc_-")
        XCTAssertEqual(jc.addrs[1], "[fd00::5]:8767")
        XCTAssertEqual(JoinCode(qr: jc.qrText), jc)
        XCTAssertTrue(jc.qrText.hasPrefix("clipboardbridge://join?code=246802&addr=192.168.1.20:8767&"))
        for _ in 0..<20 { XCTAssertTrue(JoinCode(code: JoinCode.newCode(), addrs: [], fingerprint: "").codeIsValid) }
    }

    func testHomeAddresses() {
        for a in ["10.0.0.2", "172.16.1.1", "172.31.255.1", "192.168.0.225"] { XCTAssertTrue(LocalAddresses.isHome(ipv4: a), a) }
        for a in ["8.8.8.8", "172.32.0.1", "169.254.1.1", "127.0.0.1", "100.64.0.1", "1.2.3"] { XCTAssertFalse(LocalAddresses.isHome(ipv4: a), a) }
        XCTAssertTrue(LocalAddresses.isHome(ipv6: "fd12:3456::1"))
        XCTAssertFalse(LocalAddresses.isHome(ipv6: "fe80::1%en0"))
        XCTAssertFalse(LocalAddresses.isHome(ipv6: "2001:db8::1"))
        XCTAssertLessThanOrEqual(LocalAddresses.current().count, JoinCode.maxAddrs)
    }

    func testOldFileIsARoot() throws {
        let g = try PhoneGroup.create(caSigner: SoftwareSigner(), memberKey: SoftwareSigner().publicKeyDER, now: t0)
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(g)) as? [String: Any])
        json["isRoot"] = nil
        let old = try JSONDecoder().decode(PhoneGroup.self, from: JSONSerialization.data(withJSONObject: json))
        XCTAssertTrue(old.isRoot)
        XCTAssertTrue(old.isAdmin)
        XCTAssertEqual(old.memberChain, [g.memberCert])
    }
}
