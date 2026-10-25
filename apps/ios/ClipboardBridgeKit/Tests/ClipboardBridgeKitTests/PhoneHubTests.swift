// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import XCTest
@testable import ClipboardBridgeKit

/// The phone as the group's hub: admitting clients by their tunnel keys,
/// and the offer a hello's tunnel key gets.
final class PhoneHubTests: XCTestCase {
    private func key(_ b: UInt8) -> Data { Data(repeating: b, count: 32) }

    func testAdmitsAsAComputersHub() throws {
        let hub = PhoneHub(publicKey: key(1))
        let (a, b) = (SyncEngine.newID(), SyncEngine.newID())
        let first = try hub.admit(device: a, key: key(2))
        XCTAssertTrue(first.changed)
        XCTAssertEqual(first.client.psk.count, 32)

        // The same key keeps its preshared key; a new key gets a new one.
        let same = try hub.admit(device: a, key: key(2))
        XCTAssertFalse(same.changed)
        XCTAssertEqual(same.client.psk, first.client.psk)
        let renewed = try hub.admit(device: a, key: key(3))
        XCTAssertNotEqual(renewed.client.psk, first.client.psk)
        XCTAssertEqual(hub.clients.count, 1)

        // Another device's key, the hub's own, no key, and a bad device are refused.
        XCTAssertThrowsError(try hub.admit(device: b, key: key(3))) { XCTAssertEqual($0 as? PhoneHub.Refused, .keyOfAnother(a)) }
        XCTAssertThrowsError(try hub.admit(device: b, key: key(1)))
        XCTAssertThrowsError(try hub.admit(device: b, key: key(0)))
        XCTAssertThrowsError(try hub.admit(device: b, key: Data(count: 31)))
        XCTAssertThrowsError(try hub.admit(device: "B", key: key(4)))

        // The clients go to cbbtun as JSON and come back from it.
        _ = try hub.admit(device: b, key: key(4))
        XCTAssertEqual(try PhoneHub.clients(json: try hub.clientsJSON()), hub.clients)
        XCTAssertEqual(try PhoneHub.clients(json: ""), [])
        XCTAssertThrowsError(try PhoneHub.clients(json: "{}"))

        XCTAssertEqual(hub.prune { $0.device != a }, [a])
        XCTAssertEqual(hub.clients.map(\.device), [b])
    }

    func testKeepsAtMost256Clients() throws {
        let hub = PhoneHub(publicKey: key(1))
        for i in 0..<PhoneHub.maxClients {
            var k = key(7)
            (k[0], k[1]) = (UInt8(i & 0xff), UInt8(i >> 8))
            _ = try hub.admit(device: SyncEngine.newID(), key: k)
        }
        XCTAssertThrowsError(try hub.admit(device: SyncEngine.newID(), key: key(9))) { XCTAssertEqual($0 as? PhoneHub.Refused, .tooManyClients) }
    }

    func testOffersWaitForVLESS() throws {
        let hub = PhoneHub(publicKey: key(1))
        hub.endpoints = ["203.0.113.1:8764"]
        let c = try hub.admit(device: SyncEngine.newID(), key: key(2)).client
        let o = try XCTUnwrap(hub.offer(for: c))
        XCTAssertTrue(o.isValid)
        XCTAssertEqual(o.endpoints, ["203.0.113.1:8764"])
        hub.vlessOnly = true
        XCTAssertNil(hub.offer(for: c))
        hub.vless = Member.VLESS(endpoint: "203.0.113.1:443", publicKey: key(3), shortID: "ab", serverName: "example.com", id: UUID().uuidString)
        XCTAssertEqual(hub.offer(for: c)?.vless, hub.vless)
    }

    /// A computer's hello with a tunnel key gets the hub's offer; the hub
    /// ignores an offer it gets.
    func testNodeAnswersTheTunnelKey() async throws {
        let hub = PhoneHub(publicKey: key(1))
        hub.endpoints = ["203.0.113.1:8764"]
        let phone = MemberNode(engine: SyncEngine(device: SyncEngine.newID(), clock: HybridClock()), name: "iPhone",
                               tunnelKey: key(5), hub: { d, k, _ in hub.offer(device: d, key: k) },
                               onTunnel: { _, _ in XCTFail("the hub took an offer") })
        let pc = SyncEngine.newID()
        let (a, b) = Pipe.pair()
        a.peerCertificate = Data([1])
        let task = Task { try await phone.serve(a, peer: pc) }
        let n = try Member.length(header: try await b.read(exactly: 4))
        guard case .hello = try Member.decode(body: try await b.read(exactly: n)) else { return XCTFail("no hello") }
        var hello = Member.Hello(wallMS: 0)
        hello.tunnelKey = key(2)
        try await b.write(Member.encode(.hello(.full, hello)))
        try await b.write(Member.encode(.tunnel(Member.TunnelOffer(hubKey: key(8), psk: key(9)))))
        var offer: Member.TunnelOffer?
        while offer == nil {
            let m = try Member.length(header: try await b.read(exactly: 4))
            if case let .tunnel(o) = try Member.decode(body: try await b.read(exactly: m)) { offer = o }
        }
        XCTAssertEqual(offer?.hubKey, key(1))
        XCTAssertEqual(offer?.psk, hub.clients.first?.psk)
        XCTAssertEqual(offer?.endpoints, ["203.0.113.1:8764"])
        XCTAssertEqual(hub.clients.map(\.device), [pc])
        await phone.closeAll()
        try await task.value
    }
}
