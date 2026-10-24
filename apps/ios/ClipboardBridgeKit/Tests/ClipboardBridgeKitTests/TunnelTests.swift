// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation
import XCTest
@testable import ClipboardBridgeKit

/// The tunnel key in the phone's hello and the hub's offer for it
/// (docs/protocol.md, section 11).
final class TunnelTests: XCTestCase {
    func testNodeOffersTheTunnelKeyAndKeepsTheOffer() async throws {
        let key = Data(repeating: 1, count: 32)
        let (offers, got) = AsyncStream.makeStream(of: (String?, Member.TunnelOffer).self)
        let phone = MemberNode(engine: SyncEngine(device: SyncEngine.newID(), clock: HybridClock()), name: "iPhone",
                               tunnelKey: key, onTunnel: { _ = got.yield(($0, $1)) })
        let hub = SyncEngine.newID()
        let (a, b) = Pipe.pair()
        let task = Task { try await phone.serve(a, peer: hub) }
        let n = try Member.length(header: try await b.read(exactly: 4))
        guard case let .hello(_, h) = try Member.decode(body: try await b.read(exactly: n)) else { return XCTFail("no hello") }
        XCTAssertEqual(h.tunnelKey, key)
        try await b.write(Member.encode(.hello(.linux, Member.Hello(wallMS: 0))))
        // A bad offer is dropped; a good one reaches onTunnel.
        try await b.write(Member.encode(.tunnel(Member.TunnelOffer(hubKey: Data(count: 31), psk: Data(count: 32)))))
        try await b.write(Member.encode(.tunnel(nil)))
        let good = Member.TunnelOffer(hubKey: Data(repeating: 2, count: 32), psk: Data(repeating: 3, count: 32),
                                      endpoints: ["192.0.2.1:8764"])
        try await b.write(Member.encode(.tunnel(good)))
        var it = offers.makeAsyncIterator()
        let first = await it.next()
        XCTAssertEqual(first?.0, hub)
        XCTAssertEqual(first?.1, good)

        // The next connection offers the new key.
        await phone.set(tunnelKey: nil)
        let (c, d) = Pipe.pair()
        let second = Task { try await phone.serve(c, peer: hub) }
        let m = try Member.length(header: try await d.read(exactly: 4))
        guard case let .hello(_, h2) = try Member.decode(body: try await d.read(exactly: m)) else { return XCTFail("no hello") }
        XCTAssertNil(h2.tunnelKey)
        await phone.closeAll()
        try await task.value
        try await second.value
    }
}
