// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation
import XCTest
@testable import ClipboardBridgeKit

/// Sync away from home on the phone: the kept state and the loop that
/// reaches the hub through the tunnel while it is away.
final class AwayFromHomeTests: XCTestCase {
    let hub = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    let offer = Member.TunnelOffer(hubKey: Data(repeating: 2, count: 32), psk: Data(repeating: 3, count: 32),
                                   endpoints: ["203.0.113.7:8764", "[2001:db8::7]:8764"])

    func testStateRoundTrips() throws {
        let key = Data(repeating: 1, count: 32)
        XCTAssertEqual(AwayState.decode(try AwayState(key: key).encoded()), AwayState(key: key))
        let on = AwayState(key: key, hub: hub, offer: offer)
        XCTAssertEqual(AwayState.decode(try on.encoded()), on)
        // A short key, a bad offer and an offer without its hub are not states.
        XCTAssertNil(AwayState.decode(try AwayState(key: Data(count: 31)).encoded()))
        XCTAssertNil(AwayState.decode(try AwayState(key: key, hub: hub,
                                                    offer: Member.TunnelOffer(hubKey: Data(count: 31), psk: Data(count: 32))).encoded()))
        XCTAssertNil(AwayState.decode(try AwayState(key: key, offer: offer).encoded()))
        XCTAssertNil(AwayState.decode(Data("{".utf8)))
    }

    final class FakeTunnel: OpenTunnel, @unchecked Sendable {
        let port: UInt16
        let first: String
        private let lock = NSLock()
        private var _endpoints: [String]
        private var _closed = false
        init(port: UInt16, endpoint: String) { (self.port, self.first, self._endpoints) = (port, endpoint, [endpoint]) }
        var endpoints: [String] { lock.withLock { _endpoints } }
        var closed: Bool { lock.withLock { _closed } }
        func setEndpoint(_ endpoint: String) throws { lock.withLock { _endpoints.append(endpoint) } }
        func close() { lock.withLock { _closed = true } }
    }

    final class FakeTunnels: Tunnels, @unchecked Sendable {
        private let lock = NSLock()
        private var _started: [FakeTunnel] = []
        var started: [FakeTunnel] { lock.withLock { _started } }
        func newKey() throws -> Data { Data(repeating: 7, count: 32) }
        func publicKey(_ privateKey: Data) throws -> Data { Data(privateKey.map { $0 &+ 1 }) }
        func start(privateKey: Data, psk: Data, hubKey: Data, device: String, hub: String, endpoint: String) throws -> OpenTunnel {
            lock.withLock {
                let t = FakeTunnel(port: UInt16(40_000 + _started.count), endpoint: endpoint)
                _started.append(t)
                return t
            }
        }
    }

    /// Shared values the fakes set and the test reads.
    final class Box<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var value: T
        init(_ v: T) { value = v }
        var current: T { lock.withLock { value } }
        func set(_ v: T) { lock.withLock { value = v } }
        func update(_ f: (inout T) -> Void) { lock.withLock { f(&value) } }
    }

    private func eventually(_ what: String, _ check: @Sendable () async -> Bool) async throws {
        let deadline = Date().addingTimeInterval(5)
        while !(await check()) {
            if Date() > deadline { return XCTFail(what) }
            try await Task.sleep(for: .milliseconds(5))
        }
    }

    private static let short = (first: Duration.milliseconds(10), max: Duration.milliseconds(20), home: Duration.milliseconds(10))

    func testReachesTheHubOnlyWhileItIsAway() async throws {
        let tunnels = FakeTunnels()
        let saved = Box<AwayState?>(nil)
        let home = Box(false)
        let answers = Box(false)
        let dialed = Box<[UInt16]>([])
        let served = Box(0)
        let release = Box(0)
        let hub = hub
        let a = AwayFromHome(
            device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tunnels: tunnels, state: nil,
            save: { saved.set($0) },
            atHome: { _ in home.current },
            dial: { port, h in
                XCTAssertEqual(h, hub)
                dialed.update { $0.append(port) }
                guard answers.current else { throw POSIXError(.ECONNREFUSED) }
                return Pipe()
            },
            serve: { _, _ in
                let mine = served.current
                served.set(mine + 1)
                // Runs until the test lets it end, as a connection does.
                while release.current <= mine { try await Task.sleep(for: .milliseconds(2)) }
            },
            firstWait: Self.short.first, maxWait: Self.short.max, homeCheck: Self.short.home)
        await a.start()

        // Off: no key for the hellos, no tunnel.
        let isOn = await a.isOn
        let none = await a.publicKey
        XCTAssertFalse(isOn)
        XCTAssertNil(none)
        try await eventually("off") { await a.status == .off }

        try await a.turnOn()
        let key = await a.publicKey
        XCTAssertEqual(key, Data(repeating: 8, count: 32))
        XCTAssertNotNil(saved.current)
        try await eventually("waiting for the hub") { await a.status == .waitingForHub }
        XCTAssertTrue(tunnels.started.isEmpty)

        // The hub's answer, from a peer the node named: away, the tunnel starts on its first endpoint.
        await a.keep(from: nil, offer: offer)
        await a.keep(from: hub, offer: offer)
        XCTAssertEqual(saved.current?.hub, hub)
        try await eventually("a tunnel") { tunnels.started.count == 1 }
        let t = tunnels.started[0]
        XCTAssertEqual(t.first, offer.endpoints[0])
        // No answer: the next endpoint, on the same tunnel.
        let second = offer.endpoints[1]
        try await eventually("the next endpoint") { t.endpoints.contains(second) }
        XCTAssertEqual(dialed.current.first, t.port)
        XCTAssertEqual(tunnels.started.count, 1)

        answers.set(true)
        try await eventually("served") { served.current == 1 }
        let connected = await a.status
        XCTAssertEqual(connected, .connected)

        // At home the tunnel closes and the phone dials the hub directly.
        home.set(true)
        release.set(1)
        try await eventually("at home") { await a.status == .atHome }
        XCTAssertTrue(t.closed)

        // Away again: a new tunnel.
        home.set(false)
        try await eventually("a new tunnel served") { served.current == 2 }
        XCTAssertEqual(tunnels.started.count, 2)

        // Off: the tunnel closes and the state is forgotten.
        try await a.turnOff()
        release.set(2)
        XCTAssertTrue(tunnels.started[1].closed)
        XCTAssertNil(saved.current)
        let gone = await a.publicKey
        XCTAssertNil(gone)
        try await eventually("off again") { await a.status == .off }
        await a.stop()
    }

    func testANewOfferStartsAgain() async throws {
        let tunnels = FakeTunnels()
        let release = Box(0)
        let a = AwayFromHome(
            device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tunnels: tunnels,
            state: AwayState(key: Data(repeating: 1, count: 32), hub: hub, offer: offer), save: { _ in },
            atHome: { _ in false }, dial: { _, _ in Pipe() },
            serve: { _, _ in while release.current == 0 { try await Task.sleep(for: .milliseconds(2)) } },
            firstWait: Self.short.first, maxWait: Self.short.max, homeCheck: Self.short.home)
        await a.start()
        try await eventually("connected") { await a.status == .connected }
        let t = tunnels.started[0]
        // The same offer again changes nothing; a new one closes the tunnel and starts with it.
        await a.keep(from: hub, offer: offer)
        XCTAssertFalse(t.closed)
        await a.keep(from: hub, offer: Member.TunnelOffer(hubKey: offer.hubKey, psk: offer.psk, endpoints: ["198.51.100.9:8764"]))
        XCTAssertTrue(t.closed)
        release.set(1)
        try await eventually("a new tunnel") { tunnels.started.count == 2 }
        XCTAssertEqual(tunnels.started[1].first, "198.51.100.9:8764")
        await a.stop()
        try await eventually("stopped") { await a.status == .off }
    }
}
