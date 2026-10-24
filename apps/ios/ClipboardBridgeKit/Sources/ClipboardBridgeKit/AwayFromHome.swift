// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// What sync away from home keeps on the phone (docs/protocol.md, section
/// 11): its WireGuard private key, made on the phone, and the last offer of
/// the group's hub with the hub's device ID.
public struct AwayState: Codable, Equatable, Sendable {
    public var key: Data
    public var hub: String?
    public var offer: Member.TunnelOffer?

    public init(key: Data, hub: String? = nil, offer: Member.TunnelOffer? = nil) {
        (self.key, self.hub, self.offer) = (key, hub, offer)
    }

    public func encoded() throws -> Data { try JSONEncoder().encode(self) }

    /// The state in data, or nil when it is not one this version wrote.
    public static func decode(_ data: Data) -> AwayState? {
        guard let s = try? JSONDecoder().decode(AwayState.self, from: data), s.key.count == 32 else { return nil }
        if let o = s.offer, !o.isValid || s.hub == nil { return nil }
        return s
    }
}

/// A running tunnel to the hub: a loopback port that leads to the hub's
/// member port.
public protocol OpenTunnel: AnyObject, Sendable {
    var port: UInt16 { get }
    func setEndpoint(_ endpoint: String) throws
    func close()
}

/// Makes keys and tunnels; the app's come from mobile/cbbtun, the tests'
/// from a fake.
public protocol Tunnels: Sendable {
    func newKey() throws -> Data
    func publicKey(_ privateKey: Data) throws -> Data
    /// Starts a tunnel; obfuscation is the offer's settings as JSON, "" for
    /// plain WireGuard, and vless its way over VLESS as JSON, "" without it.
    func start(privateKey: Data, psk: Data, hubKey: Data, device: String, hub: String, endpoint: String,
               obfuscation: String, vless: String) throws -> OpenTunnel
}

/// Sync away from home on this phone: off until the user turns it on. Then
/// the hellos offer the phone's WireGuard key, the hub's answer is kept, and
/// while the hub is not on the home network the phone reaches it through
/// the tunnel, in the app's own process, with the same member TLS as at
/// home (docs/design.md, "Sync away from home"). It fails closed: without a
/// tunnel there is no connection.
public actor AwayFromHome {
    /// What the screens show.
    public enum Status: Sendable { case off, waitingForHub, atHome, connecting, connected }

    public typealias Dial = @Sendable (_ port: UInt16, _ hub: String) async throws -> ClosableTransport
    public typealias Serve = @Sendable (ClosableTransport, _ hub: String) async throws -> Void

    private let device: String
    private let tunnels: Tunnels
    private let save: @Sendable (AwayState?) throws -> Void
    private let atHome: @Sendable (String) async -> Bool
    private let dial: Dial
    private let serve: Serve
    private let mayHost: @Sendable (String) -> Bool
    private let log: @Sendable (String, Error) -> Void
    private let firstWait: Duration
    private let maxWait: Duration
    private let homeCheck: Duration

    private var state: AwayState?
    private var tunnel: OpenTunnel?
    private var runner: Task<Void, Never>?
    private var nap: Task<Void, Never>?

    public private(set) var status = Status.off
    public private(set) var lastError: Error?

    /// state is what load read; save keeps each change, nil when it is
    /// turned off. atHome tells whether the hub is found on the home
    /// network, where it is dialed directly; dial reaches the hub's member
    /// TLS through the loopback port, checking that the peer is the hub;
    /// serve runs a connection until it ends; mayHost tells whether a device
    /// may be the hub: the group's root or an admin (RecordSet.mayHost).
    public init(device: String, tunnels: Tunnels, state: AwayState?, save: @escaping @Sendable (AwayState?) throws -> Void,
                atHome: @escaping @Sendable (String) async -> Bool, dial: @escaping Dial, serve: @escaping Serve,
                mayHost: @escaping @Sendable (String) -> Bool,
                log: @escaping @Sendable (String, Error) -> Void = { _, _ in },
                firstWait: Duration = .seconds(1), maxWait: Duration = .seconds(30), homeCheck: Duration = .seconds(5)) {
        (self.device, self.tunnels, self.state, self.save) = (device, tunnels, state, save)
        (self.atHome, self.dial, self.serve, self.log, self.mayHost) = (atHome, dial, serve, log, mayHost)
        (self.firstWait, self.maxWait, self.homeCheck) = (firstWait, maxWait, homeCheck)
    }

    public var isOn: Bool { state != nil }

    /// The public key the hellos offer the hub; nil while it is off.
    public var publicKey: Data? {
        guard let k = state?.key else { return nil }
        return try? tunnels.publicKey(k)
    }

    /// Turns it on with a new key; the hub's offer comes at home, on the
    /// next connection to it.
    public func turnOn() throws {
        let s = AwayState(key: try tunnels.newKey())
        try save(s)
        state = s
        poke()
    }

    /// Turns it off: forgets the key and the offer and closes the tunnel.
    public func turnOff() throws {
        try save(nil)
        state = nil
        closeTunnel()
        poke()
    }

    /// Keeps the offer a peer, the group's hub, sent for this phone's key.
    /// Only the group's root or an admin may be the hub, and once a hub is
    /// kept, offers from another device are ignored: the hub changes only
    /// when the user turns sync away from home off and on again.
    public func keep(from: String?, offer: Member.TunnelOffer) {
        guard let from, offer.isValid, var s = state, s.hub == nil || s.hub == from, s.hub != from || s.offer != offer,
              mayHost(from) else { return }
        s.hub = from
        s.offer = offer
        state = s
        // A new preshared key or new endpoints: start again with them.
        closeTunnel()
        poke()
        do { try save(s) } catch { log("cannot keep the hub's offer", error) }
    }

    /// Starts the loop that reaches the hub through the tunnel while it is
    /// away.
    public func start() {
        guard runner == nil else { return }
        runner = Task { await self.run() }
    }

    public func stop() {
        runner?.cancel()
        runner = nil
        closeTunnel()
        poke()
    }

    private func closeTunnel() {
        tunnel?.close()
        tunnel = nil
    }

    private func run() async {
        var wait = firstWait
        var endpoint = 0
        while !Task.isCancelled {
            guard let s = state else {
                status = .off
                await idle(nil)
                continue
            }
            guard let hub = s.hub, let offer = s.offer, !offer.endpoints.isEmpty else {
                status = .waitingForHub
                await idle(nil)
                continue
            }
            let home = await atHome(hub)
            guard state == s, !Task.isCancelled else { continue }
            if home {
                status = .atHome
                closeTunnel()
                wait = firstWait
                await idle(homeCheck)
                continue
            }
            status = .connecting
            let t: OpenTunnel
            if let open = tunnel {
                t = open
            } else {
                do {
                    t = try tunnels.start(privateKey: s.key, psk: offer.psk, hubKey: offer.hubKey, device: device, hub: hub,
                                          endpoint: offer.endpoints[endpoint % offer.endpoints.count],
                                          obfuscation: try offer.obfuscation?.jsonText() ?? "",
                                          vless: try offer.vless?.jsonText() ?? "")
                } catch {
                    fail("the tunnel to the hub could not start", error)
                    wait = await backoff(wait)
                    continue
                }
                tunnel = t
            }
            let started = ContinuousClock.now
            do {
                let conn = try await dial(t.port, hub)
                status = .connected
                lastError = nil
                try await serve(conn, hub)
                if ContinuousClock.now - started > maxWait { wait = firstWait }
            } catch {
                fail("the hub does not answer through the tunnel", error)
                // The next of the hub's endpoints, in turn.
                endpoint += 1
                try? t.setEndpoint(offer.endpoints[endpoint % offer.endpoints.count])
            }
            if Task.isCancelled { break }
            wait = await backoff(wait)
        }
        status = .off
    }

    private func fail(_ what: String, _ error: Error) {
        lastError = error
        log(what, error)
    }

    private func backoff(_ wait: Duration) async -> Duration {
        await idle(wait)
        return min(wait * 2, maxWait)
    }

    /// Waits for d, or until something changes; nil waits for a change only.
    private func idle(_ d: Duration?) async {
        guard !Task.isCancelled else { return }
        let t = Task { _ = try? await Task.sleep(for: d ?? .seconds(86_400)) }
        nap = t
        await t.value
        nap = nil
    }

    /// Ends the current wait, after a change.
    private func poke() { nap?.cancel() }
}
