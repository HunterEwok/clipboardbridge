// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// A connection that can be closed, which makes a blocked read or write
/// fail: a TLS connection in the app, a socket in tests.
public protocol ClosableTransport: FrameTransport {
    func close()
    /// The peer's leaf certificate from the TLS handshake, DER; nil when
    /// there is none.
    var peerCertificate: Data? { get }
    /// The peer's certificate chain from the TLS handshake, DER, leaf
    /// first: the leaf, then its admin CA when one issued it.
    var peerChain: [Data] { get }
}

extension ClosableTransport {
    public var peerCertificate: Data? { nil }
    public var peerChain: [Data] { peerCertificate.map { [$0] } ?? [] }
}

/// Keeps the group's signed records for a node (docs/protocol.md, section
/// 10). Its methods are called from the node's actor.
public protocol RecordStore: AnyObject, Sendable {
    /// The digest a hello carries; nil without records.
    var digest: String? { get }
    /// Every record, for a peer whose digest differs.
    var all: [Member.Record] { get }
    /// Takes records a peer sent and returns those that were new and valid.
    func add(_ records: [Member.Record]) -> [Member.Record]
    /// Why the records refuse a peer's certificate chain (leaf first), as
    /// RecordSet.refused, or nil: a removed device is dropped by its key,
    /// not only by its ID.
    func refused(chain: [Data]) -> String?
    /// Whether the peer with this verified chain may be the group's hub, as
    /// RecordSet.mayHost.
    func mayHost(_ device: String, chain: [Data]) -> Bool
}

public extension RecordStore {
    func refused(chain: [Data]) -> String? { nil }
    func mayHost(_ device: String, chain: [Data]) -> Bool { true }
}

/// The phone as a member: its sync engine and its connections to the Linux
/// members, which it dials (docs/protocol.md, section 9), and those that
/// come to it while it is the group's hub (MemberListener).
/// Each connection runs the member protocol of section 4: a hello first,
/// then events, a ping after 5 s without a write, and a close after 15 s
/// without a read.
public actor MemberNode {
    public let role: Member.Role
    public let name: String?
    /// This device's operating system, which the hellos state.
    public let os: String?
    /// This device's form, system version and version, which the hellos
    /// state too.
    public let device: Member.DeviceInfo?
    let engine: SyncEngine
    private var conns: [ObjectIdentifier: Conn] = [:]
    /// The commands sent that wait for their result, by command ID, with
    /// the connection they went on.
    private var waiting: [String: (conn: ObjectIdentifier, waiter: Waiter)] = [:]
    private let onChange: @Sendable (Member.Event) -> Void
    private let onCert: @Sendable (Data) -> Void
    private let records: RecordStore?
    private let renew: (@Sendable ([Data]) -> Renewal?)?
    private let adminCA: (@Sendable (Data) -> Data?)?
    private let onTunnel: @Sendable (String?, Member.TunnelOffer) -> Void
    private let hub: (@Sendable (String, Data, [Data]) -> Member.TunnelOffer?)?
    /// The WireGuard public key the hellos offer the group's hub (section
    /// 11); nil while sync away from home is off.
    public private(set) var tunnelKey: Data?

    /// A renewed member certificate for a peer, DER, and the admin CA that
    /// issued it; nil when a root did.
    public struct Renewal: Equatable, Sendable {
        public var cert: Data
        public var issuer: Data?
        public init(cert: Data, issuer: Data? = nil) { (self.cert, self.issuer) = (cert, issuer) }
    }

    /// onChange gets the new current event when a peer's event becomes it;
    /// onCert gets a renewed member certificate a peer sent for this phone;
    /// records keeps the group's records and exchanges them with the peers;
    /// renew, on an admin phone, gets each peer's certificate chain (leaf
    /// first) after its hello and returns a renewal when it is due, which
    /// the peer then gets in a cert message (section 2); adminCA, on the
    /// root, gets the admin key a computer's hello offers and returns the
    /// admin CA this phone issued for it, which the computer then gets in
    /// an admin message, so one that missed it gets it again; tunnelKey is
    /// the key the hellos offer the hub, and onTunnel gets each valid offer
    /// a peer sends for it, with the device ID the caller of serve named
    /// the peer by; hub, on the phone while it is the group's hub
    /// (docs/design.md, "The phone as the hub"), gets the device ID a peer
    /// was named by, the tunnel key its hello offers and its certificate
    /// chain (leaf first), and returns the offer the peer then gets in a
    /// tunnel message, or nil (PhoneHub.offer does it); a hub ignores the
    /// offers it gets.
    public init(engine: SyncEngine, name: String?, role: Member.Role = .phone, os: String? = nil, device: Member.DeviceInfo? = nil,
                records: RecordStore? = nil,
                renew: (@Sendable ([Data]) -> Renewal?)? = nil,
                adminCA: (@Sendable (Data) -> Data?)? = nil,
                tunnelKey: Data? = nil,
                hub: (@Sendable (String, Data, [Data]) -> Member.TunnelOffer?)? = nil,
                onChange: @escaping @Sendable (Member.Event) -> Void = { _ in },
                onCert: @escaping @Sendable (Data) -> Void = { _ in },
                onTunnel: @escaping @Sendable (String?, Member.TunnelOffer) -> Void = { _, _ in }) {
        (self.engine, self.name, self.role, self.records, self.renew, self.adminCA, self.onChange, self.onCert) =
            (engine, name, role, records, renew, adminCA, onChange, onCert)
        (self.tunnelKey, self.onTunnel, self.hub, self.os, self.device) = (tunnelKey, onTunnel, hub, os, device?.cleaned)
    }

    /// Replaces the tunnel key that the next connections' hellos offer;
    /// nil offers none.
    public func set(tunnelKey: Data?) { self.tunnelKey = tunnelKey }

    /// The current event with its age as of now.
    public var current: Member.Event? { engine.currentEvent }

    /// The current text while it is usable.
    public var usable: (text: String, kind: Member.Kind)? { engine.usable }

    /// The number of connections whose peer sent its hello.
    public var peers: Int { conns.values.filter { $0.peerRole != nil }.count }

    /// The device IDs of the connected members that sent their hello, where
    /// the caller of serve named them.
    public var connected: Set<String> {
        Set(conns.values.compactMap { $0.peerRole != nil ? $0.peer : nil })
    }

    /// The admin keys that the connected computers offer in their hello, by
    /// device ID, where the caller of serve named them: the computers the
    /// root can make admins (section 10, "A computer as admin").
    public var offeredAdminKeys: [String: Data] {
        var out: [String: Data] = [:]
        for c in conns.values { if let p = c.peer, let k = c.adminKey { out[p] = k } }
        return out
    }

    /// What the connected members' hellos say about their devices, their
    /// invalid fields dropped, by device ID where the caller of serve named
    /// them.
    public var devices: [String: Member.DeviceInfo] {
        var out: [String: Member.DeviceInfo] = [:]
        for c in conns.values { if let p = c.peer, let d = c.device { out[p] = d } }
        return out
    }

    /// The sync modes the connected members' hellos report, by device ID
    /// where the caller of serve named them.
    public var modes: [String: String] {
        var out: [String: String] = [:]
        for c in conns.values { if let p = c.peer, let m = c.mode { out[p] = m } }
        return out
    }

    /// Sends the connected member peer a command signed for it (section 15)
    /// and waits for its result, at most timeout seconds. It throws when
    /// peer is not connected, the connection ends first or no result comes
    /// in time.
    public func command(_ command: Member.Record, to peer: String, timeout: TimeInterval = 10) async throws -> Member.CommandResult {
        guard let id = Commands.id(of: command) else { throw Failure.refused("the command has no ID") }
        guard let found = conns.first(where: { $0.value.peer == peer && $0.value.peerRole != nil }) else {
            throw Failure.notConnected
        }
        let (cid, c) = (found.key, found.value)
        let w = Waiter()
        waiting[id] = (cid, w)
        c.enqueue(.command(command))
        let timer = Task {
            try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            w.resolve(.failure(Failure.timedOut))
        }
        defer {
            timer.cancel()
            if waiting[id]?.waiter === w { waiting[id] = nil }
        }
        return try await w.wait()
    }

    /// Sends a computer the admin CA the root issued for it.
    public func send(adminCA: Data, to peer: String) {
        for c in conns.values where c.peer == peer && c.peerRole != nil { c.enqueue(.admin(adminCA)) }
    }

    /// Sends a text this phone copied to every connected member.
    @discardableResult
    public func send(text: String, kind: Member.Kind, via: Member.Via = .phone) -> Member.Event {
        let e = engine.local(text: text, kind: kind, via: via)
        for c in conns.values { c.enqueue(.event(e)) }
        return e
    }

    /// Runs a connection whose TLS handshake is done until it ends, and
    /// closes it. It returns normally when the peer says goodbye or this
    /// side closed it (closeAll).
    public func serve(_ t: ClosableTransport, peer: String? = nil) async throws {
        let c = Conn(transport: t, peer: peer)
        let id = ObjectIdentifier(c)
        conns[id] = c
        var hello = engine.hello(name: name)
        hello.os = os
        hello.device = device
        hello.records = records?.digest
        hello.tunnelKey = tunnelKey
        c.enqueue(.hello(role, hello))
        let writer = Task { await c.runWriter() }
        let watchdog = Task { await c.runWatchdog() }
        defer {
            conns[id] = nil
            for w in waiting.values where w.conn == id { w.waiter.resolve(.failure(Failure.closed)) }
            c.finish()
            writer.cancel()
            watchdog.cancel()
            t.close()
        }
        var first = true
        while true {
            let m: Member.Message
            do {
                m = try await c.readMessage()
            } catch where c.closing {
                return // closed on this side; nothing more counts
            }
            if first {
                guard case let .hello(peerRole, h) = m else { throw Failure.noHello }
                first = false
                if let why = records?.refused(chain: t.peerChain) { throw Failure.refused(why) }
                c.adminKey = h.adminKey
                c.device = h.device?.cleaned
                c.mode = h.mode
                c.peerRole = peerRole
                apply(try engine.reconcile(h), from: id)
                if let store = records, let mine = store.digest, mine != h.records {
                    c.enqueue(.records(store.all))
                }
                if let renew, !t.peerChain.isEmpty, let renewed = renew(t.peerChain) {
                    c.enqueue(.cert(renewed.cert, issuer: renewed.issuer))
                }
                if let key = h.adminKey, let ca = adminCA?(key) {
                    c.enqueue(.admin(ca))
                }
                if let hub, let p = c.peer, let key = h.tunnelKey, !t.peerChain.isEmpty, let offer = hub(p, key, t.peerChain) {
                    c.enqueue(.tunnel(offer))
                }
                continue
            }
            switch m {
            case let .event(e?):
                apply(engine.received(e), from: id)
            case let .cert(der, _):
                onCert(der)
            // Only the root or an admin, by the records and its key.
            case let .tunnel(o?) where o.isValid && hub == nil:
                if let p = c.peer, records?.mayHost(p, chain: t.peerChain) != false { onTunnel(p, o) }
            case let .records(rs):
                if let store = records, !rs.isEmpty {
                    let fresh = store.add(rs)
                    if !fresh.isEmpty {
                        sendRecords(fresh, except: id)
                        dropRefused()
                    }
                }
            // A phone has no sync mode yet and takes no commands.
            case let .command(r):
                c.enqueue(.result(Member.CommandResult(id: Commands.id(of: r) ?? "", status: "refused",
                                                       reason: "this device takes no commands")))
            case let .result(r):
                if let w = waiting[r.id], w.conn == id { w.waiter.resolve(.success(r)) }
            case .bye:
                return
            default:
                break // a ping, an event that did not decode, or a newer type
            }
        }
    }

    /// Says goodbye on every connection and closes it.
    public func closeAll() {
        for c in conns.values { c.goodbye() }
    }

    /// Closes the connections to a device, for example one just removed.
    public func close(peer: String) {
        for c in conns.values where c.peer == peer { c.goodbye() }
    }

    /// Sends records made on this phone to every connected member.
    public func sendRecords(_ rs: [Member.Record]) {
        sendRecords(rs, except: nil)
        dropRefused()
    }

    /// Closes the connections whose peers the records now refuse, as a
    /// device just removed.
    private func dropRefused() {
        guard let store = records else { return }
        for c in conns.values where store.refused(chain: c.transport.peerChain) != nil { c.goodbye() }
    }

    private func sendRecords(_ rs: [Member.Record], except: ObjectIdentifier?) {
        for (id, c) in conns where id != except && c.peerRole != nil { c.enqueue(.records(rs)) }
    }

    private func apply(_ r: SyncEngine.Result, from: ObjectIdentifier) {
        if let e = r.forward {
            for (id, c) in conns where id != from { c.enqueue(.event(e)) }
        }
        if r.changed, let cur = engine.currentEvent { onChange(cur) }
    }

    public enum Failure: Error { case noHello, timedOut, refused(String), notConnected, closed }

    /// A command's result, which comes from the peer, a timeout or the end
    /// of the connection, whichever is first.
    final class Waiter: @unchecked Sendable {
        private let lock = NSLock()
        private var got: Swift.Result<Member.CommandResult, Error>?
        private var waiter: CheckedContinuation<Member.CommandResult, Error>?

        func resolve(_ r: Swift.Result<Member.CommandResult, Error>) {
            let w: CheckedContinuation<Member.CommandResult, Error>? = lock.withLock {
                guard got == nil else { return nil }
                got = r
                defer { waiter = nil }
                return waiter
            }
            w?.resume(with: r)
        }

        func wait() async throws -> Member.CommandResult {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Member.CommandResult, Error>) in
                let r: Swift.Result<Member.CommandResult, Error>? = lock.withLock {
                    if let got { return got }
                    waiter = c
                    return nil
                }
                if let r { c.resume(with: r) }
            }
        }
    }

    /// One connection: a queue the writer drains, and the times of the
    /// last read and write for the ping and the timeout.
    final class Conn: @unchecked Sendable {
        let transport: ClosableTransport
        /// The peer's device ID, when the dialer knows it.
        let peer: String?
        private let lock = NSLock()
        private var queue: [Member.Message] = []
        private var waiter: CheckedContinuation<Void, Never>?
        private var done = false
        private var sayBye = false
        private var lastRead = ProcessInfo.processInfo.systemUptime
        private var lastWrite = ProcessInfo.processInfo.systemUptime
        var peerRole: Member.Role? {
            get { lock.withLock { _peerRole } }
            set { lock.withLock { _peerRole = newValue } }
        }
        private var _peerRole: Member.Role?
        /// The admin key the peer's hello offered.
        var adminKey: Data? {
            get { lock.withLock { _adminKey } }
            set { lock.withLock { _adminKey = newValue } }
        }
        private var _adminKey: Data?
        /// What the peer's hello says about its device.
        var device: Member.DeviceInfo? {
            get { lock.withLock { _device } }
            set { lock.withLock { _device = newValue } }
        }
        private var _device: Member.DeviceInfo?
        /// The sync mode the peer's hello reports.
        var mode: String? {
            get { lock.withLock { _mode } }
            set { lock.withLock { _mode = newValue } }
        }
        private var _mode: String?

        init(transport: ClosableTransport, peer: String?) { (self.transport, self.peer) = (transport, peer) }

        func enqueue(_ m: Member.Message) {
            let w: CheckedContinuation<Void, Never>? = lock.withLock {
                guard !done else { return nil }
                queue.append(m)
                defer { waiter = nil }
                return waiter
            }
            w?.resume()
        }

        /// Whether this side ended the connection.
        var closing: Bool { lock.withLock { sayBye } }

        /// Ends the writer, after a goodbye.
        func goodbye() {
            lock.withLock { sayBye = true }
            finish()
        }

        func finish() {
            let w: CheckedContinuation<Void, Never>? = lock.withLock {
                done = true
                defer { waiter = nil }
                return waiter
            }
            w?.resume()
        }

        private func next() async -> Member.Message? {
            while true {
                let (m, isDone): (Member.Message?, Bool) = lock.withLock {
                    if !queue.isEmpty { return (queue.removeFirst(), false) }
                    return (nil, done)
                }
                if let m { return m }
                if isDone { return nil }
                await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                    let ready = lock.withLock {
                        if !queue.isEmpty || done { return true }
                        waiter = c
                        return false
                    }
                    if ready { c.resume() }
                }
            }
        }

        func runWriter() async {
            while let m = await next() {
                do {
                    try await transport.write(Member.encode(m))
                    lock.withLock { lastWrite = ProcessInfo.processInfo.systemUptime }
                } catch {
                    transport.close()
                    return
                }
            }
            if lock.withLock({ sayBye }) {
                try? await transport.write(Member.encode(.bye))
                transport.close()
            }
        }

        /// Sends a ping after a quiet write side, and closes a connection
        /// silent for the timeout.
        func runWatchdog() async {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 500_000_000)
                let now = ProcessInfo.processInfo.systemUptime
                let (r, w) = lock.withLock { (lastRead, lastWrite) }
                if now - r > Member.timeout {
                    transport.close()
                    return
                }
                if now - w >= Member.pingEvery {
                    lock.withLock { lastWrite = now } // one ping per quiet spell
                    enqueue(.ping)
                }
            }
        }

        func readMessage() async throws -> Member.Message {
            let n = try Member.length(header: try await transport.read(exactly: 4))
            let body = try await transport.read(exactly: n)
            lock.withLock { lastRead = ProcessInfo.processInfo.systemUptime }
            return try Member.decode(body: body)
        }
    }
}
