// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// A connection that can be closed, which makes a blocked read or write
/// fail: a TLS connection in the app, a socket in tests.
public protocol ClosableTransport: FrameTransport {
    func close()
}

/// The phone as a member: its sync engine and its connections to the Linux
/// members, which it dials (it never listens; docs/protocol.md, section 9).
/// Each connection runs the member protocol of section 4: a hello first,
/// then events, a ping after 5 s without a write, and a close after 15 s
/// without a read.
public actor MemberNode {
    public let role: Member.Role
    public let name: String?
    let engine: SyncEngine
    private var conns: [ObjectIdentifier: Conn] = [:]
    private let onChange: @Sendable (Member.Event) -> Void
    private let onCert: @Sendable (Data) -> Void

    /// onChange gets the new current event when a peer's event becomes it;
    /// onCert gets a renewed member certificate a peer sent for this phone.
    public init(engine: SyncEngine, name: String?, role: Member.Role = .phone,
                onChange: @escaping @Sendable (Member.Event) -> Void = { _ in },
                onCert: @escaping @Sendable (Data) -> Void = { _ in }) {
        (self.engine, self.name, self.role, self.onChange, self.onCert) = (engine, name, role, onChange, onCert)
    }

    /// The current event with its age as of now.
    public var current: Member.Event? { engine.currentEvent }

    /// The current text while it is usable.
    public var usable: (text: String, kind: Member.Kind)? { engine.usable }

    /// The number of connections whose peer sent its hello.
    public var peers: Int { conns.values.filter { $0.peerRole != nil }.count }

    /// Sends a text this phone copied to every connected member.
    @discardableResult
    public func send(text: String, kind: Member.Kind, via: Member.Via = .iphone) -> Member.Event {
        let e = engine.local(text: text, kind: kind, via: via)
        for c in conns.values { c.enqueue(.event(e)) }
        return e
    }

    /// Runs a connection whose TLS handshake is done until it ends, and
    /// closes it. It returns normally when the peer says goodbye or this
    /// side closed it (closeAll).
    public func serve(_ t: ClosableTransport) async throws {
        let c = Conn(transport: t)
        let id = ObjectIdentifier(c)
        conns[id] = c
        c.enqueue(.hello(role, engine.hello(name: name)))
        let writer = Task { await c.runWriter() }
        let watchdog = Task { await c.runWatchdog() }
        defer {
            conns[id] = nil
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
                c.peerRole = peerRole
                apply(try engine.reconcile(h), from: id)
                continue
            }
            switch m {
            case let .event(e?):
                apply(engine.received(e), from: id)
            case let .cert(der):
                onCert(der)
            case .bye:
                return
            default:
                break // a ping, records, an event that did not decode, or a newer type
            }
        }
    }

    /// Says goodbye on every connection and closes it.
    public func closeAll() {
        for c in conns.values { c.goodbye() }
    }

    private func apply(_ r: SyncEngine.Result, from: ObjectIdentifier) {
        if let e = r.forward {
            for (id, c) in conns where id != from { c.enqueue(.event(e)) }
        }
        if r.changed, let cur = engine.currentEvent { onChange(cur) }
    }

    public enum Failure: Error { case noHello, timedOut }

    /// One connection: a queue the writer drains, and the times of the
    /// last read and write for the ping and the timeout.
    final class Conn: @unchecked Sendable {
        let transport: ClosableTransport
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

        init(transport: ClosableTransport) { self.transport = transport }

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
