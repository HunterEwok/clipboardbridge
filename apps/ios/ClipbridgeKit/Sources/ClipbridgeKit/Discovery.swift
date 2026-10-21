// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// A Linux member found by mDNS browsing (docs/protocol.md, section 3): its
/// device ID, the first label of its service instance, and what its TXT
/// record says.
public struct FoundMember: Hashable, Sendable {
    public var device: String
    /// The group tag (`g`); nil when the TXT record has none.
    public var group: String?
    /// Whether a computer pairing window is open (`p=1`).
    public var pairing: Bool

    public init(device: String, group: String?, pairing: Bool = false) {
        (self.device, self.group, self.pairing) = (device, group, pairing)
    }
}

public enum Discovery {
    /// The DNS-SD service type the Linux members publish.
    public static let serviceType = "_clipbridge._tcp"

    /// Reads a found service: the instance name must be a device ID; the TXT
    /// strings are "key=value", keys matched without regard to case, the
    /// value what follows the first "=". Unknown keys are ignored.
    public static func member(instance: String, txt: [String]) -> FoundMember? {
        guard GroupCertificates.isDeviceID(instance) else { return nil }
        var fields: [String: String] = [:]
        for s in txt {
            let (k, v) = s.firstIndex(of: "=").map { (String(s[..<$0]), String(s[s.index(after: $0)...])) } ?? (s, "")
            let key = k.lowercased()
            if fields[key] == nil { fields[key] = v }
        }
        return FoundMember(device: instance, group: fields["g"], pairing: fields["p"] == "1")
    }

    /// The same from a TXT record already split into keys and values, as
    /// Network.framework gives it.
    public static func member(instance: String, txt: [String: String]) -> FoundMember? {
        member(instance: instance, txt: txt.map { "\($0.key)=\($0.value)" })
    }
}

/// Keeps one connection to every found member of the phone's group: it
/// dials each, runs the connection on the node, and dials again after it
/// ends, waiting 1 s, doubling to 30 s; a connection that lasted more than
/// 30 s resets the wait (docs/protocol.md, section 4, "Who dials whom").
/// A member that is no longer found is not dialed again.
public actor MemberDialer {
    public typealias Dial = @Sendable (FoundMember) async throws -> ClosableTransport

    let node: MemberNode
    let group: String
    let dial: Dial
    let firstWait: TimeInterval
    let maxWait: TimeInterval
    private var found: Set<String> = []
    private var tasks: [String: Task<Void, Never>] = [:]
    private var stopped = false

    /// dial connects to a found member and finishes the TLS handshake,
    /// checking that the peer is that device of this group.
    public init(node: MemberNode, group: String, firstWait: TimeInterval = 1, maxWait: TimeInterval = 30, dial: @escaping Dial) {
        (self.node, self.group, self.dial, self.firstWait, self.maxWait) = (node, group, dial, firstWait, maxWait)
    }

    /// The members being dialed or connected.
    public var dialing: Set<String> { Set(tasks.keys) }

    /// Takes the members browsing finds now. Those of another group are
    /// ignored.
    public func update(_ members: Set<FoundMember>) {
        guard !stopped else { return }
        found = Set(members.filter { $0.group == group }.map(\.device))
        for d in found where tasks[d] == nil {
            let m = FoundMember(device: d, group: group)
            tasks[d] = Task { await self.keep(m) }
        }
    }

    /// Stops dialing; the node's connections stay until closed.
    public func stop() {
        stopped = true
        for t in tasks.values { t.cancel() }
        tasks = [:]
    }

    private func stillWanted(_ d: String) -> Bool { !stopped && found.contains(d) }

    private func done(_ d: String) { tasks[d] = nil }

    private func keep(_ m: FoundMember) async {
        var wait = firstWait
        while stillWanted(m.device), !Task.isCancelled {
            let started = ProcessInfo.processInfo.systemUptime
            if let t = try? await dial(m) {
                try? await node.serve(t)
                if ProcessInfo.processInfo.systemUptime - started > maxWait { wait = firstWait }
            }
            guard stillWanted(m.device), !Task.isCancelled else { break }
            try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
            wait = min(wait * 2, maxWait)
        }
        done(m.device)
    }
}
