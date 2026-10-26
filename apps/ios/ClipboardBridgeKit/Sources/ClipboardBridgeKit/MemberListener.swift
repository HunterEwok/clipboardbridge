// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Network)
import Foundation
import Network
import Security

/// Takes member connections for a node: the phone's member port while it
/// is the group's hub (docs/design.md, "The phone as the hub"), on the
/// loopback address, where cbbtun's Hub joins each connection through the
/// tunnel. It accepts a peer whose chain (leaf first) is a member's of the
/// group's roots, which trusted gives for each handshake, and serves each
/// connection in a task of its own, naming the peer by its device ID.
public final class MemberListener: @unchecked Sendable {
    private let listener: TLSListener
    private let node: MemberNode
    private let trusted: @Sendable () -> [Data]
    private let onError: @Sendable (Error) -> Void
    private var task: Task<Void, Never>?

    /// chain is what follows the identity's certificate, as TLSTransport
    /// takes it; on the home network (loopback false) service publishes it
    /// by Bonjour, as TLSListener does; onError gets why a connection
    /// failed, for the log.
    public init(node: MemberNode, identity: SecIdentity, chain: [Data] = [], trusted: @escaping @Sendable () -> [Data],
                port: UInt16 = 0, loopback: Bool = true, service: (name: String, txt: [String: String])? = nil,
                onError: @escaping @Sendable (Error) -> Void = { _ in }) throws {
        (self.node, self.trusted, self.onError) = (node, trusted, onError)
        listener = try TLSListener(port: port, alpn: Member.alpn, identity: identity, chain: chain, loopback: loopback, service: service) {
            Self.peer($0, trusted()) != nil
        }
    }

    private static func peer(_ chain: [Data], _ roots: [Data]) -> String? {
        try? GroupCertificates.verifyMember(chain: chain, roots: roots, now: Date())
    }

    /// Starts listening and returns the port, which cbbtun's StartHub
    /// takes.
    public func start() async throws -> UInt16 {
        let port = try await listener.start()
        let (listener, node, trusted, onError) = (listener, node, trusted, onError)
        task = Task {
            while let t = await listener.next() {
                Task {
                    do {
                        try await t.start()
                        guard let id = Self.peer(t.peerChain, trusted()) else { return t.close() }
                        try await node.serve(t, peer: id)
                    } catch {
                        t.close()
                        onError(error)
                    }
                }
            }
        }
        return port
    }

    /// Stops listening; the connections it took go on until the node
    /// closes them.
    public func stop() {
        listener.stop()
        task?.cancel()
    }
}
#endif
