// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Network)
import Foundation
import Network
import Security

/// Browses for the Linux members with Network.framework: the services of
/// type _clipboardbridge._tcp in local., with their TXT records. The app's
/// Info.plist must list the type under NSBonjourServices and explain the use
/// in NSLocalNetworkUsageDescription.
public final class BonjourBrowser: @unchecked Sendable {
    let browser: NWBrowser
    let queue = DispatchQueue(label: "clipboardbridge.browse")
    private let lock = NSLock()
    private var endpoints: [String: NWEndpoint] = [:]

    /// onChange gets the members found now, after every change.
    public init(onChange: @escaping @Sendable (Set<FoundMember>) -> Void) {
        let params = NWParameters()
        params.includePeerToPeer = false
        browser = NWBrowser(for: .bonjourWithTXTRecord(type: Discovery.serviceType, domain: "local."), using: params)
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self else { return }
            var found = Set<FoundMember>()
            var eps: [String: NWEndpoint] = [:]
            for r in results {
                guard case let .service(name, _, _, _) = r.endpoint else { continue }
                var txt: [String: String] = [:]
                if case let .bonjour(record) = r.metadata { txt = record.dictionary }
                if let m = Discovery.member(instance: name, txt: txt) {
                    found.insert(m)
                    eps[m.device] = r.endpoint
                }
            }
            self.lock.withLock { self.endpoints = eps }
            onChange(found)
        }
    }

    public func start() { browser.start(queue: queue) }
    public func stop() { browser.cancel() }

    /// The endpoint of a found member, to dial.
    public func endpoint(of device: String) -> NWEndpoint? { lock.withLock { endpoints[device] } }

    /// A dial function for MemberDialer: TLS 1.3 to the member's endpoint
    /// with the member ALPN protocol and this phone's identity, followed by
    /// chain (the admin CA that issued its certificate, if one did),
    /// accepting only that device's certificate from one of roots, the
    /// group's roots (docs/protocol.md, section 10, "Roots"). A member
    /// browsing does not find is dialed at the addresses known gives for
    /// it, one after another.
    public func dialer(identity: SecIdentity, chain: [Data] = [], roots: [Data],
                       known: @escaping @Sendable (String) -> [String] = { _ in [] }) -> MemberDialer.Dial {
        { [weak self] m in
            let eps = self?.endpoint(of: m.device).map { [$0] } ?? JoinCode.ordered(known(m.device)).compactMap { a -> NWEndpoint? in
                guard let (host, port) = JoinCode.split(a), let p = NWEndpoint.Port(rawValue: port) else { return nil }
                return .hostPort(host: NWEndpoint.Host(host), port: p)
            }
            var failure: Error = TLSTransport.Failure.notReady("not found")
            for ep in eps {
                let t = TLSTransport(endpoint: ep, alpn: Member.alpn, identity: identity, chain: chain) { chain in
                    (try? GroupCertificates.verifyMember(chain: chain, roots: roots, now: Date())) == m.device
                }
                do {
                    try await t.start()
                    return t
                } catch {
                    t.close()
                    failure = error
                }
            }
            throw failure
        }
    }
}
#endif
