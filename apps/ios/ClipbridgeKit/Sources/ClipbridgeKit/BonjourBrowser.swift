// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Network)
import Foundation
import Network
import Security

/// Browses for the Linux members with Network.framework: the services of
/// type _clipbridge._tcp in local., with their TXT records. The app's
/// Info.plist must list the type under NSBonjourServices and explain the use
/// in NSLocalNetworkUsageDescription.
public final class BonjourBrowser: @unchecked Sendable {
    let browser: NWBrowser
    let queue = DispatchQueue(label: "clipbridge.browse")
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
    /// with the member ALPN protocol and this phone's identity, accepting
    /// only that device's certificate from the group CA.
    public func dialer(identity: SecIdentity, groupCA: Data) -> MemberDialer.Dial {
        { [weak self] m in
            guard let ep = self?.endpoint(of: m.device) else { throw TLSTransport.Failure.notReady("not found") }
            let t = TLSTransport(endpoint: ep, alpn: Member.alpn, identity: identity) { leaf in
                (try? GroupCertificates.verifyMember(leaf, groupCA: groupCA, now: Date())) == m.device
            }
            try await t.start()
            return t
        }
    }
}
#endif
