// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Network)
import Foundation
import Network
import Security

/// A TLS 1.3 connection with Network.framework that carries frames: pairing
/// with a listening computer now, member connections later.
public final class TLSTransport: FrameTransport, @unchecked Sendable {
    public enum Failure: Error { case notReady(String), closed, peerRejected }

    let connection: NWConnection
    let queue = DispatchQueue(label: "clipbridge.tls")
    /// The peer's leaf certificate, DER, once the handshake is done.
    public private(set) var peerCertificate: Data?

    /// Dials host:port with TLS 1.3 and the ALPN protocol, presenting
    /// identity. verify gets the peer's leaf certificate (DER) and decides
    /// whether to trust it: for pairing, against the QR code's fingerprint.
    public init(host: String, port: UInt16, alpn: String, identity: SecIdentity, verify: @escaping @Sendable (Data) -> Bool) {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(sec, alpn)
        if let id = sec_identity_create(identity) {
            sec_protocol_options_set_local_identity(sec, id)
        }
        sec_protocol_options_set_verify_block(sec, { _, trust, complete in
            let t = sec_trust_copy_ref(trust).takeRetainedValue()
            guard let chain = SecTrustCopyCertificateChain(t) as? [SecCertificate], let leaf = chain.first else {
                complete(false)
                return
            }
            complete(verify(SecCertificateCopyData(leaf) as Data))
        }, DispatchQueue(label: "clipbridge.tls.verify"))
        let params = NWParameters(tls: tls)
        connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: params)
    }

    /// Starts the connection and waits for the handshake.
    public func start() async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            var done = false
            connection.stateUpdateHandler = { [weak self] state in
                guard !done else { return }
                switch state {
                case .ready:
                    done = true
                    self?.peerCertificate = self?.leafCertificate()
                    c.resume()
                case .failed(let e), .waiting(let e):
                    done = true
                    self?.connection.cancel()
                    c.resume(throwing: Failure.notReady("\(e)"))
                case .cancelled:
                    done = true
                    c.resume(throwing: Failure.closed)
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    public func close() { connection.cancel() }

    var tlsMetadata: sec_protocol_metadata_t? {
        (connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata)?.securityProtocolMetadata
    }

    func leafCertificate() -> Data? {
        guard let meta = tlsMetadata else { return nil }
        var leaf: Data?
        sec_protocol_metadata_access_peer_certificate_chain(meta) { cert in
            if leaf == nil {
                leaf = SecCertificateCopyData(sec_certificate_copy_ref(cert).takeRetainedValue()) as Data
            }
        }
        return leaf
    }

    /// The TLS exporter's output for label with an empty context, as Go's
    /// ExportKeyingMaterial(label, nil, length) gives it.
    public func exportKeyingMaterial(label: String, length: Int) -> [UInt8]? {
        guard let meta = tlsMetadata,
              let secret = sec_protocol_metadata_create_secret(meta, label.utf8.count, label, length) else { return nil }
        return Array(secret as DispatchData)
    }

    public func write(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { e in
                if let e { c.resume(throwing: e) } else { c.resume() }
            })
        }
    }

    public func read(exactly n: Int) async throws -> Data {
        if n == 0 { return Data() }
        return try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: n, maximumLength: n) { data, _, complete, e in
                if let e {
                    c.resume(throwing: e)
                } else if let data, data.count == n {
                    c.resume(returning: data)
                } else {
                    c.resume(throwing: complete ? Failure.closed : Failure.notReady("short read"))
                }
            }
        }
    }
}
#endif
