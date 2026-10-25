// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The phone as the group's hub while its app is open (docs/design.md, "The
/// phone as the hub", D-64): the clients it admits by the tunnel keys their
/// hellos offer, and the offers it answers with (docs/protocol.md, section
/// 11), by the same rules as a computer's hub. The tunnel itself is
/// cbbtun's Hub, which takes clientsJSON. It is thread-safe.
public final class PhoneHub: @unchecked Sendable {
    /// A client: its device ID, the tunnel key it offered and the preshared
    /// key the hub gave it.
    public struct Client: Codable, Equatable, Sendable {
        public var device: String
        public var key: Data
        public var psk: Data

        public init(device: String, key: Data, psk: Data) { (self.device, self.key, self.psk) = (device, key, psk) }
    }

    public enum Refused: Error, Equatable { case badDevice, badKey, keyOfAnother(String), tooManyClients }

    /// The most clients a hub keeps, as a computer's hub.
    public static let maxClients = 256

    /// The hub's WireGuard public key.
    public let publicKey: Data
    private let lock = NSLock()
    private var list: [Client]
    private var link = Link()

    /// What the offers carry besides the keys.
    struct Link {
        var endpoints: [String] = []
        var obfuscation: Member.Obfuscation?
        var vlessOnly = false
        var vless: Member.VLESS?
    }

    public init(publicKey: Data, clients: [Client] = []) {
        precondition(publicKey.count == 32, "a WireGuard key is 32 bytes")
        (self.publicKey, list) = (publicKey, clients)
    }

    public var clients: [Client] { lock.withLock { list } }

    /// Where the clients reach the hub away from home, "ip:port": the
    /// forwarder's endpoint, which the offers carry.
    public var endpoints: [String] {
        get { lock.withLock { link.endpoints } }
        set { lock.withLock { link.endpoints = newValue } }
    }

    /// The group's obfuscation settings, nil for plain WireGuard.
    public var obfuscation: Member.Obfuscation? {
        get { lock.withLock { link.obfuscation } }
        set { lock.withLock { link.obfuscation = newValue } }
    }

    /// Whether the clients may come only over VLESS: the offers then wait
    /// for vless, the way to the forwarder that its answer gives (cbbtun's
    /// Status).
    public var vlessOnly: Bool {
        get { lock.withLock { link.vlessOnly } }
        set { lock.withLock { link.vlessOnly = newValue } }
    }

    /// The way to the forwarder over VLESS, nil without it.
    public var vless: Member.VLESS? {
        get { lock.withLock { link.vless } }
        set { lock.withLock { link.vless = newValue } }
    }

    /// Admits device with the tunnel key it offered, as the hub keeps it. A
    /// client that keeps its key keeps its preshared key; a new key gets a
    /// new one. changed tells whether the clients must be saved and handed
    /// to the tunnel again. It refuses a key that is not 32 bytes, the
    /// hub's own, or another client's, and a 257th client.
    public func admit(device: String, key: Data) throws -> (client: Client, changed: Bool) {
        try lock.withLock {
            guard GroupCertificates.isDeviceID(device) else { throw Refused.badDevice }
            guard key.count == 32, key.contains(where: { $0 != 0 }), key != publicKey else { throw Refused.badKey }
            let i = list.firstIndex { $0.device == device }
            if let other = list.enumerated().first(where: { $0.offset != i && $0.element.key == key }) {
                throw Refused.keyOfAnother(other.element.device)
            }
            if let i {
                if list[i].key == key { return (list[i], false) }
                list[i] = Client(device: device, key: key, psk: Self.newPSK())
                return (list[i], true)
            }
            guard list.count < Self.maxClients else { throw Refused.tooManyClients }
            let c = Client(device: device, key: key, psk: Self.newPSK())
            list.append(c)
            return (c, true)
        }
    }

    /// The offer for a client admitted with admit, or nil while the offers
    /// wait for VLESS.
    public func offer(for c: Client) -> Member.TunnelOffer? {
        let l = lock.withLock { link }
        if l.vlessOnly && l.vless == nil { return nil }
        return Member.TunnelOffer(hubKey: publicKey, psk: c.psk, endpoints: Array(l.endpoints.prefix(8)), obfuscation: l.obfuscation, vless: l.vless)
    }

    /// Admits a peer and returns its offer, for MemberNode's hub: nil when
    /// it is refused (refused tells why) or the offers wait. changed gets
    /// the clients when they changed.
    public func offer(device: String, key: Data, changed: ([Client]) -> Void = { _ in },
                      refused: (Error) -> Void = { _ in }) -> Member.TunnelOffer? {
        let admitted: (client: Client, changed: Bool)
        do {
            admitted = try admit(device: device, key: key)
        } catch {
            refused(error)
            return nil
        }
        if admitted.changed { changed(clients) }
        return offer(for: admitted.client)
    }

    /// Forgets the clients keep refuses, removed devices for one, and
    /// returns their devices.
    @discardableResult
    public func prune(keep: (Client) -> Bool) -> [String] {
        lock.withLock {
            let gone = list.filter { !keep($0) }.map(\.device)
            list.removeAll { !keep($0) }
            return gone
        }
    }

    /// The clients as cbbtun's StartHub and SetClients take them.
    public func clientsJSON() throws -> String {
        String(decoding: try JSONEncoder().encode(clients), as: UTF8.self)
    }

    /// The clients clientsJSON gave.
    public static func clients(json: String) throws -> [Client] {
        json.isEmpty ? [] : try JSONDecoder().decode([Client].self, from: Data(json.utf8))
    }

    private static func newPSK() -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
    }
}
