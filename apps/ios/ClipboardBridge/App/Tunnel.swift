// SPDX-License-Identifier: AGPL-3.0-only

import Cbbtun
import ClipboardBridgeKit
import Foundation
import Security

/// The tunnel of mobile/cbbtun, WireGuard in the app's process, bound by
/// gomobile into Cbbtun.xcframework (mobile/cbbtun/bind.sh ios).
struct GoTunnels: Tunnels {
    /// A call that failed without saying why.
    struct Failure: Error { let call: String }

    func newKey() throws -> Data { try Self.call("NewKey") { CbbtunNewKey($0) } }

    func publicKey(_ privateKey: Data) throws -> Data { try Self.call("PublicKey") { CbbtunPublicKey(privateKey, $0) } }

    func start(privateKey: Data, psk: Data, hubKey: Data, device: String, hub: String, endpoint: String,
               obfuscation: String, vless: String) throws -> OpenTunnel {
        GoTunnel(try Self.call("Start") { CbbtunStart(privateKey, psk, hubKey, device, hub, endpoint, obfuscation, vless, $0) })
    }

    private static func call<T>(_ name: String, _ f: (NSErrorPointer) -> T?) throws -> T {
        var error: NSError?
        if let v = f(&error) { return v }
        throw error ?? Failure(call: name)
    }
}

/// A running tunnel of mobile/cbbtun.
final class GoTunnel: OpenTunnel, @unchecked Sendable {
    private let tunnel: CbbtunTunnel
    let port: UInt16

    init(_ tunnel: CbbtunTunnel) {
        self.tunnel = tunnel
        port = UInt16(clamping: tunnel.port())
    }

    func setEndpoint(_ endpoint: String) throws { try tunnel.setEndpoint(endpoint) }

    func close() { try? tunnel.close() }
}

/// The state of sync away from home in the keychain: readable after the
/// first unlock, so the app syncs in the background as at home, and never
/// in a backup or on another device.
enum AwayKeychain {
    static let service = "io.github.hunterewok.clipboardbridge.away"

    enum Failure: Error { case keychain(OSStatus) }

    private static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "state"]
    }

    static func load() -> AwayState? {
        var q = query
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return AwayState.decode(data)
    }

    /// Keeps s; nil deletes it.
    static func save(_ s: AwayState?) throws {
        guard let s else {
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure.keychain(status) }
            return
        }
        let data = try s.encoded()
        let attrs: [String: Any] = [kSecValueData as String: data,
                                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        var status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(attrs) { $1 } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Failure.keychain(status) }
    }
}
