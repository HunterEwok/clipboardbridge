// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Security) && canImport(Network)
import Crypto
import Foundation
import Security

/// Turns a certificate and its private key into the SecIdentity that TLS
/// presents. On a device the key lives in the Secure Enclave; the keychain
/// pairs it with its certificate.
public enum KeychainIdentity {
    public enum Failure: Error { case keychain(OSStatus), noIdentity }

    /// A SecKey for a software P-256 key, for tests and tools.
    public static func secKey(_ key: P256.Signing.PrivateKey) throws -> SecKey {
        var error: Unmanaged<CFError>?
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        guard let k = SecKeyCreateWithData(key.x963Representation as CFData, attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return k
    }

    /// Stores the key (unless it is in the keychain already, as a Secure
    /// Enclave key is) and the certificate under label, and returns the
    /// identity they make.
    public static func identity(certificate der: Data, key: SecKey, label: String, storeKey: Bool = true) throws -> SecIdentity {
        guard let cert = SecCertificateCreateWithData(nil, der as CFData) else { throw Failure.noIdentity }
        // On macOS a tool without entitlements may only use the file
        // keychain; the app on iOS uses the data protection keychain.
        #if os(macOS)
        let where_: [CFString: Any] = [kSecUseDataProtectionKeychain: false]
        #else
        let where_: [CFString: Any] = [:]
        #endif
        if storeKey {
            let add = [kSecClass: kSecClassKey, kSecValueRef: key, kSecAttrLabel: label].merging(where_) { a, _ in a }
            let status = SecItemAdd(add as CFDictionary, nil)
            guard status == errSecSuccess || status == errSecDuplicateItem else { throw Failure.keychain(status) }
        }
        let add = [kSecClass: kSecClassCertificate, kSecValueRef: cert, kSecAttrLabel: label].merging(where_) { a, _ in a }
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else { throw Failure.keychain(status) }
        #if os(macOS)
        var identity: SecIdentity?
        let s = SecIdentityCreateWithCertificate(nil, cert, &identity)
        guard s == errSecSuccess, let identity else { throw Failure.keychain(s) }
        return identity
        #else
        var out: CFTypeRef?
        let s = SecItemCopyMatching([kSecClass: kSecClassIdentity, kSecAttrLabel: label, kSecReturnRef: true] as CFDictionary, &out)
        guard s == errSecSuccess, let out else { throw Failure.keychain(s) }
        return out as! SecIdentity
        #endif
    }
}
#endif
