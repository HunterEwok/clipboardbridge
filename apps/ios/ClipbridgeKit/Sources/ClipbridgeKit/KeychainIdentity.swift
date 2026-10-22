// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Security) && canImport(Network)
import Crypto
import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif
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

    /// Creates a P-256 key in the keychain under label: in the Secure
    /// Enclave with secureEnclave (on a device), a keychain key otherwise.
    /// With userPresence, a Secure Enclave key signs only after Face ID,
    /// Touch ID or the passcode (an evaluated LAContext that loadKey takes).
    public static func makeKey(label: String, secureEnclave: Bool = false, userPresence: Bool = false) throws -> SecKey {
        var attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrIsPermanent: true,
            kSecAttrLabel: label,
        ]
        if secureEnclave {
            // A Secure Enclave key needs an access control that allows
            // signing; it stays on this device and works while unlocked.
            var error: Unmanaged<CFError>?
            let flags: SecAccessControlCreateFlags = userPresence ? [.privateKeyUsage, .userPresence] : .privateKeyUsage
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            attrs[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
            attrs[kSecPrivateKeyAttrs] = [kSecAttrIsPermanent: true, kSecAttrLabel: label, kSecAttrAccessControl: access] as [CFString: Any]
        }
        #if os(macOS)
        if !secureEnclave { attrs[kSecUseDataProtectionKeychain] = false }
        #endif
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    /// The key that makeKey created under label, or nil.
    public static func loadKey(label: String) throws -> SecKey? { try loadKey(label: label, context: nil) }

    /// The same, signing with an authentication context: one that the
    /// user already passed signs without asking again, and one that does
    /// not allow interaction makes a key that needs the user fail instead
    /// of asking.
    public static func loadKey(label: String, context: AnyObject?) throws -> SecKey? {
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrLabel: label,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecReturnRef: true,
        ]
        #if canImport(LocalAuthentication)
        if let context = context as? LAContext { query[kSecUseAuthenticationContext] = context }
        #endif
        #if os(macOS)
        query[kSecUseDataProtectionKeychain] = false
        #endif
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let out else { throw Failure.keychain(status) }
        return (out as! SecKey)
    }

    /// Removes the certificates stored under label, before a new one
    /// replaces them.
    public static func removeCertificates(label: String) {
        var query: [CFString: Any] = [kSecClass: kSecClassCertificate, kSecAttrLabel: label]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain] = false
        #endif
        SecItemDelete(query as CFDictionary)
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
            let item: [CFString: Any] = [kSecClass: kSecClassKey, kSecValueRef: key, kSecAttrLabel: label]
            let add = item.merging(where_) { a, _ in a }
            let status = SecItemAdd(add as CFDictionary, nil)
            guard status == errSecSuccess || status == errSecDuplicateItem else { throw Failure.keychain(status) }
        }
        let item: [CFString: Any] = [kSecClass: kSecClassCertificate, kSecValueRef: cert, kSecAttrLabel: label]
        let add = item.merging(where_) { a, _ in a }
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
