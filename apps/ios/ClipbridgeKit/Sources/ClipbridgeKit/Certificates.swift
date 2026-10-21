// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// A P-256 key that signs certificates: a software key in tests, a key in
/// the Secure Enclave in the app, which never leaves it.
public protocol CertificateSigner {
    /// The public key as a SubjectPublicKeyInfo, DER.
    var publicKeyDER: Data { get }
    /// An ECDSA signature with SHA-256 over data, DER.
    func signature(for data: Data) throws -> Data
}

/// A software P-256 key as a CertificateSigner.
public struct SoftwareSigner: CertificateSigner {
    public let key: P256.Signing.PrivateKey
    public init(_ key: P256.Signing.PrivateKey = .init()) { self.key = key }
    public var publicKeyDER: Data { key.publicKey.derRepresentation }
    public func signature(for data: Data) throws -> Data { try key.signature(for: data).derRepresentation }
}

/// The group's certificates, with the profiles of docs/protocol.md,
/// section 2, as the Go side issues them (internal/group/cert.go).
public enum GroupCertificates {
    /// How long a member certificate lasts.
    public static let memberYears = 2
    /// How long the group CA lasts.
    public static let caYears = 20
    /// Certificates start this much before now, for clocks a little behind.
    public static let backdate: TimeInterval = 24 * 3600

    static let oidECPublicKey = "1.2.840.10045.2.1"
    static let oidECDSAWithSHA256 = "1.2.840.10045.4.3.2"
    static let oidCommonName = "2.5.4.3"
    static let oidBasicConstraints = "2.5.29.19"
    static let oidKeyUsage = "2.5.29.15"
    static let oidExtKeyUsage = "2.5.29.37"
    static let oidSubjectAltName = "2.5.29.17"
    static let oidSubjectKeyID = "2.5.29.14"
    static let oidAuthorityKeyID = "2.5.29.35"
    static let oidServerAuth = "1.3.6.1.5.5.7.3.1"
    static let oidClientAuth = "1.3.6.1.5.5.7.3.2"

    /// A new group CA certificate for the signer's key: self-signed, a CA
    /// with path length 0 for certificate and CRL signing, valid from a day
    /// ago for 20 years.
    public static func groupCA(signer: CertificateSigner, now: Date) throws -> Data {
        let day = ISO8601DateFormatter.string(from: now, timeZone: TimeZone(identifier: "UTC")!, formatOptions: [.withFullDate])
        let name = distinguishedName("clipbridge group CA \(day)")
        let ski = keyIdentifier(signer.publicKeyDER)
        let extensions = [
            ext(oidBasicConstraints, critical: true, DER.sequence([DER.bool(true), DER.integer(0)])),
            // keyCertSign (bit 5) and cRLSign (bit 6).
            ext(oidKeyUsage, critical: true, DER.bitString([0x06], unused: 1)),
            ext(oidSubjectKeyID, critical: false, DER.octetString(ski)),
        ]
        let notAfter = Calendar.utc.date(byAdding: .year, value: caYears, to: now)!
        return try sign(subject: name, issuer: name, publicKey: signer.publicKeyDER,
                        notBefore: now.addingTimeInterval(-backdate), notAfter: notAfter,
                        extensions: extensions, signer: signer)
    }

    /// A member certificate for a device's public key (a SubjectPublicKeyInfo),
    /// signed by the group CA: the device ID as its CN, cb-<ID>.local as its
    /// one DNS name, for server and client use, from the CA's start until
    /// two years from now or the CA's end, whichever is sooner.
    public static func member(device: String, publicKey: Data, ca: Data, caSigner: CertificateSigner, now: Date) throws -> Data {
        guard isDeviceID(device) else { throw CertificateError.badDeviceID }
        let caInfo = try CertificateInfo(der: ca)
        guard now >= caInfo.notBefore, now < caInfo.notAfter else { throw CertificateError.outsideCALifetime }
        let notAfter = min(Calendar.utc.date(byAdding: .year, value: memberYears, to: now)!, caInfo.notAfter)
        let extensions = [
            // digitalSignature (bit 0).
            ext(oidKeyUsage, critical: true, DER.bitString([0x80], unused: 7)),
            ext(oidExtKeyUsage, critical: false, DER.sequence([DER.oid(oidServerAuth), DER.oid(oidClientAuth)])),
            ext(oidBasicConstraints, critical: true, DER.sequence([])),
            ext(oidSubjectAltName, critical: false, DER.sequence([DER.context(2, constructed: false, Array("cb-\(device).local".utf8))])),
            ext(oidAuthorityKeyID, critical: false, DER.sequence([DER.context(0, constructed: false, keyIdentifier(caSigner.publicKeyDER))])),
        ]
        return try sign(subject: distinguishedName(device), issuer: caInfo.rawSubject, publicKey: publicKey,
                        notBefore: caInfo.notBefore, notAfter: notAfter, extensions: extensions, signer: caSigner)
    }

    /// The group tag: the first 8 bytes of SHA-256 over the group CA
    /// certificate, in hex. Members publish it, and the welcome names it.
    public static func tag(groupCA: Data) -> String {
        SHA256.hash(data: groupCA).prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// Whether s is a device ID: 32 lowercase hex characters.
    public static func isDeviceID(_ s: String) -> Bool {
        s.utf8.count == 32 && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    static func distinguishedName(_ cn: String) -> [UInt8] {
        DER.sequence([DER.set([DER.sequence([DER.oid(oidCommonName), DER.utf8String(cn)])])])
    }

    static func ext(_ oid: String, critical: Bool, _ value: [UInt8]) -> [UInt8] {
        DER.sequence([DER.oid(oid)] + (critical ? [DER.bool(true)] : []) + [DER.octetString(value)])
    }

    /// The key identifier Go uses: SHA-1 over the public key's bit string.
    static func keyIdentifier(_ spki: Data) -> [UInt8] {
        Array(Insecure.SHA1.hash(data: (try? CertificateInfo.subjectPublicKeyBits(spki)) ?? Array(spki)))
    }

    static func sign(subject: [UInt8], issuer: [UInt8], publicKey: Data, notBefore: Date, notAfter: Date,
                     extensions: [[UInt8]], signer: CertificateSigner) throws -> Data {
        var serial = [UInt8](repeating: 0, count: 16)
        var rng = SystemRandomNumberGenerator()
        for i in serial.indices { serial[i] = UInt8.random(in: .min ... .max, using: &rng) }
        serial[0] &= 0x7f
        serial[0] |= 0x01 // non-zero, so the minimal encoding keeps 16 bytes
        let algorithm = DER.sequence([DER.oid(oidECDSAWithSHA256)])
        let tbs = DER.sequence([
            DER.context(0, constructed: true, DER.integer(2)), // v3
            DER.integer(unsigned: serial),
            algorithm,
            issuer,
            DER.sequence([DER.time(notBefore), DER.time(notAfter)]),
            subject,
            Array(publicKey),
            DER.context(3, constructed: true, DER.sequence(extensions)),
        ])
        let sig = try signer.signature(for: Data(tbs))
        return Data(DER.sequence([tbs, algorithm, DER.bitString(Array(sig))]))
    }

    public enum CertificateError: Error { case badDeviceID, outsideCALifetime, malformed }
}

/// What ClipbridgeKit reads from a certificate: its subject, validity and
/// public key. It is a minimal DER reader, not a verifier.
public struct CertificateInfo {
    public let rawSubject: [UInt8]
    public let notBefore: Date
    public let notAfter: Date
    public let publicKey: Data // SubjectPublicKeyInfo

    public init(der: Data) throws {
        var r = DERReader(Array(der))
        var cert = try r.read(0x30)
        var tbs = try cert.read(0x30)
        if tbs.peek == 0xa0 { _ = try tbs.readAny() } // version
        _ = try tbs.read(0x02) // serial
        _ = try tbs.read(0x30) // algorithm
        _ = try tbs.readAny() // issuer
        var validity = try tbs.read(0x30)
        notBefore = try validity.readTime()
        notAfter = try validity.readTime()
        rawSubject = try tbs.readAny(raw: true).bytes
        publicKey = Data(try tbs.readAny(raw: true).bytes)
    }

    /// The subject's common name, or nil without one.
    public var commonName: String? {
        var r = DERReader(rawSubject)
        guard var name = try? r.read(0x30) else { return nil }
        while name.peek != nil {
            guard var rdn = try? name.read(0x31) else { return nil }
            while rdn.peek != nil {
                guard var atv = try? rdn.read(0x30), let oid = try? atv.readAny(raw: true).bytes,
                      let value = try? atv.readAny() else { return nil }
                if oid == DER.oid(GroupCertificates.oidCommonName) {
                    return String(decoding: value.bytes, as: UTF8.self)
                }
            }
        }
        return nil
    }

    /// The bits of the public key in a SubjectPublicKeyInfo.
    static func subjectPublicKeyBits(_ spki: Data) throws -> [UInt8] {
        var r = DERReader(Array(spki))
        var seq = try r.read(0x30)
        _ = try seq.read(0x30)
        let bits = try seq.read(0x03).bytes
        return Array(bits.dropFirst()) // the unused-bits byte
    }
}

struct DERReader {
    var bytes: [UInt8]
    var pos = 0
    init(_ b: [UInt8]) { bytes = b }

    var peek: UInt8? { pos < bytes.count ? bytes[pos] : nil }

    /// Reads one element; returns its content, or the whole element with raw.
    mutating func readAny(raw: Bool = false) throws -> DERReader {
        guard pos + 2 <= bytes.count else { throw GroupCertificates.CertificateError.malformed }
        let start = pos
        pos += 1
        var n = Int(bytes[pos])
        pos += 1
        if n & 0x80 != 0 {
            let k = n & 0x7f
            guard k > 0, k <= 4, pos + k <= bytes.count else { throw GroupCertificates.CertificateError.malformed }
            n = bytes[pos..<pos + k].reduce(0) { $0 << 8 | Int($1) }
            pos += k
        }
        guard pos + n <= bytes.count else { throw GroupCertificates.CertificateError.malformed }
        defer { pos += n }
        return DERReader(Array(bytes[(raw ? start : pos)..<pos + n]))
    }

    mutating func read(_ tag: UInt8) throws -> DERReader {
        guard peek == tag else { throw GroupCertificates.CertificateError.malformed }
        return try readAny()
    }

    mutating func readTime() throws -> Date {
        let tag = peek
        let s = String(decoding: try readAny().bytes, as: UTF8.self)
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        switch tag {
        case 0x17:
            f.dateFormat = "yyMMddHHmmss'Z'"
            // yy from 50 on is 19yy, as RFC 5280 says.
            f.twoDigitStartDate = Date(timeIntervalSince1970: -631_152_000) // 1950-01-01
        case 0x18: f.dateFormat = "yyyyMMddHHmmss'Z'"
        default: throw GroupCertificates.CertificateError.malformed
        }
        guard let d = f.date(from: s) else { throw GroupCertificates.CertificateError.malformed }
        return d
    }
}

extension Calendar {
    static var utc: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }
}
