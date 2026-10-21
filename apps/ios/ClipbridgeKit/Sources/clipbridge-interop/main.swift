// SPDX-License-Identifier: AGPL-3.0-only

// clipbridge-interop plays the phone against the Go code in tests
// (internal/pair, TestSwiftMemberAdmitsGoJoiner): it creates a group, dials
// a Go joiner over plain TCP, exchanges certificates in place of a TLS
// handshake, and admits the joiner with PairingMember.
//
//   clipbridge-interop admit HOST PORT CODE
//   clipbridge-interop admit-tls HOST PORT CODE FINGERPRINT   (macOS: real TLS)
//
// It prints the group CA in base64 on success. Test use only.

import ClipbridgeKit
import Foundation
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

final class SocketTransport: FrameTransport {
    let fd: Int32

    init(host: String, port: UInt16) throws {
        #if canImport(Glibc)
        let stream = Int32(SOCK_STREAM.rawValue) // an enum in Glibc
        #else
        let stream = SOCK_STREAM
        #endif
        fd = socket(AF_INET, stream, 0)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        #if !canImport(Glibc)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard ok == 0 else { throw POSIXError(.ECONNREFUSED) }
    }

    func write(_ data: Data) async throws {
        try data.withUnsafeBytes { buf in
            var off = 0
            while off < buf.count {
                let n = send(fd, buf.baseAddress! + off, buf.count - off, 0)
                guard n > 0 else { throw POSIXError(.EPIPE) }
                off += n
            }
        }
    }

    func read(exactly n: Int) async throws -> Data {
        var out = Data(count: n)
        try out.withUnsafeMutableBytes { buf in
            var off = 0
            while off < n {
                let got = recv(fd, buf.baseAddress! + off, n - off, 0)
                guard got > 0 else { throw POSIXError(.ECONNRESET) }
                off += got
            }
        }
        return out
    }

    func writeBlob(_ d: Data) async throws {
        var len = UInt32(d.count).bigEndian
        try await write(Data(bytes: &len, count: 4) + d)
    }

    func readBlob() async throws -> Data {
        let n = try await read(exactly: 4).reduce(0) { $0 << 8 | Int($1) }
        return try await read(exactly: n)
    }
}

let args = CommandLine.arguments
guard args.count >= 5, let port = UInt16(args[3]),
      args[1] == "admit" && args.count == 5 || args[1] == "admit-tls" && args.count == 6 else {
    FileHandle.standardError.write("usage: clipbridge-interop admit HOST PORT CODE | admit-tls HOST PORT CODE FINGERPRINT\n".data(using: .utf8)!)
    exit(2)
}

do {
    let now = Date()
    let caSigner = SoftwareSigner()
    let ca = try GroupCertificates.groupCA(signer: caSigner, now: now)
    let phoneKey = SoftwareSigner()
    let phoneID = (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
    let phoneCert = try GroupCertificates.member(device: phoneID, publicKey: phoneKey.publicKeyDER, ca: ca, caSigner: caSigner, now: now)
    let t: FrameTransport
    let joinerCert: Data
    let sid: [UInt8]
    if args[1] == "admit-tls" {
        #if canImport(Network)
        let fp = args[5]
        let identity = try KeychainIdentity.identity(certificate: phoneCert, key: try KeychainIdentity.secKey(phoneKey.key),
                                                     label: "clipbridge-interop-\(phoneID)")
        let tls = TLSTransport(host: args[2], port: port, alpn: Pairing.alpn, identity: identity) { leaf in
            Pairing.fingerprint(cert: leaf) == fp
        }
        try await tls.start()
        guard let leaf = tls.peerCertificate,
              let exported = tls.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else {
            throw TLSTransport.Failure.notReady("no peer certificate or exporter")
        }
        (t, joinerCert, sid) = (tls, leaf, exported)
        #else
        FileHandle.standardError.write("admit-tls needs Network.framework\n".data(using: .utf8)!)
        exit(2)
        #endif
    } else {
        let s = try SocketTransport(host: args[2], port: port)
        // In place of the TLS handshake: the member's certificate, then the
        // joiner's; the session ID is fixed.
        try await s.writeBlob(phoneCert)
        (t, joinerCert, sid) = (s, try await s.readBlob(), [UInt8](repeating: 0, count: 32))
    }
    let tag = GroupCertificates.tag(groupCA: ca)
    let admitted = try await PairingMember.admit(
        over: t, code: args[4], memberCert: phoneCert, joinerCert: joinerCert,
        sessionID: sid,
        memberAD: Pairing.MemberAD(device: phoneID, group: tag)
    ) { device, publicKey, _ in
        Pairing.Welcome(cert: try GroupCertificates.member(device: device, publicKey: publicKey, ca: ca, caSigner: caSigner, now: now), groupCA: ca)
    }
    guard admitted.confirmed else {
        FileHandle.standardError.write("the joiner did not confirm\n".data(using: .utf8)!)
        exit(1)
    }
    print(ca.base64EncodedString())
} catch {
    FileHandle.standardError.write("clipbridge-interop: \(error)\n".data(using: .utf8)!)
    exit(1)
}
