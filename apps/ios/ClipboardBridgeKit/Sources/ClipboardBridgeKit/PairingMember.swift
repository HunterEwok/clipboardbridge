// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// A connection that carries pairing frames: a TLS connection in the app,
/// anything in tests.
public protocol FrameTransport: AnyObject {
    func write(_ data: Data) async throws
    /// Reads exactly n bytes, or throws.
    func read(exactly n: Int) async throws -> Data
}

extension FrameTransport {
    func writeFrame(_ f: Pairing.Frame) async throws { try await write(Pairing.encode(f)) }

    func readFrame() async throws -> Pairing.Frame {
        let n = try Pairing.length(header: try await read(exactly: 4))
        return try Pairing.decode(body: try await read(exactly: n))
    }
}

/// The admitting side of pairing, which the phone, as the root of the
/// group, plays: it dials a listening computer and confirms the code first
/// (docs/protocol.md, section 6, "The joiner listens").
public enum PairingMember {
    public struct Admitted: Equatable {
        public var device: String
        public var info: Pairing.Info
        public var cert: Data
        /// Whether the computer said it stored its identity. Without it, it
        /// may still hold the certificate.
        public var confirmed: Bool
    }

    public enum Failure: Error, Equatable {
        /// The computer's answer: a wrong code, or another refusal.
        case refused(Pairing.ErrorCode)
        case badJoiner(String)
        case protocolError(String)
    }

    /// Runs the exchange over a connection the member dialed and whose TLS
    /// handshake is done: memberCert and joinerCert are the two
    /// certificates of the handshake, the joiner's already checked against
    /// the QR code's fingerprint; sessionID is the TLS exporter's output.
    /// issue makes the welcome for the joiner's device ID, public key and
    /// description; it is called only after the joiner proved it knows the
    /// code.
    public static func admit(over t: FrameTransport, code: String, memberCert: Data, joinerCert: Data,
                             sessionID: [UInt8], memberAD: Pairing.MemberAD, taken: (String) -> Bool = { _ in false },
                             issue: (String, Data, Pairing.Info) throws -> Pairing.Welcome) async throws -> Admitted {
        let joiner = try CertificateInfo(der: joinerCert)
        guard let device = joiner.commonName, GroupCertificates.isDeviceID(device) else {
            throw Failure.badJoiner("the computer's certificate names no device ID")
        }
        let first = try await t.readFrame()
        // A device picks its own ID, so one that is in the group already is
        // refused before the exchange.
        if taken(device) {
            try? await t.writeFrame(Pairing.Frame(error: Pairing.ErrorCode.taken.rawValue))
            throw Failure.refused(.taken)
        }
        guard let ya = first.msg, let ada = first.ad,
              let info = try? JSONDecoder().decode(Pairing.Info.self, from: ada), info.isValid else {
            throw Failure.protocolError("bad first frame")
        }
        let adb = try JSONEncoder().encode(memberAD)
        var st = try CPace(role: .responder, password: Array(code.utf8),
                           channelID: Pairing.channelID(memberCert: memberCert, joinerCert: joinerCert),
                           sessionID: sessionID, ad: Array(adb))
        _ = try st.finish(peerMessage: Array(ya), peerAD: Array(ada))
        try await t.writeFrame(Pairing.Frame(msg: Data(st.message), ad: adb, tag: Data(st.confirmationTag!)))
        let confirm = try await t.readFrame()
        if let code = confirm.error { throw Failure.refused(Pairing.ErrorCode(wire: code)) }
        guard let tag = confirm.tag, (try? st.verify(peerTag: Array(tag))) != nil else {
            try? await t.writeFrame(Pairing.Frame(error: Pairing.ErrorCode.wrongCode.rawValue))
            throw Failure.refused(.wrongCode)
        }
        let welcome = try issue(device, joiner.publicKey, info)
        try await t.writeFrame(Pairing.Frame(welcome: welcome))
        // The welcome went out: the computer counts as admitted now.
        let done = try? await t.readFrame()
        return Admitted(device: device, info: info, cert: welcome.cert, confirmed: done?.ok == true)
    }
}
