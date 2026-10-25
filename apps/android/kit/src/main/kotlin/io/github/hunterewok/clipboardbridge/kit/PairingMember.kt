// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

/**
 * The admitting side of pairing, which the phone, as an admin of the
 * group, plays: it dials a listening device and confirms the code first
 * (docs/protocol.md, section 6, "The joiner listens").
 */
object PairingMember {
    data class Admitted(
        val device: String,
        val info: Pairing.Info,
        val cert: ByteArray,
        /** Whether the device said it stored its identity. Without it, it may still hold the certificate. */
        val confirmed: Boolean,
    )

    /** Why admitting failed: the device's answer (a wrong code, or another refusal), a bad joiner, or a broken exchange. */
    class Failure(message: String, val code: Pairing.ErrorCode? = null) : Exception(message)

    /**
     * Runs the exchange over a connection the member dialed and whose TLS
     * handshake is done: memberCert and joinerCert are the two certificates
     * of the handshake, the joiner's already checked against the QR code's
     * fingerprint; sessionID is the TLS exporter's output. issue makes the
     * welcome for the joiner's device ID, public key and description; it is
     * called only after the joiner proved it knows the code. taken reports
     * whether the joiner's device ID is in the group already; such a joiner
     * is refused before the exchange, as a device picks its own ID.
     */
    fun admit(
        t: FrameTransport,
        code: String,
        memberCert: ByteArray,
        joinerCert: ByteArray,
        sessionID: ByteArray,
        memberAD: Pairing.MemberAD,
        taken: (String) -> Boolean = { false },
        issue: (String, ByteArray, Pairing.Info) -> Pairing.Welcome,
    ): Admitted {
        val joiner = CertificateInfo(joinerCert)
        val device = joiner.commonName
        if (device == null || !GroupCertificates.isDeviceID(device)) throw Failure("the device's certificate names no device ID")
        val first = t.readFrame()
        if (taken(device)) {
            runCatching { t.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.TAKEN.wire)) }
            throw Failure("a device with this device ID is in the group already", Pairing.ErrorCode.TAKEN)
        }
        val ya = first.msg
        val ada = first.ad
        val info = ada?.let { Pairing.Info.decode(it) }
        if (ya == null || ada == null || info == null || !info.isValid) throw Failure("bad first frame")
        val adb = memberAD.encode()
        val st = CPace(CPace.Role.RESPONDER, code.toByteArray(), Pairing.channelID(memberCert, joinerCert), sessionID, adb)
        st.finish(ya, ada)
        t.writeFrame(Pairing.Frame(msg = st.message, ad = adb, tag = st.confirmationTag))
        val confirm = t.readFrame()
        confirm.error?.let { throw Failure("refused: $it", Pairing.ErrorCode.of(it)) }
        val tag = confirm.tag
        if (tag == null || runCatching { st.verify(tag) }.isFailure) {
            runCatching { t.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.WRONG_CODE.wire)) }
            throw Failure("wrong code", Pairing.ErrorCode.WRONG_CODE)
        }
        val welcome = issue(device, joiner.publicKey, info)
        t.writeFrame(Pairing.Frame(welcome = welcome))
        // The welcome went out: the device counts as admitted now.
        val done = runCatching { t.readFrame() }.getOrNull()
        return Admitted(device, info, welcome.cert, done?.ok == true)
    }
}
