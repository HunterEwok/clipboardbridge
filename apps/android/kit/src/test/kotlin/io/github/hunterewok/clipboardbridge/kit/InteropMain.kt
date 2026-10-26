// SPDX-License-Identifier: AGPL-3.0-only

// The Kotlin twin of clipboardbridge-interop (apps/ios/ClipboardBridgeKit): it
// plays the Android phone against the Go code in tests, with the same
// commands, so Go's TestSwiftMemberAdmitsGoJoiner, TestSwiftMemberAdmitsGoJoinerTLS,
// TestSwiftHubAdmitsInvitedGoJoiner and TestSwiftMemberTLS run it too. Gradle's
// interopScript task writes a script that starts it.
//
//   admit HOST PORT CODE                 pairing over plain TCP, certificates exchanged in place of TLS
//   admit-tls HOST PORT CODE FINGERPRINT pairing over TLS
//
// print the group CA in base64 on success.
//
//   invite-window SECRET yes|no
//
// opens a remote invitation's pairing window on the loopback address with
// SECRET (base64), as the phone that is the hub does, and prints
// "port N"; for the device that proves it knows the secret it prints
// "fingerprint F" and admits it or not; then it prints the group CA in
// base64 and ends, or fails with the first failed attempt.
//
//   member-tls HOST PORT PEER
//
// prints "key <SubjectPublicKeyInfo, base64>", reads "cert <DER, base64>"
// and "ca <DER, base64>" from standard input, dials the Go member PEER with
// TLS, sends "from swift" (the Swift tool's text, which Go waits for),
// waits for "from go", and prints "ok". Test use only.

package io.github.hunterewok.clipboardbridge.kit

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.time.Instant
import java.util.Base64
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess

private fun fail(msg: String): Nothing {
    System.err.println("clipboardbridge-interop: $msg")
    exitProcess(1)
}

private fun admit(host: String, port: Int, code: String, fingerprint: String?) {
    val now = Instant.now()
    val caSigner = SoftwareSigner()
    val memberKey = SoftwareSigner()
    val group = PhoneGroup.create(caSigner, memberKey.publicKeyDER, now)
    val t: FrameTransport
    val joinerCert: ByteArray
    val sid: ByteArray
    if (fingerprint != null) {
        val tls = TLSTransport.dial(host, port, Pairing.ALPN, memberKey.keyPair.private, listOf(group.memberCert)) {
            Pairing.fingerprint(it[0]) == fingerprint
        }
        t = tls
        joinerCert = tls.peerCertificate ?: fail("no peer certificate")
        sid = tls.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32)
    } else {
        // In place of the TLS handshake: the member's certificate, then the joiner's; the session ID is fixed.
        val s = Socket(host, port)
        val out = DataOutputStream(s.getOutputStream())
        val input = DataInputStream(s.getInputStream())
        out.writeInt(group.memberCert.size)
        out.write(group.memberCert)
        out.flush()
        joinerCert = ByteArray(input.readInt()).also { input.readFully(it) }
        t = StreamTransport(input, out, s::close)
        sid = ByteArray(32)
    }
    val admitted = try {
        group.admit(t, code, joinerCert, sid, caSigner, now)
    } finally {
        t.close()
    }
    if (!admitted.confirmed || group.computers.map { it.device } != listOf(admitted.device)) fail("the joiner did not confirm")
    println(Base64.getEncoder().encodeToString(group.groupCA))
}

private fun memberTLS(host: String, port: Int, peer: String) {
    val key = SoftwareSigner()
    println("key ${Base64.getEncoder().encodeToString(key.publicKeyDER)}")
    System.out.flush()
    fun field(name: String): ByteArray {
        val line = readlnOrNull() ?: fail("no $name on standard input")
        if (!line.startsWith("$name ")) fail("no $name on standard input")
        return Base64.getDecoder().decode(line.removePrefix("$name "))
    }
    val cert = field("cert")
    val ca = field("ca")
    val me = CertificateInfo(cert).commonName ?: fail("no device ID")
    val tls = TLSTransport.dial(host, port, Member.ALPN, key.keyPair.private, listOf(cert)) {
        runCatching { GroupCertificates.verifyMember(it[0], ca, Instant.now()) }.getOrNull() == peer
    }
    val changes = LinkedBlockingQueue<String>()
    val node = MemberNode(SyncEngine(me, HybridClock()), "Android", onChange = { changes.add(it.text) })
    val serving = Thread { node.serve(tls) }.apply { start() }
    val deadline = System.nanoTime() + 15_000_000_000L
    while (node.peers == 0) {
        if (System.nanoTime() > deadline) fail("no hello within 15 s")
        Thread.sleep(50)
    }
    node.send("from swift", Member.Kind.TEXT) // the text Go's test waits for
    while (true) {
        val left = deadline - System.nanoTime()
        val t = changes.poll(maxOf(left, 0), TimeUnit.NANOSECONDS) ?: fail("no \"from go\" within 15 s")
        if (t == "from go") break
    }
    println("ok")
    System.out.flush()
    node.closeAll()
    serving.join()
}

private fun inviteWindow(secret: ByteArray, yes: Boolean) {
    val now = Instant.now()
    val caSigner = SoftwareSigner()
    val memberKey = SoftwareSigner()
    val group = PhoneGroup.create(caSigner, memberKey.publicKeyDER, now)
    val ended = LinkedBlockingQueue<Result<PairingMember.Admitted>>()
    val invitation = PairingMember.Invitation(secret) { req ->
        println("fingerprint ${req.fingerprint}")
        System.out.flush()
        yes
    }
    val window = InvitationWindow(
        memberKey.keyPair.private, group.memberCert, now.plusSeconds(60),
        admit = { t, joinerCert, sid -> group.admit(t, "", joinerCert, sid, caSigner, Instant.now(), invitation = invitation) },
        onEnd = { ended.add(it) },
        onError = { ended.add(Result.failure(it)) },
    )
    println("port ${window.port}")
    System.out.flush()
    val result = ended.poll(30, TimeUnit.SECONDS) ?: fail("no attempt within 30 s")
    val admitted = result.getOrElse { fail("$it") }
    if (!admitted.confirmed || group.computers.map { it.device } != listOf(admitted.device)) fail("the joiner did not confirm")
    println(Base64.getEncoder().encodeToString(group.groupCA))
}

fun main(args: Array<String>) {
    try {
        val port = args.getOrNull(2)?.toIntOrNull()
        when {
            args.size == 4 && args[0] == "member-tls" && port != null -> memberTLS(args[1], port, args[3])
            args.size == 4 && args[0] == "admit" && port != null -> admit(args[1], port, args[3], null)
            args.size == 5 && args[0] == "admit-tls" && port != null -> admit(args[1], port, args[3], args[4])
            args.size == 3 && args[0] == "invite-window" -> inviteWindow(Base64.getDecoder().decode(args[1]), args[2] == "yes")
            else -> {
                System.err.println("usage: clipboardbridge-interop admit HOST PORT CODE | admit-tls HOST PORT CODE FINGERPRINT | invite-window SECRET yes|no | member-tls HOST PORT PEER")
                exitProcess(2)
            }
        }
    } catch (e: Exception) {
        fail("$e")
    }
    exitProcess(0)
}
