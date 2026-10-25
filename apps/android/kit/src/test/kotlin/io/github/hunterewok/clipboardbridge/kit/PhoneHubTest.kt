// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge.kit

import java.time.Instant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The phone as the group's hub: admitting clients by their tunnel keys, and the offers over member TLS. */
class PhoneHubTest {
    private val now = Instant.now()

    private fun key(b: Int) = ByteArray(32) { b.toByte() }

    @Test
    fun admitsAsAComputersHub() {
        val hub = PhoneHub(key(1))
        val a = SyncEngine.newID()
        val b = SyncEngine.newID()
        val (first, changed) = hub.admit(a, key(2))
        assertTrue(changed)
        assertEquals(32, first.psk.size)

        // The same key keeps its preshared key; a new key gets a new one.
        val (same, unchanged) = hub.admit(a, key(2))
        assertFalse(unchanged)
        assertContentEquals(first.psk, same.psk)
        val (renewed, _) = hub.admit(a, key(3))
        assertFalse(renewed.psk.contentEquals(first.psk))
        assertEquals(1, hub.clients.size)

        // Another device's key, the hub's own, no key, and a bad device are refused.
        assertFailsWith<PhoneHub.Refused> { hub.admit(b, key(3)) }
        assertFailsWith<PhoneHub.Refused> { hub.admit(b, key(1)) }
        assertFailsWith<PhoneHub.Refused> { hub.admit(b, key(0)) }
        assertFailsWith<PhoneHub.Refused> { hub.admit(b, ByteArray(31)) }
        assertFailsWith<PhoneHub.Refused> { hub.admit("B", key(4)) }

        // The clients go to cbbtun as JSON and come back from it.
        hub.admit(b, key(4))
        val back = PhoneHub.clientsFromJson(hub.clientsJson)
        assertEquals(listOf(a, b), back.map { it.device })
        assertContentEquals(hub.clients[1].psk, back[1].psk)
        assertTrue(PhoneHub.clientsFromJson("").isEmpty())
        assertFailsWith<IllegalArgumentException> { PhoneHub.clientsFromJson("{}") }
        assertFailsWith<IllegalArgumentException> { PhoneHub.clientsFromJson("""[{"device":"x"}]""") }

        assertEquals(listOf(a), hub.prune { it.device != a })
        assertEquals(listOf(b), hub.clients.map { it.device })
    }

    @Test
    fun keepsAtMost256Clients() {
        val hub = PhoneHub(key(1))
        repeat(PhoneHub.MAX_CLIENTS) { i -> hub.admit(SyncEngine.newID(), key(7).also { it[0] = i.toByte(); it[1] = (i shr 8).toByte() }) }
        assertFailsWith<PhoneHub.Refused> { hub.admit(SyncEngine.newID(), key(9)) }
    }

    @Test
    fun offersWaitForVLESS() {
        val hub = PhoneHub(key(1))
        hub.endpoints = listOf("203.0.113.1:8764")
        val c = hub.admit(SyncEngine.newID(), key(2)).first
        val o = assertNotNull(hub.offer(c))
        assertTrue(o.isValid)
        assertEquals(listOf("203.0.113.1:8764"), o.endpoints)
        hub.vlessOnly = true
        assertNull(hub.offer(c))
        hub.vless = """{"endpoint":"203.0.113.1:443"}"""
        assertEquals(hub.vless, hub.offer(c)?.vless)
    }

    /**
     * A computer dials the phone's member listener with a tunnel key in its
     * hello and gets the hub's offer; the hub ignores an offer it gets.
     */
    @Test
    fun answersTheTunnelKeyOverTLS() {
        val caKey = SoftwareSigner()
        val ca = GroupCertificates.groupCA(caKey, now, pathLength = 1)
        fun member(): Triple<String, SoftwareSigner, ByteArray> {
            val id = SyncEngine.newID()
            val k = SoftwareSigner()
            return Triple(id, k, GroupCertificates.member(id, k.publicKeyDER, ca, caKey, now))
        }
        val (phoneID, phoneKey, phoneCert) = member()
        val (pcID, pcKey, pcCert) = member()
        val hub = PhoneHub(key(1))
        hub.endpoints = listOf("203.0.113.1:8764")
        val saved = LinkedBlockingQueue<List<PhoneHub.Client>>()
        val phone = MemberNode(
            SyncEngine(phoneID, HybridClock()), "Pixel",
            tunnelKey = { key(5) },
            onTunnel = { _, _ -> error("the hub took an offer") },
            hub = { device, k, _ -> hub.offer(device, k, changed = { saved.add(it) }) },
        )
        val errors = LinkedBlockingQueue<Exception>()
        val listener = MemberListener(phone, phoneKey.keyPair.private, listOf(phoneCert), { listOf(ca) }, onError = { errors.add(it) })
        val offers = LinkedBlockingQueue<Pair<String?, Member.TunnelOffer>>()
        val pc = MemberNode(SyncEngine(pcID, HybridClock()), "PC", role = Member.Role.FULL, tunnelKey = { key(2) }, onTunnel = { p, o -> offers.add(p to o) })
        try {
            val t = TLSTransport.dial("127.0.0.1", listener.port, Member.ALPN, pcKey.keyPair.private, listOf(pcCert)) {
                runCatching { GroupCertificates.verifyMember(it, listOf(ca), now) }.getOrNull() == phoneID
            }
            val dialled = Background { pc.serve(t, phoneID) }
            val (from, offer) = assertNotNull(offers.poll(10, TimeUnit.SECONDS))
            assertEquals(phoneID, from)
            assertContentEquals(key(1), offer.hubKey)
            assertEquals(listOf("203.0.113.1:8764"), offer.endpoints)
            val client = assertNotNull(saved.poll(1, TimeUnit.SECONDS)).single()
            assertEquals(pcID, client.device)
            assertContentEquals(client.psk, offer.psk)
            waitUntil { phone.connected == setOf(pcID) }
            pc.closeAll()
            dialled.join()
        } finally {
            listener.stop()
        }
        assertTrue(errors.isEmpty(), "the listener failed: ${errors.peek()}")
    }

    /** A peer whose certificate is not the group's gets no connection. */
    @Test
    fun refusesAStranger() {
        val caKey = SoftwareSigner()
        val ca = GroupCertificates.groupCA(caKey, now, pathLength = 1)
        val otherKey = SoftwareSigner()
        val other = GroupCertificates.groupCA(otherKey, now, pathLength = 1)
        val phoneKey = SoftwareSigner()
        val phoneID = SyncEngine.newID()
        val phoneCert = GroupCertificates.member(phoneID, phoneKey.publicKeyDER, ca, caKey, now)
        val strangerKey = SoftwareSigner()
        val strangerCert = GroupCertificates.member(SyncEngine.newID(), strangerKey.publicKeyDER, other, otherKey, now)
        val phone = MemberNode(SyncEngine(phoneID, HybridClock()), "Pixel")
        val listener = MemberListener(phone, phoneKey.keyPair.private, listOf(phoneCert), { listOf(ca) })
        try {
            assertFailsWith<java.io.IOException> {
                val t = TLSTransport.dial("127.0.0.1", listener.port, Member.ALPN, strangerKey.keyPair.private, listOf(strangerCert)) { true }
                // TLS 1.3 may finish on the client before the server refuses it.
                t.read(4)
            }
            assertEquals(0, phone.peers)
        } finally {
            listener.stop()
        }
    }
}
