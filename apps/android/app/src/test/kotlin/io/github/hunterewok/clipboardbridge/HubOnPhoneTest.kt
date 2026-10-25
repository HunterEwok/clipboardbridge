// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge

import io.github.hunterewok.clipboardbridge.kit.Member
import io.github.hunterewok.clipboardbridge.kit.PhoneHub
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList

class HubOnPhoneTest {
    private val phone = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    private val pc = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    private val tv = "cccccccccccccccccccccccccccccccc"
    private val pin = "sha256:" + "A".repeat(43)

    private class FakeHub(val memberPort: Int, var held: String) : HubTunnel {
        var registered: List<String>? = null
        var shown = ""
        var report = "{}"
        @Volatile var closed = false

        override fun setClients(json: String) {
            held = json
        }

        override fun register(endpoint: String, pin: String, chain: String, sign: (ByteArray) -> ByteArray, records: String) {
            registered = listOf(endpoint, pin, chain)
            shown = records
        }

        override fun setRecords(records: String) {
            shown = records
        }

        override fun status(): String = report

        override fun close() {
            closed = true
        }
    }

    private class FakeTunnels : HubTunnels {
        val started = CopyOnWriteArrayList<FakeHub>()
        override fun newKey(): ByteArray = ByteArray(32) { 7 }
        override fun publicKey(private: ByteArray): ByteArray = ByteArray(32) { 8 }
        override fun start(private: ByteArray, device: String, memberPort: Int, clients: String): HubTunnel =
            FakeHub(memberPort, clients).also { started.add(it) }
    }

    private fun group(records: List<Member.Record> = emptyList()) = HubOnPhone.Group(4242, listOf(ByteArray(3) { 1 }), { it }, records)

    @Test
    fun stateRoundTrips() {
        val s = HubState(
            ByteArray(32) { 1 }, on = true, forwarder = HubState.Forwarder("203.0.113.9:8764", pin), background = true,
            homes = listOf("192.168.0.1 192.168.0.0/24"), clients = listOf(PhoneHub.Client(pc, ByteArray(32) { 2 }, ByteArray(32) { 3 })),
        )
        val back = HubState.decode(s.encode())
        assertEquals(s, back)
        assertArrayEquals(s.clients[0].psk, back!!.clients[0].psk)
        assertNull(HubState.decode("{}".toByteArray()))
        assertNull(HubState.decode("not json".toByteArray()))
        assertNull(HubState.decode("""{"key":"AAAA"}""".toByteArray()))
    }

    @Test
    fun forwarderInput() {
        assertTrue(HubState.validPin(pin))
        assertTrue(HubState.validPin("sha256:" + "a-_9".repeat(10) + "abc"))
        assertFalse(HubState.validPin("sha256:" + "A".repeat(42)))
        assertFalse(HubState.validPin("sha1:" + "A".repeat(45)))
        assertFalse(HubState.validPin("sha256:" + "A".repeat(42) + "="))
        assertEquals("203.0.113.9:8764", HubState.resolve(" 203.0.113.9:8764 "))
        // IPv6 in brackets, which Go's netip reads in either form.
        val v6 = HubState.resolve("[2001:db8::9]:8764") ?: ""
        assertTrue(v6, v6.startsWith("[2001:db8:") && v6.endsWith("9]:8764"))
        assertNull(HubState.resolve("203.0.113.9"))
        assertNull(HubState.resolve("203.0.113.9:0"))
        assertNull(HubState.resolve(":8764"))
    }

    @Test
    fun networkKeys() {
        val gw = InetAddress.getByName("192.168.0.1")
        assertEquals("192.168.0.1 192.168.0.0/24", HubOnPhone.networkKey(gw, InetAddress.getByName("192.168.0.57"), 24))
        assertEquals("192.168.0.1 192.168.0.0/23", HubOnPhone.networkKey(gw, InetAddress.getByName("192.168.1.57"), 23))
        assertEquals("192.168.0.1 10.1.2.3/32", HubOnPhone.networkKey(gw, InetAddress.getByName("10.1.2.3"), 32))
        assertNull(HubOnPhone.networkKey(null, InetAddress.getByName("192.168.0.57"), 24))
        assertNull(HubOnPhone.networkKey(gw, InetAddress.getByName("192.168.0.57"), 33))
    }

    /** On with a forwarder: it offers the forwarder's endpoint, keeps the clients, and hands them and the records to the tunnel. */
    @Test
    fun servesWithAForwarder() {
        var saved: HubState? = null
        val tunnels = FakeTunnels()
        val h = HubOnPhone(phone, tunnels, load = { saved }, save = { saved = it })
        assertFalse(h.isOn)
        assertNull(h.offer(pc, ByteArray(32) { 2 }))
        h.turnOn("192.168.0.1 192.168.0.0/24")
        assertTrue(h.isOn)
        assertTrue(h.isHome("192.168.0.1 192.168.0.0/24"))
        assertFalse(h.isHome("10.0.0.1 10.0.0.0/24"))
        assertFalse(h.isHome(null))
        // At home only: no offer, nothing to register.
        assertEquals(HubOnPhone.Status.HOME_ONLY, h.status(paused = false).first)
        assertNull(h.offer(pc, ByteArray(32) { 2 }))
        h.start(group())
        assertTrue(tunnels.started.isEmpty())

        h.setForwarder(HubState.Forwarder("203.0.113.9:8764", pin))
        val o = requireNotNull(h.offer(pc, ByteArray(32) { 2 }))
        assertEquals(listOf("203.0.113.9:8764"), o.endpoints)
        assertArrayEquals(ByteArray(32) { 8 }, o.hubKey)
        assertEquals(listOf(pc), saved!!.clients.map { it.device })
        assertEquals(HubOnPhone.Status.PAUSED, h.status(paused = true).first)

        val rec = Member.Record(byteArrayOf(1), byteArrayOf(2))
        h.start(group(listOf(rec)))
        val t = tunnels.started.single()
        assertEquals(4242, t.memberPort)
        assertTrue(t.held.contains(pc))
        assertEquals("203.0.113.9:8764", t.registered!![0])
        assertTrue(t.shown.contains("\"body\""))
        h.start(group()) // running already
        assertEquals(1, tunnels.started.size)
        assertEquals(HubOnPhone.Status.REGISTERING, h.status(paused = false).first)
        t.report = """{"registered":true,"seen":"198.51.100.1:5555"}"""
        assertEquals(HubOnPhone.Status.REGISTERED, h.status(paused = false).first)
        t.report = """{"error":"the forwarder refused it"}"""
        assertEquals(HubOnPhone.Status.FAILED to "the forwarder refused it", h.status(paused = false))

        // A new client reaches the running tunnel; a removed one leaves it.
        h.offer(tv, ByteArray(32) { 4 })
        assertTrue(t.held.contains(tv))
        assertEquals(listOf(pc), h.prune { it != pc })
        assertFalse(t.held.contains(pc))
        assertEquals(listOf(tv), saved!!.clients.map { it.device })
        h.setRecords(emptyList())
        assertEquals("[]", t.shown)

        // A new forwarder stops the tunnel; turning it off stops it and keeps the clients.
        h.setForwarder(HubState.Forwarder("203.0.113.10:8764", pin))
        assertTrue(t.closed)
        h.start(group())
        h.turnOff()
        assertTrue(tunnels.started.last().closed)
        assertEquals(HubOnPhone.Status.OFF, h.status(paused = false).first)
        assertEquals(listOf(tv), HubOnPhone(phone, FakeTunnels(), load = { saved }, save = {}).clients)
    }

    @Test
    fun remembersAFewHomes() {
        var saved: HubState? = null
        val h = HubOnPhone(phone, FakeTunnels(), load = { saved }, save = { saved = it })
        h.turnOn(null)
        for (i in 1..HubState.MAX_HOMES + 2) h.addHome("home $i")
        assertEquals(HubState.MAX_HOMES, saved!!.homes.size)
        assertFalse(h.isHome("home 1"))
        assertTrue(h.isHome("home ${HubState.MAX_HOMES + 2}"))
        h.setBackground(true)
        assertTrue(h.background)
    }
}
