// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge

import io.github.hunterewok.clipboardbridge.kit.FrameTransport
import io.github.hunterewok.clipboardbridge.kit.Member
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class AwayFromHomeTest {
    private val hub = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    private val offer = Member.TunnelOffer(ByteArray(32) { 2 }, ByteArray(32) { 3 }, listOf("203.0.113.7:8764", "[2001:db8::7]:8764"))

    @Test
    fun stateRoundTrips() {
        val key = ByteArray(32) { 1 }
        val off = AwayState.decode(AwayState(key).encode())
        assertNotNull(off)
        assertArrayEquals(key, off!!.key)
        assertNull(off.hub)
        assertNull(off.offer)

        val on = AwayState.decode(AwayState(key).withOffer(hub, offer).encode())
        assertNotNull(on)
        assertEquals(hub, on!!.hub)
        assertEquals(offer, on.offer)

        // An obfuscated hub's settings are kept as they came.
        val hidden = Member.TunnelOffer(offer.hubKey, offer.psk, offer.endpoints, """{"jc":4,"s1":20}""")
        assertEquals(hidden, AwayState.decode(AwayState(key).withOffer(hub, hidden).encode())!!.offer)

        // Another version, a cut file and a bad offer are not states.
        val b = AwayState(key).withOffer(hub, offer).encode()
        assertNull(AwayState.decode(byteArrayOf(9) + b.copyOfRange(1, b.size)))
        assertNull(AwayState.decode(b.copyOf(b.size - 3)))
        assertNull(AwayState.decode(AwayState(key).withOffer(hub, Member.TunnelOffer(ByteArray(31), ByteArray(32))).encode()))
    }

    private class FakeTunnel(override val port: Int, val endpoint: String, val obfuscation: String = "") : OpenTunnel {
        val endpoints = CopyOnWriteArrayList(listOf(endpoint))
        @Volatile var closed = false
        override fun setEndpoint(endpoint: String) {
            endpoints.add(endpoint)
        }
        override fun close() {
            closed = true
        }
    }

    private class FakeTunnels : Tunnels {
        val started = LinkedBlockingQueue<FakeTunnel>()
        override fun newKey() = ByteArray(32) { 7 }
        override fun publicKey(private: ByteArray) = private.map { (it + 1).toByte() }.toByteArray()
        override fun start(
            private: ByteArray,
            psk: ByteArray,
            hubKey: ByteArray,
            device: String,
            hub: String,
            endpoint: String,
            obfuscation: String,
        ): OpenTunnel = FakeTunnel(40_000 + started.size, endpoint, obfuscation).also { started.add(it) }
    }

    private object NoTransport : FrameTransport {
        override fun write(data: ByteArray) = Unit
        override fun read(n: Int): ByteArray = throw IOException("closed")
        override fun close() = Unit
    }

    private fun eventually(what: String, check: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5_000
        while (!check()) {
            if (System.currentTimeMillis() > deadline) throw AssertionError(what)
            Thread.sleep(5)
        }
    }

    @Test
    fun reachesTheHubOnlyWhileItIsAway() {
        val tunnels = FakeTunnels()
        val saved = AtomicReference<AwayState?>(null)
        val home = AtomicBoolean(false)
        val answers = AtomicBoolean(false)
        val dialed = LinkedBlockingQueue<Pair<Int, String>>()
        val served = LinkedBlockingQueue<String>()
        val release = LinkedBlockingQueue<Unit>()
        val a = AwayFromHome(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tunnels,
            load = { null },
            save = { saved.set(it) },
            atHome = { home.get() },
            dial = { port, h ->
                dialed.add(port to h)
                if (!answers.get()) throw IOException("no answer")
                NoTransport
            },
            serve = { _, h ->
                served.add(h)
                release.poll(5, TimeUnit.SECONDS)
            },
            firstWaitMS = 10,
            maxWaitMS = 20,
            homeCheckMS = 10,
        )
        a.start()
        try {
            // Off: no key for the hellos, no tunnel.
            assertFalse(a.isOn)
            assertNull(a.publicKey)
            eventually("off") { a.status == AwayFromHome.Status.OFF }

            a.turnOn()
            assertTrue(a.isOn)
            assertArrayEquals(ByteArray(32) { 8 }, a.publicKey)
            assertNotNull(saved.get())
            eventually("waiting for the hub") { a.status == AwayFromHome.Status.WAITING_FOR_HUB }
            assertTrue(tunnels.started.isEmpty())

            // The hub's answer, from a peer the node named: away, the tunnel starts on its first endpoint.
            a.keep(null, offer)
            a.keep(hub, offer)
            assertEquals(hub, saved.get()?.hub)
            val t = tunnels.started.poll(5, TimeUnit.SECONDS)!!
            assertEquals(offer.endpoints[0], t.endpoint)
            assertEquals("", t.obfuscation)
            assertEquals(t.port to hub, dialed.poll(5, TimeUnit.SECONDS))
            // No answer: the next endpoint, on the same tunnel.
            eventually("the next endpoint") { t.endpoints.contains(offer.endpoints[1]) }
            assertTrue(tunnels.started.isEmpty())

            answers.set(true)
            assertEquals(hub, served.poll(5, TimeUnit.SECONDS))
            assertEquals(AwayFromHome.Status.CONNECTED, a.status)

            // At home the tunnel closes and the phone dials the hub directly.
            home.set(true)
            release.add(Unit)
            eventually("at home") { a.status == AwayFromHome.Status.AT_HOME }
            assertTrue(t.closed)

            // Away again: a new tunnel.
            home.set(false)
            val t2 = tunnels.started.poll(5, TimeUnit.SECONDS)!!
            assertEquals(hub, served.poll(5, TimeUnit.SECONDS))

            // Off: the tunnel closes and the state is forgotten.
            a.turnOff()
            release.add(Unit)
            assertTrue(t2.closed)
            assertNull(saved.get())
            assertNull(a.publicKey)
            eventually("off again") { a.status == AwayFromHome.Status.OFF }
        } finally {
            a.stop()
        }
    }

    @Test
    fun aNewOfferStartsAgain() {
        val tunnels = FakeTunnels()
        val release = LinkedBlockingQueue<Unit>()
        val a = AwayFromHome(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tunnels,
            load = { AwayState(ByteArray(32) { 1 }).withOffer(hub, offer) },
            save = {},
            atHome = { false },
            dial = { _, _ -> NoTransport },
            serve = { _, _ -> release.poll(5, TimeUnit.SECONDS) },
            firstWaitMS = 10,
            maxWaitMS = 20,
        )
        a.start()
        try {
            val t = tunnels.started.poll(5, TimeUnit.SECONDS)!!
            eventually("connected") { a.status == AwayFromHome.Status.CONNECTED }
            // The same offer again changes nothing; a new one closes the tunnel and starts with it.
            a.keep(hub, offer)
            assertFalse(t.closed)
            val moved = Member.TunnelOffer(offer.hubKey, offer.psk, listOf("198.51.100.9:8764"))
            a.keep(hub, moved)
            assertTrue(t.closed)
            release.add(Unit)
            val t2 = tunnels.started.poll(5, TimeUnit.SECONDS)!!
            assertEquals("198.51.100.9:8764", t2.endpoint)
        } finally {
            a.stop()
        }
    }
}
