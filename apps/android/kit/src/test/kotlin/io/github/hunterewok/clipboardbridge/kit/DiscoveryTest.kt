// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge.kit

import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DiscoveryTest {
    private val dev = "0123456789abcdef0123456789abcdef"

    @Test
    fun txt() {
        assertEquals(FoundMember(dev, "0011223344556677", true), Discovery.member(dev, listOf("v=1", "g=0011223344556677", "p=1")))
        // Keys without regard to case, the value after the first "=", the first of a repeated key.
        assertEquals(FoundMember(dev, "a=b", false), Discovery.member(dev, listOf("G=a=b", "g=other", "x")))
        assertNull(Discovery.member(dev, emptyList<String>())?.group)
        assertEquals(FoundMember(dev, "77"), Discovery.member(dev, mapOf("g" to "77".toByteArray(), "p" to "0".toByteArray(), "x" to null)))
        assertNull(Discovery.member("printer", listOf("g=77")))
        assertNull(Discovery.member(dev.uppercase(), listOf("g=77")))
    }

    @Test
    fun dialer() {
        val phone = MemberNode(SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock()), "Pixel")
        phone.send("from the phone", Member.Kind.TEXT)
        val pi = MemberNode(SyncEngine(dev, HybridClock()), "pi", Member.Role.FULL)
        val dials = java.util.Collections.synchronizedList(mutableListOf<String>())
        val d = MemberDialer(phone, "g1", 50, 200) { m ->
            dials.add(m.device)
            val (mine, theirs) = Pipe.pair()
            // The pi serves the connection, then hangs up after a moment.
            Thread {
                Thread.sleep(30)
                theirs.close()
            }.start()
            Thread { runCatching { pi.serve(theirs) } }.start()
            mine
        }
        val other = FoundMember("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "another group")
        d.update(setOf(FoundMember(dev, "g1"), other))
        // It dials again after each end, and the pi got the phone's text.
        waitUntil { dials.size >= 3 }
        assertEquals("from the phone", pi.usable?.first)
        assertFalse(other.device in dials, "dialed a member of another group")
        // A member no longer found is not dialed again.
        d.update(emptySet())
        waitUntil { d.dialing.isEmpty() }
        val n = dials.size
        Thread.sleep(300)
        assertEquals(n, dials.size)
        // Found again, it is dialed again; stop ends that.
        d.update(setOf(FoundMember(dev, "g1")))
        waitUntil { dials.size > n }
        d.stop()
        assertTrue(d.dialing.isEmpty())
    }

    @Test
    fun dialFailuresBackOff() {
        val phone = MemberNode(SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock()), null)
        val tries = AtomicInteger()
        val d = MemberDialer(phone, "g1", 50, 400) {
            tries.incrementAndGet()
            throw IOException("refused")
        }
        d.update(setOf(FoundMember(dev, "g1")))
        Thread.sleep(700)
        d.stop()
        // 0.05 + 0.1 + 0.2 + 0.4 ...: about five tries in 0.7 s, not dozens.
        assertTrue(tries.get() in 3..6, "${tries.get()} tries")
    }
}
