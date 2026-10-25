// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import java.io.File
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CommandsTest {
    private val now = Instant.now()
    private val pc = "00112233445566778899aabbccddeeff"

    @Test
    fun modeCommand() {
        val root = SoftwareSigner()
        val ca = GroupCertificates.groupCA(root, now, pathLength = 1)
        val c = Commands.mode(pc, "own", GroupCertificates.tag(ca), "0123456789abcdef0123456789abcdef", now, root)
        val o = Wire.parse(c.body)!!
        assertEquals("mode", o.optString("type"))
        assertEquals(pc, o.optString("to"))
        assertEquals(Commands.LIFETIME_MS, o.optLong("expires_ms")!! - o.optLong("time_ms")!!)
        assertEquals(32, Commands.idOf(c)!!.length)
        assertNull(c.chain)
        assertFailsWith<IllegalArgumentException> { Commands.mode(pc, "everything", "tag", "by", now, root) }
    }

    /** A phone group signs a mode command with its root key, for its own group. */
    @Test
    fun phoneGroupModeCommand() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now)
        val c = g.modeCommand(pc, "receive", rootKey, now)
        val o = Wire.parse(c.body)!!
        assertEquals(g.tag, o.optString("group"))
        assertEquals(g.device, o.optString("by"))
        assertEquals("receive", o.optString("mode"))
        assertNull(c.chain)
    }

    /** A hub command carries the forwarder and the clients; a result carries the new hub's offer. */
    @Test
    fun hubCommand() {
        val root = SoftwareSigner()
        val client = PhoneHub.Client("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val c = Commands.hub(pc, "203.0.113.9:8764" to "sha256:AAAA", emptyList(), listOf(client), "tag", "by", now, root)
        val o = Wire.parse(c.body)!!
        assertEquals("hub", o.optString("type"))
        val order = o.optObject("hub")!!
        assertEquals("203.0.113.9:8764", order.optObject("forwarder")!!.optString("endpoint"))
        assertEquals(1, order.optArray("clients")!!.size)
        assertFailsWith<IllegalArgumentException> { Commands.hub(pc, null, emptyList(), listOf(client), "tag", "by", now, root) }
        val r = Member.decode(
            """{"t":"result","result":{"id":"ab","status":"done","tunnel":{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","endpoints":["203.0.113.9:8764"]}}}""".toByteArray(),
        ) as Member.Message.Result
        assertEquals(listOf("203.0.113.9:8764"), r.result.tunnel?.endpoints)
        val hub = PhoneHub(ByteArray(32) { 9 }, listOf(client))
        val moved = hub.movedOffer(client.device, pc, r.result.tunnel!!)!!
        assertEquals(pc, moved.hub)
        assertTrue(moved.moved)
        assertEquals(client.psk.toList(), moved.psk.toList())
        assertNull(hub.movedOffer(pc, pc, r.result.tunnel!!))
        val back = Member.decode(Member.encode(Member.Message.Tunnel(moved)).let { it.copyOfRange(4, it.size) }) as Member.Message.Tunnel
        assertEquals(moved, back.offer)
    }

    /** A command and its result through the frames, as Go sends and reads them. */
    @Test
    fun messages() {
        val c = Member.Record("{}".toByteArray(), byteArrayOf(1, 2), listOf(byteArrayOf(3)))
        for (m in listOf(Member.Message.Command(c), Member.Message.Result(Member.CommandResult("ab", "refused", "why")))) {
            val e = Member.encode(m)
            assertEquals(m, Member.decode(e.copyOfRange(4, e.size)))
        }
        val h = Member.decode("""{"t":"hello","role":"full","hello":{"wall_ms":1,"mode":"receive"}}""".toByteArray()) as Member.Message.Hello
        assertEquals("receive", h.hello.mode)
        val odd = Member.decode("""{"t":"hello","role":"full","hello":{"wall_ms":1,"mode":"everything"}}""".toByteArray()) as Member.Message.Hello
        assertNull(odd.hello.mode)
    }

    /** A command goes to the named peer, and its result comes back; a phone refuses commands. */
    @Test
    fun commandRoundTrip() {
        val (pa, pb) = Pipe.pair()
        val a = MemberNode(SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock()), "Pixel")
        val b = MemberNode(SyncEngine("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", HybridClock()), "Phone two")
        val ta = Background { a.serve(pa, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") }
        val tb = Background { b.serve(pb, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") }
        waitUntil { a.peers == 1 }
        val c = Commands.mode("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "own", "tag", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now, SoftwareSigner())
        val r = a.command("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", c)
        assertEquals(Commands.idOf(c), r.id)
        assertEquals("refused", r.status)
        assertFailsWith<MemberNode.ProtocolException> { a.command("cccccccccccccccccccccccccccccccc", c) }
        a.closeAll()
        ta.join()
        tb.join()
    }

    /**
     * Writes mode commands this kit signed, with the root key and with an
     * admin CA's, for internal/group's TestSwiftCommand, under the Swift
     * kit's file name, when CBB_INTEROP_OUT names a directory.
     */
    @Test
    fun commandsForGo() {
        val dir = Interop.out ?: return
        val root = SoftwareSigner()
        val ca = GroupCertificates.groupCA(root, now, pathLength = 1)
        val tag = GroupCertificates.tag(ca)
        val admin = SoftwareSigner()
        val adminCA = GroupCertificates.adminCA("fedcba9876543210fedcba9876543210", admin.publicKeyDER, ca, root)
        val by = "0123456789abcdef0123456789abcdef"
        val out = Wire.obj(
            "group_ca" to Wire.bytes(ca),
            "to" to Wire.str(pc),
            "commands" to JsonArray(
                listOf(
                    Commands.mode(pc, "receive", tag, by, now, root).toJson(),
                    Commands.mode(pc, "receive", tag, by, now, admin, adminCA).toJson(),
                    Commands.hub(
                        pc,
                        "203.0.113.9:8764" to "sha256:AAAA",
                        emptyList(),
                        listOf(PhoneHub.Client("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ByteArray(32) { 1 }, ByteArray(32) { 2 })),
                        tag,
                        by,
                        now,
                        root,
                    ).toJson(),
                ),
            ),
        )
        File(dir, "swift-command.json").writeBytes(Wire.encode(out))
    }
}
