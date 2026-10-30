// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
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

    /** A phone group signs a paste command with its root key, its way and kind in the body. */
    @Test
    fun phoneGroupPasteCommand() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now)
        val c = g.pasteCommand(pc, "ls", "type", enter = true, secret = true, caSigner = rootKey, now = now)
        val o = Wire.parse(c.body)!!
        assertEquals("paste", o.optString("type"))
        assertEquals(g.tag, o.optString("group"))
        assertEquals("type", o.optString("mode"))
        assertEquals("secret", o.optString("kind"))
        assertEquals("ls", o.optString("text"))
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

    /** A paste command carries its way, Enter, kind and text, within the limits; paste-off carries nothing. */
    @Test
    fun pasteCommand() {
        val root = SoftwareSigner()
        val ca = GroupCertificates.groupCA(root, now, pathLength = 1)
        val c = Commands.paste(pc, "ls <dir>", enter = true, kind = "secret", group = GroupCertificates.tag(ca), by = pc, now = now, signer = root)
        val o = Wire.parse(c.body)!!
        assertEquals("paste", o.optString("type"))
        assertEquals("paste", o.optString("mode"))
        assertEquals("ls <dir>", o.optString("text"))
        assertEquals("secret", o.optString("kind"))
        assertEquals(true, o.optBool("enter"))
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, "", group = "t", by = pc, now = now, signer = root) }
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, "x".repeat(Commands.MAX_TYPE_TEXT + 1), "type", group = "t", by = pc, now = now, signer = root) }
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, "x", "drop", group = "t", by = pc, now = now, signer = root) }
        val off = Wire.parse(Commands.pasteOff(pc, "t", pc, now, root).body)!!
        assertEquals("paste-off", off.optString("type"))
        assertNull(off.opt("text"))
    }

    /** A command for a member this one is not connected to goes through one that is, and the result comes back. */
    @Test
    fun commandPassedOn() {
        val (ia, ib, ih) = listOf("a", "b", "c").map { it.repeat(32) }
        val got = mutableListOf<String>()
        val a = MemberNode(SyncEngine(ia, HybridClock()), "Pixel")
        val hub = MemberNode(SyncEngine(ih, HybridClock()), "Hub", onCommand = { _, _ -> synchronized(got) { got += "hub" }; Member.CommandResult("", "done") })
        val b = MemberNode(SyncEngine(ib, HybridClock()), "Phone two", onCommand = { _, c -> synchronized(got) { got += "b" }; Member.CommandResult(Commands.idOf(c)!!, "done") })
        val (p1, p2) = Pipe.pair()
        val (p3, p4) = Pipe.pair()
        val ts = listOf(
            Background { a.serve(p1, ih) },
            Background { hub.serve(p2, ia) },
            Background { b.serve(p3, ih) },
            Background { hub.serve(p4, ib) },
        )
        waitUntil { a.peers == 1 && b.peers == 1 && hub.peers == 2 }
        val c = Commands.mode(ib, "own", "tag", ia, Instant.now(), SoftwareSigner())
        assertFailsWith<MemberNode.ProtocolException> { a.command(ib, c) }
        // Only through the hubs.
        assertFailsWith<MemberNode.ProtocolException> { a.command(ib, c, via = listOf("d")) }
        val r = a.command(ib, c, via = listOf("d", ih))
        assertEquals("done", r.status)
        assertEquals(ib, r.by)
        assertEquals(listOf("b"), synchronized(got) { got.toList() })
        // The hub passes the same command on once only.
        assertFailsWith<MemberNode.ProtocolException> { a.command(ib, c, timeoutMS = 300, via = listOf(ih)) }
        assertEquals(listOf("b"), synchronized(got) { got.toList() })
        a.closeAll()
        b.closeAll()
        hub.closeAll()
        ts.forEach { it.join() }
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
                    Commands.paste(pc, "echo <ok> & \"done\"\n", "type", enter = true, group = tag, by = by, now = now, signer = admin, adminCA = adminCA).toJson(),
                    Commands.pasteOff(pc, tag, by, now, root).toJson(),
                    Commands.action(pc, "lock", tag, by, now, admin, adminCA).toJson(),
                    Commands.actionsOff(pc, tag, by, now, root).toJson(),
                ),
            ),
        )
        File(dir, "swift-command.json").writeBytes(Wire.encode(out))
    }

    /** testdata/interop/go-commands.json, from Go's TestGoCommandVectors: which commands for this phone count. */
    @Test
    fun goCommands() {
        val v = Interop.read("go-commands.json").jsonObject
        val set = RecordSet()
        val records = v.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }
        assertEquals(records.size, set.addAll(records, b64(v.str("group_ca"))).size)
        val now = v.getValue("now_ms").jsonPrimitive.long
        val commands = v.getValue("commands").jsonArray.map { it.jsonObject }
        assertEquals(14, commands.size)
        for (c in commands) {
            val name = c.str("name")
            val got = runCatching { Commands.verify(Member.Record.fromJson(c.getValue("command").jsonObject), set, v.str("self"), now) }
            assertEquals(c.getValue("ok").jsonPrimitive.boolean, got.isSuccess, "$name: ${got.exceptionOrNull()?.message}")
            got.getOrNull()?.let { assertEquals(c["mode"]?.jsonPrimitive?.content, it.mode, name) }
            got.getOrNull()?.takeIf { it.type == "paste" }?.let { assertTrue(it.enter && it.kind == "text" && it.text!!.endsWith("\"done\"\n"), name) }
        }
    }

    /** testdata/interop/go-actions.json, from Go's TestGoActionVectors: action commands for a member, as Go checks them. */
    @Test
    fun goActions() {
        val v = Interop.read("go-actions.json").jsonObject
        val set = RecordSet()
        val records = v.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }
        assertEquals(records.size, set.addAll(records, b64(v.str("group_ca"))).size)
        val now = v.getValue("now_ms").jsonPrimitive.long
        val commands = v.getValue("commands").jsonArray.map { it.jsonObject }
        assertEquals(6, commands.size)
        for (c in commands) {
            val name = c.str("name")
            val got = runCatching { Commands.verify(Member.Record.fromJson(c.getValue("command").jsonObject), set, v.str("self"), now) }
            assertEquals(c.getValue("ok").jsonPrimitive.boolean, got.isSuccess, "$name: ${got.exceptionOrNull()?.message}")
            got.getOrNull()?.let { assertEquals(c["action"]?.jsonPrimitive?.content, it.action, name) }
        }
    }

    @Test
    fun actionCommands() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now)
        val o = Wire.parse(g.actionCommand(pc, "reboot", rootKey, now).body)!!
        assertEquals("action", o.optString("type"))
        assertEquals("reboot", o.optString("action"))
        assertEquals("actions-off", Wire.parse(g.actionsOffCommand(pc, rootKey, now).body)!!.optString("type"))
        assertFailsWith<IllegalArgumentException> { g.actionCommand(pc, "Reboot now", rootKey, now) }
        assertTrue(Commands.validActionName("cancel-shutdown"))
        for (bad in listOf("", "-x", "1x", "X", "a".repeat(33), "a b")) assertTrue(!Commands.validActionName(bad), bad)
    }

    /** The reason of a result is shown to a person: short, without control characters. */
    @Test
    fun cleanReason() {
        assertEquals("the screen is locked", Member.cleanReason("the screen is locked"))
        assertEquals("", Member.cleanReason(""))
        assertEquals("a [2Jb ]52;c;ZXZpbA== c", Member.cleanReason("a\u001b[2Jb\u001b]52;c;ZXZpbA==\u0007c"))
        assertEquals("a b c ", Member.cleanReason("a\nb\tc\r"))
        assertEquals("a b", Member.cleanReason("a\u009bb"))
        assertEquals("écran verrouillé", Member.cleanReason("écran verrouillé"))
        assertEquals(Member.MAX_REASON, Member.cleanReason("a".repeat(1000)).toByteArray().size)
        // A character that would cross the limit goes whole.
        assertEquals("a".repeat(Member.MAX_REASON - 1), Member.cleanReason("a".repeat(Member.MAX_REASON - 1) + "é"))
        assertTrue(Member.cleanReason("é".repeat(300)).toByteArray().size <= Member.MAX_REASON)
    }
}
