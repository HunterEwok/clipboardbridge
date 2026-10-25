// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RecordsTest {
    private val now = Instant.now()

    /** A device ID whose records name two keys stays listed while either is not revoked, as Go's TestDeviceWithTwoKeys. */
    @Test
    fun deviceWithTwoKeys() {
        val g = Group(now)
        val k1 = Records.keyHash(SoftwareSigner().publicKeyDER)
        val k2 = Records.keyHash(SoftwareSigner().publicKeyDER)
        val set = RecordSet()
        val dev = "00112233445566778899aabbccddeeff"
        set.add(Records.device(dev, "pc", "full", k1, g.tag, g.phone, now, g.rootKey), g.ca)
        set.add(Records.device(dev, "pc", "full", k2, g.tag, g.phone, now.plusSeconds(1), g.rootKey), g.ca)
        assertTrue(set.knows(dev))
        assertEquals(2, set.devices.single().keys.size)
        set.add(Records.revoke(listOf(k2), g.tag, g.phone, now, g.rootKey), g.ca)
        assertContentEquals(k1, set.devices.single().key)
        set.add(Records.revoke(set.devices.single().keys, g.tag, g.phone, now.plusSeconds(2), g.rootKey), g.ca)
        assertTrue(set.devices.isEmpty())
    }

    /** A phone's root, its own record and a computer's. */
    private class Group(now: Instant) {
        val rootKey = SoftwareSigner()
        val ca = GroupCertificates.groupCA(rootKey, now, pathLength = 1)
        val tag = GroupCertificates.tag(ca)
        val phone = "0123456789abcdef0123456789abcdef"
        val pc = "fedcba9876543210fedcba9876543210"
        val phoneKey = SoftwareSigner().publicKeyDER
        val pcCert = GroupCertificates.member(pc, SoftwareSigner().publicKeyDER, ca, rootKey, now)
        val set = RecordSet()

        init {
            set.add(Records.device(phone, "My phone", "phone", Records.keyHash(phoneKey), tag, phone, now, rootKey), ca)
            set.add(Records.device(pc, "pi", "linux", Records.keyHashOfCert(pcCert), tag, phone, now, rootKey), ca)
        }
    }

    @Test
    fun devicesAndRevoke() {
        val g = Group(now)
        assertEquals(listOf("My phone", "pi"), g.set.devices.map { it.name })
        assertEquals(g.phone, g.set.rootDevice)
        val digest = g.set.digest
        assertTrue(g.set.add(Records.revoke(listOf(Records.keyHashOfCert(g.pcCert)), g.tag, g.phone, now, g.rootKey), g.ca))
        assertEquals(listOf(g.phone), g.set.devices.map { it.id })
        assertNotEquals(digest, g.set.digest)
        assertEquals("the device was removed from the group", g.set.refused(listOf(g.pcCert)))

        val kept = RecordSet.fromJson(g.set.toJson())
        assertEquals(g.set.digest, kept.digest)
        assertContentEquals(g.ca, kept.groupCA)
    }

    @Test
    fun refused() {
        val g = Group(now)
        val set = RecordSet()
        val good = g.set.records[0]
        val forged = Member.Record(good.body, good.sig.reversedArray())
        val tampered = Member.Record(String(good.body).replace("phone", "linux").toByteArray(), good.sig)
        val chained = Member.Record(good.body, good.sig, listOf(byteArrayOf(1)))
        for (r in listOf(forged, tampered, chained)) assertFalse(set.add(r, g.ca))
        assertFalse(set.add(good, GroupCertificates.groupCA(SoftwareSigner(), now, pathLength = 1)))
        assertTrue(set.add(good, g.ca))
        assertFalse(set.add(good, g.ca), "a known record is not new")
    }

    /** testdata/interop/go-root.json, a handover that Go's TestGoRootVectors wrote, and what Go makes of it. */
    @Test
    fun goHandover() {
        val v = Interop.read("go-root.json").jsonObject
        val records = v.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }
        val set = RecordSet()
        assertEquals(records.size, set.addAll(records, b64(v.str("group_ca"))).size)
        assertEquals(v.str("digest"), set.digest)
        assertEquals(v.getValue("roots").jsonArray.map { it.jsonPrimitive.content }, set.roots.map { b64(it) })
        val devices = v.getValue("devices").jsonArray.map { it.jsonObject }
        assertEquals(devices.map { it.str("id") }, set.devices.map { it.id })
        assertEquals(devices.map { it.str("name") }, set.devices.map { it.name })
        assertEquals(devices.map { it.getValue("admin").jsonPrimitive.boolean }, set.devices.map { it.admin })
        for (c in v.getValue("chains").jsonArray) {
            val o = c.jsonObject
            val chain = o.getValue("chain").jsonArray.map { b64(it.jsonPrimitive.content) }
            assertEquals(o.getValue("refused").jsonPrimitive.boolean, set.refused(chain) != null, o.str("name"))
        }
    }

    /**
     * testdata/interop/go-admins.json, from Go's TestGoAdminVectors: a
     * computer's admin CA removes a device but neither the admin phone nor
     * the root, nor hands the group over, and nothing it signs after the
     * admin phone removed it counts.
     */
    @Test
    fun goAdminPowers() {
        val v = Interop.read("go-admins.json").jsonObject
        val records = v.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }.reversed()
        val set = RecordSet()
        // The record signed under the root the computer admin named is dropped: that root is never known.
        val dropped = v["dropped"]?.jsonPrimitive?.int ?: 0
        assertEquals(1, dropped)
        assertEquals(records.size - dropped, set.addAll(records, b64(v.str("group_ca"))).size)
        assertEquals(v.str("digest"), set.digest)
        assertTrue(set.roots.isEmpty(), "a computer admin handed the group over")
        val devices = v.getValue("devices").jsonArray.map { it.jsonObject }
        assertEquals(devices.map { it.str("name") }, set.devices.map { it.name })
        assertEquals(devices.map { it.getValue("admin").jsonPrimitive.boolean }, set.devices.map { it.admin })
        for (k in v.getValue("keys").jsonArray) {
            val o = k.jsonObject
            assertEquals(o.getValue("revoked").jsonPrimitive.boolean, set.isRevoked(b64(o.str("key"))), o.str("name"))
        }
        for (c in v.getValue("chains").jsonArray) {
            val o = c.jsonObject
            val chain = o.getValue("chain").jsonArray.map { b64(it.jsonPrimitive.content) }
            assertEquals(o.getValue("refused").jsonPrimitive.boolean, set.refused(chain) != null, o.str("name"))
        }
    }

    /** An admin computer freezing another (go-freeze.json, docs/protocol.md section 10, rule 4), as Go's TestGoFreezeVectors writes it. */
    @Test
    fun goFreeze() {
        val v = Interop.read("go-freeze.json").jsonObject
        val records = v.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }.reversed()
        val set = RecordSet()
        assertEquals(records.size, set.addAll(records, b64(v.str("group_ca"))).size)
        assertEquals(v.str("digest"), set.digest)
        val devices = v.getValue("devices").jsonArray.map { it.jsonObject }
        assertEquals(devices.map { it.str("name") }, set.devices.map { it.name })
        assertEquals(devices.map { it.getValue("admin").jsonPrimitive.boolean }, set.devices.map { it.admin })
        for (k in v.getValue("keys").jsonArray) {
            val o = k.jsonObject
            assertEquals(o.getValue("frozen").jsonPrimitive.boolean, set.isFrozen(b64(o.str("key"))), o.str("name"))
            assertTrue(!set.isRevoked(b64(o.str("key"))), o.str("name"))
        }
        for (c in v.getValue("chains").jsonArray) {
            val o = c.jsonObject
            val chain = o.getValue("chain").jsonArray.map { b64(it.jsonPrimitive.content) }
            assertEquals(o.getValue("refused").jsonPrimitive.boolean, set.refused(chain) != null, o.str("name"))
        }
    }

    /**
     * An admin computer taking over a group whose root is a computer (go-takeover.json, from Go's
     * TestGoTakeoverVectors): it counts there, but not in a phone's group, not while another admin computer has
     * frozen it, and not once the old root removed it.
     */
    @Test
    fun goTakeover() {
        val cases = Interop.read("go-takeover.json").jsonObject.getValue("cases").jsonArray.map { it.jsonObject }
        assertEquals(4, cases.size)
        for (c in cases) {
            val name = c.str("name")
            val records = c.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }.reversed()
            val set = RecordSet()
            val dropped = c["dropped"]?.jsonPrimitive?.int ?: 0
            assertEquals(if (name == "phone root") 1 else 0, dropped, name)
            assertEquals(records.size - dropped, set.addAll(records, b64(c.str("group_ca"))).size, name)
            assertEquals(c.str("digest"), set.digest, name)
            val roots = (c["roots"] as? JsonArray).orEmpty().map { it.jsonPrimitive.content }
            assertEquals(roots, set.roots.map { b64(it) }, name)
            for (k in c.getValue("keys").jsonArray) {
                val o = k.jsonObject
                assertEquals(o.getValue("revoked").jsonPrimitive.boolean, set.isRevoked(b64(o.str("key"))), "$name: ${o.str("name")}")
            }
        }
    }

    /**
     * Writes records this kit signed for internal/group's TestSwiftRecords,
     * under the Swift kit's file name, when CBB_INTEROP_OUT names a directory.
     */
    @Test
    fun recordsForGo() {
        val dir = Interop.out ?: return
        val g = Group(now)
        g.set.add(Records.revoke(listOf(Records.keyHashOfCert(g.pcCert)), g.tag, g.phone, now, g.rootKey), g.ca)
        val out = Wire.obj(
            "group_ca" to Wire.bytes(g.ca),
            "records" to JsonArray(g.set.records.map { it.toJson() }),
            "digest" to Wire.str(g.set.digest),
            "devices" to JsonArray(g.set.devices.map { JsonPrimitive(it.id) }),
            "revoked" to JsonArray(g.set.revoked.map { JsonPrimitive(b64(unhex(it))) }),
        )
        File(dir, "swift-records.json").writeBytes(Wire.encode(out))
    }
}
