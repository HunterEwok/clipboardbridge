// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import java.io.File
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Root records (docs/protocol.md, section 10, "Roots" and "Handing the
 * group over"): the root phone is lost, and admin phone B takes the group
 * over with a new root.
 */
class RootTest {
    private val t0 = Instant.now()

    /** A computer: its device ID, key and member certificate. */
    class Computer(ca: ByteArray, signer: CertificateSigner, now: Instant) {
        val device = SyncEngine.newID()
        val key = SoftwareSigner()
        val cert = GroupCertificates.member(device, key.publicKeyDER, ca, signer, now)
        val keyHash: ByteArray get() = Records.keyHashOfCert(cert)
    }

    /** The group before the loss: the root phone, which admitted computer one itself, and admin phone B, which admitted computer two. */
    class Group(now: Instant) {
        val rootKey = SoftwareSigner()
        val adminKey = SoftwareSigner()
        val newRootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now, "Lost")
        private val bDevice = SyncEngine.newID()

        /** B's admin CA, under the old root. */
        val adminCA = GroupCertificates.adminCA(bDevice, adminKey.publicKeyDER, root.groupCA, rootKey)
        private val bCert = GroupCertificates.member(bDevice, SoftwareSigner().publicKeyDER, root.groupCA, rootKey, now)
        val b = PhoneGroup(bDevice, root.groupCA, bCert)
        val one = Computer(root.groupCA, rootKey, now)
        val two = Computer(adminCA, adminKey, now)

        init {
            root.record(bDevice, "B", "phone", Records.keyHashOfCert(bCert), rootKey, now, Records.keyHashOfCert(adminCA))
            root.record(one.device, "one", "linux", one.keyHash, rootKey, now)
            b.isRoot = false
            b.adminCA = adminCA
            b.add(root.records.records)
            b.record(two.device, "two", "linux", two.keyHash, adminKey, now)
            root.add(b.records.records)
        }
    }

    @Test
    fun takeOver() {
        val g = Group(t0)
        val lost = g.root.device
        assertEquals(lost, g.b.records.rootDevice)
        val rs = g.b.takeOver(lost, g.adminKey, g.newRootKey, t0)
        assertEquals(3, rs.size)
        assertTrue(g.b.isRoot)
        assertNull(g.b.adminCA)
        assertEquals(1, g.b.roots.size)
        assertEquals(g.root.tag, g.b.tag, "the group keeps its tag")
        assertEquals(g.b.device, g.b.records.rootDevice)
        assertEquals(listOf("B", "one", "two"), g.b.devices.map { it.name })
        assertEquals(true, g.b.devices.firstOrNull { it.name == "B" }?.admin)
        val set = g.b.records
        assertNotNull(set.refused(listOf(g.root.memberCert)), "the lost phone")
        assertNull(set.refused(listOf(g.one.cert)), "the computer the old root admitted")
        assertNull(set.refused(listOf(g.two.cert, g.adminCA)), "the computer B admitted")
        assertNull(set.refused(g.b.memberChain), "B itself")

        // A computer that gets the records in any order sees the same.
        val computer = RecordSet()
        computer.addAll(g.b.records.records.shuffled() + rs.shuffled(), g.root.groupCA)
        assertEquals(g.b.records.digest, computer.digest)
        assertEquals(g.b.roots.map { Key(it) }, computer.roots.map { Key(it) })
        assertEquals(listOf("B", "one", "two"), computer.devices.map { it.name })

        // The new root admits and renews.
        val three = Computer(g.b.currentRoot, g.newRootKey, t0)
        assertEquals(three.device, GroupCertificates.verifyMember(listOf(three.cert), g.b.trusted, t0))
        assertNull(set.refused(listOf(three.cert)))
        val later = t0.plusSeconds(500L * 24 * 3600)
        val renewed = assertNotNull(g.b.renewal(listOf(g.one.cert), g.newRootKey, later)).cert
        assertEquals(g.one.device, GroupCertificates.verifyMember(renewed, g.b.currentRoot, later))
    }

    @Test
    fun oldRootKeyAfterTakeOver() {
        val g = Group(t0)
        g.b.takeOver(g.root.device, g.adminKey, g.newRootKey, t0)
        val set = g.b.records
        // Whoever has the lost phone's root key signs a computer, an admin CA, a device record and a root record: none counts.
        val stolen = Computer(g.root.groupCA, g.rootKey, t0)
        val thiefKey = SoftwareSigner()
        val thiefCA = GroupCertificates.adminCA(SyncEngine.newID(), thiefKey.publicKeyDER, g.root.groupCA, g.rootKey)
        val viaThief = GroupCertificates.member(SyncEngine.newID(), SoftwareSigner().publicKeyDER, thiefCA, thiefKey, t0)
        assertNotNull(set.refused(listOf(stolen.cert)))
        assertNotNull(set.refused(listOf(viaThief, thiefCA)))
        val otherRoot = GroupCertificates.groupCA(SoftwareSigner(), t0, pathLength = 1)
        val thirdRoot = GroupCertificates.groupCA(SoftwareSigner(), t0, pathLength = 1)
        for (r in listOf(
            Records.device(stolen.device, "stolen", "linux", stolen.keyHash, g.b.tag, g.root.device, t0, g.rootKey),
            Records.root(otherRoot, g.b.tag, g.root.device, t0, g.rootKey),
            Records.root(thirdRoot, g.b.tag, g.root.device, t0, thiefKey, thiefCA),
        )) {
            assertTrue(set.add(r, g.root.groupCA))
        }
        assertEquals(listOf("B", "one", "two"), set.devices.map { it.name })
        assertEquals(g.b.roots.map { Key(it) }, set.roots.map { Key(it) })
    }

    @Test
    fun takeOverRefused() {
        val g = Group(t0)
        assertFailsWith<PhoneGroup.Failure> { g.b.takeOver(g.one.device, g.adminKey, g.newRootKey, t0) }
        assertFailsWith<PhoneGroup.Failure> { g.root.takeOver(g.root.device, g.rootKey, g.newRootKey, t0) }
        // A root record in a computer's group, or naming no phone root, is not taken.
        val pcCA = GroupCertificates.groupCA(g.rootKey, t0)
        val set = RecordSet()
        assertFalse(set.add(Records.root(pcCA, g.root.tag, g.root.device, t0, g.rootKey), g.root.groupCA))
        assertFalse(set.add(Records.root(g.adminCA, g.root.tag, g.root.device, t0, g.rootKey), g.root.groupCA))
    }

    /** A welcome after the takeover names the new root, and a phone that joins checks it. */
    @Test
    fun welcomeAfterTakeOver() {
        val g = Group(t0)
        g.b.takeOver(g.root.device, g.adminKey, g.newRootKey, t0)
        val joiner = SyncEngine.newID()
        val key = SoftwareSigner()
        val selfSigned = GroupCertificates.selfSigned(joiner, key)
        val cert = GroupCertificates.member(joiner, key.publicKeyDER, g.b.currentRoot, g.newRootKey, t0)
        val w = Pairing.Welcome(cert, g.b.groupCA, roots = g.b.roots, records = g.b.records.pathRecords)
        val j = PairingJoiner.Joined(joiner, w, Pairing.MemberAD(g.b.device, g.b.tag))
        val info = Pairing.Info("C", "android")
        PairingJoiner.check(j, info, g.b.memberCert, selfSigned, t0)
        assertTrue(g.b.records.pathRecords.size < g.b.records.records.size, "the welcome carries more than the path needs")
        val bad = PairingJoiner.Joined(joiner, Pairing.Welcome(cert, g.b.groupCA), j.member)
        assertFailsWith<PairingJoiner.Failure> { PairingJoiner.check(bad, info, g.b.memberCert, selfSigned, t0) }
        // A root that no record leads to, as one an admin made up and named in the Welcome, is refused.
        val made = PairingJoiner.Joined(joiner, Pairing.Welcome(cert, g.b.groupCA, roots = g.b.roots), j.member)
        assertFailsWith<PairingJoiner.Failure> { PairingJoiner.check(made, info, g.b.memberCert, selfSigned, t0) }
        assertEquals(g.b.roots.map { Key(it) }, PhoneGroup.joined(j).roots.map { Key(it) })
    }

    /**
     * What a phone hub shows its forwarder: the records of the root's own device and of the admins, and every
     * record that is no device record, never the records that name the computers.
     */
    @Test
    fun authorityRecords() {
        val g = Group(t0)
        fun names(rs: List<Member.Record>) = rs.mapNotNull { Records.Body.decode(it.body) }.filter { it.type == "device" }.map { it.name }.toSet()
        assertEquals(setOf("Lost", "B"), names(g.root.records.authorityRecords))
        val rs = g.b.takeOver(g.root.device, g.adminKey, g.newRootKey, t0)
        val after = g.b.records.authorityRecords
        assertEquals(setOf("Lost", "B"), names(after))
        val ids = after.map { Key(Records.id(it)) }.toSet()
        assertTrue(rs.all { Key(Records.id(it)) in ids }, "the takeover's records")
        assertTrue(g.b.records.pathRecords.all { Key(Records.id(it)) in ids }, "the path")
        assertEquals(ids.size, after.size)
        // A forwarder that knows only these sees the same roots and the lost phone removed.
        val forwarder = RecordSet()
        forwarder.addAll(after.shuffled(), g.root.groupCA)
        assertEquals(g.b.roots.map { Key(it) }, forwarder.roots.map { Key(it) })
        assertNotNull(forwarder.refused(listOf(g.root.memberCert)))
    }

    /** Writes swift-root.json for internal/group's TestSwiftRoot: a takeover as this kit signs it. */
    @Test
    fun takeOverForGo() {
        val dir = Interop.out ?: return
        val g = Group(t0)
        g.b.takeOver(g.root.device, g.adminKey, g.newRootKey, t0)
        File(dir, "swift-root.json").writeBytes(
            Wire.encode(
                Wire.obj(
                    "group_ca" to Wire.bytes(g.root.groupCA),
                    "records" to JsonArray(g.b.records.records.reversed().map { it.toJson() }),
                    "roots" to Wire.list(g.b.roots),
                    "devices" to JsonArray(g.b.devices.map { Wire.str(it.id)!! }),
                    "digest" to Wire.str(g.b.records.digest ?: ""),
                    "lost" to Wire.bytes(g.root.memberCert),
                    "kept" to Wire.bytes(g.one.cert),
                ),
            ),
        )
    }
}
