// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import java.io.File
import java.security.SecureRandom
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A second phone joins a phone group and becomes an admin (docs/protocol.md,
 * sections 6 and 10), then admits, renews and is removed; and a computer
 * becomes an admin.
 */
class PhoneGroupTest {
    private val t0 = Instant.now()
    private val later = t0.plusSeconds(500L * 24 * 3600)
    private val sid = ByteArray(32).also { SecureRandom().nextBytes(it) }

    /** A device that listens for pairing: its device ID, member key and self-signed certificate. */
    class Listener {
        val device = SyncEngine.newID()
        val key = SoftwareSigner()
        val cert = GroupCertificates.selfSigned(device, key)
    }

    /** Runs one pairing: the admitting phone dials the listener, which answers with joinerCode (code when null). */
    private fun pair(
        admitter: PhoneGroup,
        signer: CertificateSigner,
        l: Listener,
        info: Pairing.Info,
        code: String = "123456",
        joinerCode: String? = null,
        makeAdmin: Boolean = true,
        addrs: List<String> = emptyList(),
    ): Pair<Result<PairingMember.Admitted>, Result<PairingJoiner.Joined>> {
        val (m, j) = Pipe.pair()
        val member = Background { admitter.admit(m, code, l.cert, sid, signer, t0, makeAdmin, addrs) }
        val joined = runCatching {
            PairingJoiner.accept(j, joinerCode ?: code, info, admitter.memberCert, l.cert, sid, t0) {}
        }
        j.close()
        return runCatching { member.join() } to joined
    }

    @Test
    fun secondPhoneBecomesAdmin() {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0, "First")
        assertEquals(root.device, root.records.rootDevice)

        // The second phone joins with an admin key and gets its admin CA.
        val second = Listener()
        val adminKey = SoftwareSigner()
        val (m, j) = pair(root, rootKey, second, Pairing.Info("Second", "android", adminKey.publicKeyDER))
        val joined = j.getOrThrow()
        assertTrue(m.getOrThrow().confirmed)
        assertEquals(second.device, joined.device)
        val adminCA = assertNotNull(joined.welcome.adminCA)
        GroupCertificates.checkAdminCA(adminCA, root.groupCA)
        assertTrue(root.computers.isEmpty(), "a phone is no computer")
        val listed = assertNotNull(root.devices.firstOrNull { it.id == second.device })
        assertEquals("phone", listed.role)
        assertTrue(listed.admin)

        val admin = PhoneGroup.joined(joined)
        assertFalse(admin.isRoot)
        assertTrue(admin.isAdmin)
        assertEquals(root.tag, admin.tag)
        // The records reach it through the computers.
        admin.add(root.records.records)
        assertEquals(root.device, admin.records.rootDevice)

        // The admin admits a computer from its own admin CA.
        val pc = Listener()
        val (_, j2) = pair(admin, adminKey, pc, Pairing.Info("pi", "linux"))
        val pcJoined = j2.getOrThrow()
        assertContentEquals(adminCA, pcJoined.welcome.issuer)
        assertNull(pcJoined.welcome.adminCA)
        val pcChain = listOf(pcJoined.welcome.cert, adminCA)
        assertEquals(pc.device, GroupCertificates.verifyMember(pcChain, root.groupCA, t0))
        assertEquals(listOf(pc.device), admin.computers.map { it.device })
        root.add(admin.records.records)
        assertTrue(root.devices.any { it.id == pc.device }, "a record signed through the admin CA counts")
        // The root and the admin may be the hub away from home; a plain member may not.
        assertTrue(root.records.mayHost(root.device))
        assertTrue(root.records.mayHost(second.device))
        assertFalse(root.records.mayHost(pc.device))
        // By key: the root's own chain and the admin's, not another device's under their IDs.
        assertTrue(root.records.mayHost(root.device, root.memberChain))
        assertTrue(root.records.mayHost(second.device, admin.memberChain))
        assertFalse(root.records.mayHost(second.device, pcChain), "a chain whose key no admin record names")
        assertFalse(root.records.mayHost(root.device, admin.memberChain))

        // Renewals: an admin renews what it issued, and what the root issued, from its admin CA; the root renews any.
        val byAdmin = assertNotNull(admin.renewal(pcChain, adminKey, later))
        assertContentEquals(adminCA, byAdmin.issuer)
        assertEquals(pc.device, GroupCertificates.verifyMember(byAdmin.cert, root.groupCA, later, adminCA))
        val rootsOne = assertNotNull(admin.renewal(listOf(root.memberCert), adminKey, later))
        assertEquals(root.device, GroupCertificates.verifyMember(rootsOne.cert, root.groupCA, later, adminCA))
        val byRoot = assertNotNull(root.renewal(pcChain, rootKey, later)).cert
        assertEquals(pc.device, GroupCertificates.verifyMember(byRoot, root.groupCA, later))
        assertTrue(admin.renewOwnCertificate(adminKey, later))
        assertContentEquals(adminCA, admin.memberIssuer)
        assertEquals(admin.device, GroupCertificates.verifyMember(admin.memberChain, root.groupCA, later))

        // The admin cannot remove the root; the root removes the admin and keeps every listed device: the
        // computer it admitted, and the root, whose certificate it renewed.
        assertFailsWith<PhoneGroup.Failure> { admin.revoke(root.device, adminKey, t0) }
        val revocation = root.revoke(second.device, rootKey, t0)
        val body = assertNotNull(Records.Body.decode(revocation.body))
        assertEquals(setOf(Key(listed.key), Key(Records.keyHashOfCert(adminCA))), body.keys!!.map { Key(it) }.toSet())
        assertEquals(setOf(Key(Records.keyHashOfCert(pcJoined.welcome.cert)), Key(Records.keyHashOfCert(root.memberCert))), body.keep!!.map { Key(it) }.toSet())
        assertFalse(root.devices.any { it.id == second.device })
        assertTrue(root.devices.any { it.id == pc.device })
        assertNull(root.records.refused(pcChain))
        assertNull(root.records.refused(listOf(rootsOne.cert, adminCA)), "the root's certificate the removed admin renewed")
        assertNotNull(root.records.refused(listOf(joined.welcome.cert)))
    }

    @Test
    fun phoneWithoutAdmin() {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0)
        val l = Listener()
        val (_, j) = pair(root, rootKey, l, Pairing.Info("Third", "ios", SoftwareSigner().publicKeyDER), makeAdmin = false)
        val joined = j.getOrThrow()
        assertNull(joined.welcome.adminCA)
        assertEquals(false, root.devices.firstOrNull { it.id == l.device }?.admin)
        val g = PhoneGroup.joined(joined)
        assertFalse(g.isAdmin)
        assertFailsWith<PhoneGroup.Failure> { g.revoke(root.device, rootKey, t0) }
        assertFalse(g.renewOwnCertificate(rootKey, later))

        // An admin that is not the root makes no admins.
        val adminKey = SoftwareSigner()
        val (_, j2) = pair(root, rootKey, Listener(), Pairing.Info("Admin", "ios", adminKey.publicKeyDER))
        val admin = PhoneGroup.joined(j2.getOrThrow())
        val (_, j3) = pair(admin, adminKey, Listener(), Pairing.Info("Fourth", "android", SoftwareSigner().publicKeyDER))
        assertNull(j3.getOrThrow().welcome.adminCA)
    }

    @Test
    fun liteMember() {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0)
        val l = Listener()
        val addrs = listOf("192.168.20.5:8764", "203.0.113.7:8764", "[fd00::5]:8764", "[2001:db8::5]:8764")
        val (_, j) = pair(root, rootKey, l, Pairing.Info("router", "linux", role = Pairing.Info.LITE), addrs = addrs)
        // Only the home network addresses are kept, to dial it when mDNS does not reach its subnet.
        assertEquals(mapOf(l.device to listOf("192.168.20.5:8764", "[fd00::5]:8764")), root.addresses)
        val welcome = j.getOrThrow().welcome
        assertNull(welcome.groupCAKey)
        assertNull(welcome.adminCA)
        assertEquals("lite", root.devices.first { it.id == l.device }.role)
        assertFailsWith<PhoneGroup.Failure> { root.makeAdmin(l.device, SoftwareSigner().publicKeyDER, rootKey, t0, allowFileKey = true) }
    }

    @Test
    fun wrongCode() {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0)
        val (m, j) = pair(root, rootKey, Listener(), Pairing.Info("Second", "android"), joinerCode = "654321")
        assertEquals(Pairing.ErrorCode.WRONG_CODE, (j.exceptionOrNull() as PairingJoiner.Failure).code)
        assertEquals(Pairing.ErrorCode.WRONG_CODE, (m.exceptionOrNull() as PairingMember.Failure).code)
    }

    @Test
    fun joinerRefusesAWelcomeForAnotherKey() {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0)
        val l = Listener()
        val (m, j) = Pipe.pair()
        val member = Background {
            PairingMember.admit(m, "123456", root.memberCert, l.cert, sid, Pairing.MemberAD(root.device, root.tag)) { dev, _, _ ->
                Pairing.Welcome(GroupCertificates.member(dev, SoftwareSigner().publicKeyDER, root.groupCA, rootKey, t0), root.groupCA)
            }
        }
        val e = assertFailsWith<PairingJoiner.Failure> {
            PairingJoiner.accept(j, "123456", Pairing.Info("Second", "android"), root.memberCert, l.cert, sid, t0) { error("stored a bad welcome") }
        }
        assertEquals("the certificate is not for this phone", e.message)
        assertFalse(member.join().confirmed)
    }

    @Test
    fun saveAndLoad() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0, "My\u0007Pixel")
        assertEquals(listOf("MyPixel"), g.devices.map { it.name })
        val pi = SyncEngine.newID()
        val cert = GroupCertificates.member(pi, SoftwareSigner().publicKeyDER, g.groupCA, rootKey, t0)
        g.record(pi, "pi", "linux", Records.keyHashOfCert(cert), rootKey, t0)
        g.computers.add(PhoneGroup.Computer(pi, "pi", "linux", cert, Instant.ofEpochMilli(t0.toEpochMilli()), listOf("10.0.0.5:8764")))
        val (ca, _) = g.makeAdmin(pi, SoftwareSigner().publicKeyDER, rootKey, t0.plusSeconds(1), allowFileKey = true)
        val f = File.createTempFile("group", ".json")
        try {
            g.save(f)
            val back = assertNotNull(PhoneGroup.load(f))
            assertEquals(g.device, back.device)
            assertContentEquals(g.memberCert, back.memberCert)
            assertEquals(g.computers, back.computers)
            assertEquals(g.records.digest, back.records.digest)
            assertEquals(g.devices, back.devices)
            assertContentEquals(ca, back.computerAdmins[pi])
            assertTrue(back.isRoot)
        } finally {
            f.delete()
        }
        assertEquals("Android", PhoneGroup.validName("\u0001"))
        assertEquals(64, PhoneGroup.validName("\u0436".repeat(40)).toByteArray().size)
    }

    @Test
    fun rename() {
        val root = SoftwareSigner()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        val pi = SyncEngine.newID()
        val piKey = Records.keyHashOfCert(GroupCertificates.member(pi, SoftwareSigner().publicKeyDER, g.groupCA, root, t0))
        g.record(pi, "pi", "full", piKey, root, t0, os = "linux")
        val (ca, _) = g.makeAdmin(pi, SoftwareSigner().publicKeyDER, root, t0.plusSeconds(1), allowFileKey = true)
        val r = g.rename(pi, "  living room pi ", root, t0.plusSeconds(2))
        assertTrue(r in g.records.records)
        val d = assertNotNull(g.devices.firstOrNull { it.id == pi })
        assertEquals("living room pi", d.name)
        assertTrue(d.admin)
        assertContentEquals(Records.keyHashOfCert(ca), d.adminKey)
        assertContentEquals(piKey, d.key)
        assertEquals("full", d.role)
        assertEquals("linux", d.os)
        assertFailsWith<PhoneGroup.Failure> { g.rename(pi, " ", root, t0) }
        assertFailsWith<PhoneGroup.Failure> { g.rename(pi, "x".repeat(65), root, t0) }
        assertFailsWith<PhoneGroup.Failure> { g.rename(SyncEngine.newID(), "x", root, t0) }
    }

    /** The watch's emergency actions (section 10, rule 8): the phone builds the body, the watch signs it, and it counts as the rules say. */
    @Test
    fun watchActions() {
        val root = SoftwareSigner()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        val pi = SyncEngine.newID()
        g.record(pi, "pi", "linux", Records.keyHashOfCert(GroupCertificates.member(pi, SoftwareSigner().publicKeyDER, g.groupCA, root, t0)), root, t0)
        g.makeAdmin(pi, SoftwareSigner().publicKeyDER, root, t0.plusSeconds(1), allowFileKey = true)
        val deck = SyncEngine.newID()
        g.record(deck, "deck", "full", Records.keyHashOfCert(GroupCertificates.member(deck, SoftwareSigner().publicKeyDER, g.groupCA, root, t0)), root, t0)
        val watchKey = SoftwareSigner()
        val watch = SyncEngine.newID()
        val (ca, _) = g.addWatch(watch, "Watch", "wearos", watchKey.publicKeyDER, root, t0.plusSeconds(1))
        val all = listOf(PhoneGroup.WatchAction.PASTE_OFF, PhoneGroup.WatchAction.ACTIONS_OFF, PhoneGroup.WatchAction.AWAY_OFF, PhoneGroup.WatchAction.ACTION)
        assertEquals(listOf(PhoneGroup.WatchAction.FREEZE) + all, g.watchActions(pi))
        assertEquals(listOf(PhoneGroup.WatchAction.REMOVE) + all, g.watchActions(deck))
        assertEquals(emptyList(), g.watchActions(g.device))
        assertEquals(emptyList(), g.watchActions(watch))
        assertFailsWith<PhoneGroup.Failure> { g.watchBody(PhoneGroup.WatchAction.REMOVE, pi, watch, t0) }
        assertFailsWith<PhoneGroup.Failure> { g.watchBody(PhoneGroup.WatchAction.FREEZE, pi, deck, t0) }
        val t2 = t0.plusSeconds(2)
        fun signed(a: PhoneGroup.WatchAction, device: String, name: String? = null): Member.Record {
            val body = g.watchBody(a, device, watch, t2, name)
            return PhoneGroup.watchRecord(body, watchKey.signature(body), ca)
        }
        val now = t0.plusSeconds(3).toEpochMilli()
        for (a in listOf(PhoneGroup.WatchAction.PASTE_OFF, PhoneGroup.WatchAction.ACTIONS_OFF, PhoneGroup.WatchAction.AWAY_OFF)) {
            Commands.verify(signed(a, pi), g.records, pi, now)
        }
        Commands.verify(signed(PhoneGroup.WatchAction.ACTION, pi, "lock"), g.records, pi, now)
        assertEquals(2, g.add(listOf(signed(PhoneGroup.WatchAction.FREEZE, pi), signed(PhoneGroup.WatchAction.REMOVE, deck))).size)
        assertTrue(g.devices.first { it.id == pi }.frozen)
        assertTrue(g.devices.none { it.id == deck })
    }

    /** The root makes a watch an admin (section 10, rule 8): it may freeze but admits nobody, and removing it takes it out. */
    @Test
    fun addWatch() {
        val root = SoftwareSigner()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        val watchKey = SoftwareSigner()
        val watch = SyncEngine.newID()
        for ((id, os) in listOf("abc" to "wearos", watch.uppercase() to "wearos", watch to "android", g.device to "wearos")) {
            assertFailsWith<PhoneGroup.Failure>("$id $os") { g.addWatch(id, "Watch", os, watchKey.publicKeyDER, root, t0) }
        }
        val (ca, r) = g.addWatch(watch, " My watch ", "wearos", watchKey.publicKeyDER, root, t0.plusSeconds(1))
        assertContentEquals(watchKey.publicKeyDER, CertificateInfo(ca).publicKey)
        assertTrue(r in g.records.records)
        val d = assertNotNull(g.devices.firstOrNull { it.id == watch })
        val key = Records.keyHashOfCert(ca)
        assertEquals("My watch", d.name)
        assertEquals("watch", d.role)
        assertEquals("wearos", d.os)
        assertEquals(Records.HARDWARE, d.store)
        assertContentEquals(key, d.key)
        assertContentEquals(key, d.adminKey)
        assertTrue(d.admin)
        assertTrue(g.records.isWatch(key))
        assertFalse(g.records.mayHost(watch))

        // A device record the watch signs admits nobody.
        val deck = SyncEngine.newID()
        val deckCert = GroupCertificates.member(deck, SoftwareSigner().publicKeyDER, ca, watchKey, t0)
        g.add(listOf(Records.device(deck, "deck", "linux", Records.keyHashOfCert(deckCert), g.tag, watch, t0.plusSeconds(1), watchKey, adminCA = ca)))
        assertTrue(g.devices.none { it.id == deck })
        assertNotNull(g.records.refused(listOf(deckCert, ca)))

        g.revoke(watch, root, t0.plusSeconds(2))
        assertTrue(g.devices.none { it.id == watch })
        assertTrue(g.records.isRevoked(key))
    }

    @Test
    fun makeAdmin() {
        val root = SoftwareSigner()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        val pi = SyncEngine.newID()
        val piKey = Records.keyHashOfCert(GroupCertificates.member(pi, SoftwareSigner().publicKeyDER, g.groupCA, root, t0))
        g.record(pi, "pi", "linux", piKey, root, t0)
        val adminKey = SoftwareSigner()
        // A computer whose keys sit in a file, or that does not say, needs
        // the user's consent; one with hardware keys does not.
        assertFailsWith<PhoneGroup.FileKey> { g.makeAdmin(pi, adminKey.publicKeyDER, root, t0.plusSeconds(1)) }
        assertFailsWith<PhoneGroup.FileKey> { g.makeAdmin(pi, adminKey.publicKeyDER, root, t0.plusSeconds(1), keyStore = Records.FILE) }
        assertEquals(Records.FILE, g.devices.first { it.id == pi }.store)
        val (ca, r) = g.makeAdmin(pi, adminKey.publicKeyDER, root, t0.plusSeconds(1), allowFileKey = true)
        assertContentEquals(adminKey.publicKeyDER, CertificateInfo(ca).publicKey)
        val d = assertNotNull(g.devices.firstOrNull { it.id == pi })
        assertTrue(d.admin)
        assertEquals(Records.FILE, d.store)
        assertEquals(Records.HARDWARE, g.devices.first { it.id == g.device }.store)
        assertContentEquals(Records.keyHashOfCert(ca), d.adminKey)
        assertContentEquals(piKey, d.key)
        assertTrue(r in g.records.records)
        assertContentEquals(ca, g.computerAdminCA(adminKey.publicKeyDER))
        assertNull(g.computerAdminCA(SoftwareSigner().publicKeyDER))
        assertFailsWith<PhoneGroup.Failure> { g.makeAdmin(g.device, adminKey.publicKeyDER, root, t0, allowFileKey = true) }
        assertFailsWith<PhoneGroup.Failure> { g.makeAdmin(SyncEngine.newID(), adminKey.publicKeyDER, root, t0, allowFileKey = true) }

        // The admin computer admits the deck; removing the computer keeps it.
        val deck = SyncEngine.newID()
        val deckCert = GroupCertificates.member(deck, SoftwareSigner().publicKeyDER, ca, adminKey, t0)
        g.add(listOf(Records.device(deck, "deck", "linux", Records.keyHashOfCert(deckCert), g.tag, pi, t0, adminKey, adminCA = ca)))
        assertTrue(g.devices.any { it.id == deck })
        g.revoke(pi, root, t0)
        assertEquals(setOf(g.device, deck), g.devices.map { it.id }.toSet())
        assertNull(g.computerAdmins[pi])
        assertNull(g.computerAdminCA(adminKey.publicKeyDER))
    }

    /** Writes swift-renewal.json, swift-admin.json and swift-computer-admin.json for internal/group's TestSwift tests. */
    @Test
    fun forGo() {
        val dir = Interop.out ?: return
        val ca = SoftwareSigner()
        val g = PhoneGroup.create(ca, SoftwareSigner().publicKeyDER, t0)
        val key = SoftwareSigner()
        val pc = SyncEngine.newID()
        val cert = GroupCertificates.member(pc, key.publicKeyDER, g.groupCA, ca, t0)
        val renewed = assertNotNull(GroupCertificates.renewal(cert, g.groupCA, ca, later))
        val adminKey = SoftwareSigner()
        val adminCA = GroupCertificates.adminCA(SyncEngine.newID(), adminKey.publicKeyDER, g.groupCA, ca)
        val byAdmin = assertNotNull(GroupCertificates.renewal(listOf(cert), listOf(g.groupCA), adminKey, later, adminCA))
        File(dir, "swift-renewal.json").writeBytes(
            Wire.encode(
                Wire.obj(
                    "device" to Wire.str(pc), "group_ca" to Wire.bytes(g.groupCA), "key" to Wire.bytes(key.keyPair.private.encoded),
                    "cert" to Wire.bytes(cert), "renewed" to Wire.bytes(renewed), "admin_ca" to Wire.bytes(adminCA),
                    "admin_renewed" to Wire.bytes(byAdmin),
                ),
            ),
        )

        // An admin phone and the computer it admitted.
        val adminDevice = SyncEngine.newID()
        val deskKey = SoftwareSigner()
        val desk = SyncEngine.newID()
        val deskCert = GroupCertificates.member(desk, deskKey.publicKeyDER, adminCA, adminKey, t0)
        val records = listOf(
            Records.device(adminDevice, "Second", "phone", Records.keyHash(adminKey.publicKeyDER), g.tag, adminDevice, t0, ca, Records.keyHashOfCert(adminCA)),
            Records.device(desk, "Desk", "linux", Records.keyHashOfCert(deskCert), g.tag, adminDevice, t0, adminKey, adminCA = adminCA),
        )
        val set = RecordSet()
        for (r in records) assertTrue(set.add(r, g.groupCA))
        File(dir, "swift-admin.json").writeBytes(
            Wire.encode(
                Wire.obj(
                    "group_ca" to Wire.bytes(g.groupCA), "admin_ca" to Wire.bytes(adminCA), "cert" to Wire.bytes(deskCert),
                    "key" to Wire.bytes(deskKey.keyPair.private.encoded), "device" to Wire.str(desk),
                    "records" to JsonArray(records.map { it.toJson() }),
                    "devices" to JsonArray(set.devices.map { Wire.str(it.id)!! }), "digest" to Wire.str(set.digest),
                ),
            ),
        )

        // The root makes a computer an admin.
        g.record(pc, "pi", "linux", Records.keyHashOfCert(cert), ca, t0)
        val computerKey = SoftwareSigner()
        val (computerCA, _) = g.makeAdmin(pc, computerKey.publicKeyDER, ca, t0.plusSeconds(1), allowFileKey = true)
        File(dir, "swift-computer-admin.json").writeBytes(
            Wire.encode(
                Wire.obj(
                    "group_ca" to Wire.bytes(g.groupCA), "device" to Wire.str(pc), "admin_key" to Wire.bytes(computerKey.publicKeyDER),
                    "admin_ca" to Wire.bytes(computerCA), "records" to JsonArray(g.records.records.map { it.toJson() }),
                ),
            ),
        )
    }
}
