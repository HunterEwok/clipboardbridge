// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import java.io.File
import java.time.Instant

/**
 * A phone group (docs/protocol.md, sections 9 and 10) as this phone holds
 * it: the group CA, the phone's own member certificate, the computers it
 * admitted and the records. The phone is the root, which made the group,
 * an admin with an admin CA under the root, or a member without either.
 * The keys stay outside, in the Android Keystore. It is saved as JSON next
 * to the app's other data.
 */
class PhoneGroup internal constructor(
    /** This phone's device ID. */
    val device: String,
    /** The group root CA, DER; path length 1. The group's first root, which names it for good. */
    val groupCA: ByteArray,
    /** This phone's member certificate, DER, from one of the roots or from memberIssuer. */
    var memberCert: ByteArray,
) {
    /** The roots that took the group over from groupCA, in order, DER; the last is the current root (section 10, "Roots"). */
    var roots: List<ByteArray> = emptyList()
        internal set

    /** The admin CA that issued memberCert, which the phone sends after it in TLS handshakes; null when a root did. */
    var memberIssuer: ByteArray? = null
        internal set

    /** Whether this phone holds the current root's key: it made the group, or took it over. */
    var isRoot = true
        internal set

    /** This phone's admin CA when it is an admin but not the root. */
    var adminCA: ByteArray? = null
        internal set

    val computers = mutableListOf<Computer>()

    /** The group's signed device and revocation records; admins sign them, and they spread to every member. */
    var records = RecordSet()
        internal set

    /**
     * The admin CAs this phone, as the root, issued to computers, DER, by
     * device ID: sent again to a computer that offers the same admin key
     * (section 10, "A computer as admin").
     */
    val computerAdmins = mutableMapOf<String, ByteArray>()

    /** A computer this phone admitted. */
    data class Computer(
        val device: String,
        val name: String,
        /** "linux", "windows" or "macos", as its pairing Info says. */
        val os: String,
        val cert: ByteArray,
        val admitted: Instant,
        /**
         * Its addresses on the home network from the QR code, the one that
         * answered first: dialed when mDNS does not find it, as in another
         * subnet (docs/protocol.md, section 9).
         */
        val addrs: List<String> = emptyList(),
    ) {
        override fun equals(other: Any?): Boolean =
            other is Computer && device == other.device && name == other.name && os == other.os && cert.contentEquals(other.cert) &&
                admitted == other.admitted && addrs == other.addrs

        override fun hashCode(): Int = device.hashCode()
    }

    class Failure(message: String) : Exception(message)

    /** Whether this phone may admit devices, renew certificates and remove devices: the root and the admins. */
    val isAdmin: Boolean get() = isRoot || adminCA != null

    /** The certificate chain this phone presents in TLS, leaf first. */
    val memberChain: List<ByteArray> get() = listOf(memberCert) + listOfNotNull(memberIssuer)

    /** The current root: the last of roots, or the group CA. */
    val currentRoot: ByteArray get() = roots.lastOrNull() ?: groupCA

    /** Every root the group had, the group CA first: member certificates and admin CAs from any of them verify. */
    val trusted: List<ByteArray> get() = listOf(groupCA) + roots

    /** The CA whose key signs for this phone: the current root, or its admin CA. */
    internal val signingCA: ByteArray get() = adminCA ?: currentRoot

    /** The home network addresses of the computers this phone admitted, by device ID, best first. */
    val addresses: Map<String, List<String>> get() = computers.filter { it.addrs.isNotEmpty() }.associate { it.device to it.addrs }

    /** The group tag the computers publish. */
    val tag: String get() = GroupCertificates.tag(groupCA)

    /** The devices of the group, from the records. */
    val devices: List<RecordSet.Device> get() = records.devices

    /** Adds records from other members, then follows the roots they lead to when they go further than this phone's; returns the new records. */
    fun add(rs: List<Member.Record>): List<Member.Record> {
        val fresh = records.addAll(rs, groupCA)
        adoptRoots()
        return fresh
    }

    /** Takes the roots of the records when they go further than roots. */
    private fun adoptRoots() {
        val path = records.roots
        if (path.size > roots.size && path.take(roots.size).zip(roots).all { (a, b) -> a.contentEquals(b) }) roots = path
    }

    /** Signs and adds a device record. */
    internal fun record(
        device: String,
        name: String,
        role: String,
        key: ByteArray,
        caSigner: CertificateSigner,
        now: Instant,
        admin: ByteArray? = null,
        os: String? = null,
    ): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        val r = Records.device(device, name, role, key, tag, this.device, now, caSigner, admin, adminCA, os)
        records.add(r, groupCA)
        return r
    }

    /**
     * Hands the group to this admin phone when the root phone lost is gone
     * (section 10, "Handing the group over"): a new root for rootSigner's
     * key, a root record signed with this phone's admin CA (adminSigner),
     * then, as the new root, a revocation of the old root's key and the lost
     * phone that keeps everything else the old root certified, and this
     * phone's own record under the new root. It returns the records to
     * send; this phone is the root afterwards.
     */
    fun takeOver(lost: String, adminSigner: CertificateSigner, rootSigner: CertificateSigner, now: Instant): List<Member.Record> {
        val myCA = adminCA
        if (myCA == null || isRoot) throw Failure("this phone is no admin")
        if (lost != records.rootDevice || lost == device) throw Failure("that phone does not hold the root")
        val list = devices
        val d = list.firstOrNull { it.id == lost } ?: throw Failure("unknown device")
        val me = list.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        val oldRoot = Records.keyHashOfCert(currentRoot)
        val newRoot = GroupCertificates.groupCA(rootSigner, now, pathLength = 1)
        val keep = records.admitted(oldRoot).toMutableList()
        for (other in list) {
            val k = other.adminKey
            if (other.id != lost && k != null && keep.none { it.contentEquals(k) }) keep.add(k)
        }
        keep.removeAll { it.contentEquals(d.key) || it.contentEqualsOrNull(d.adminKey) }
        val out = mutableListOf(Records.root(newRoot, tag, device, now, adminSigner, myCA))
        records.add(out[0], groupCA)
        out.add(Records.revoke(listOf(oldRoot, d.key) + listOfNotNull(d.adminKey), tag, device, now, rootSigner, keep))
        out.add(Records.device(device, me.name, "phone", me.key, tag, device, now, rootSigner, me.adminKey, os = me.os ?: "android"))
        for (r in out.drop(1)) records.add(r, groupCA)
        adoptRoots()
        if (!currentRoot.contentEquals(newRoot)) throw Failure("the takeover did not make this phone the root")
        isRoot = true
        adminCA = null
        return out
    }

    /**
     * Renews this phone's own member certificate when it is due; reports
     * whether it did, after which the TLS identity must be made again. An
     * admin issues it from its own admin CA, a phone without one cannot.
     */
    fun renewOwnCertificate(caSigner: CertificateSigner, now: Instant): Boolean {
        if (!isAdmin || !GroupCertificates.isDue(memberCert, signingCA, now)) return false
        if (runCatching { GroupCertificates.verifyMember(memberChain, trusted, now) }.getOrNull() != device) return false
        memberCert = GroupCertificates.member(device, CertificateInfo(memberCert).publicKey, signingCA, caSigner, now)
        memberIssuer = adminCA
        return true
    }

    /**
     * A renewed certificate for a peer's chain (leaf first) when it is due
     * and this phone is an admin: the root issues it from its root, an admin
     * from its admin CA, which the cert message carries, whoever issued the
     * old one (as a removed admin did).
     */
    fun renewal(chain: List<ByteArray>, caSigner: CertificateSigner, now: Instant): MemberNode.Renewal? {
        if (!isAdmin) return null
        val cert = runCatching { GroupCertificates.renewal(chain, trusted, caSigner, now, adminCA) }.getOrNull() ?: return null
        return MemberNode.Renewal(cert, adminCA)
    }

    /**
     * Removes a device from the group: signs a revocation of its key, which
     * every member then refuses, and returns the record to send. For an
     * admin it revokes its admin key too and keeps the devices that admin
     * admitted, so they stay in the group (section 10). The root phone is
     * removed with takeOver instead.
     */
    fun revoke(device: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        if (device == this.device) throw Failure("this phone cannot remove itself")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        if (device == records.rootDevice) throw Failure("the root phone is removed by taking the group over")
        val keys = mutableListOf(d.key)
        var keep: List<ByteArray>? = null
        val admin = d.adminKey
        if (admin != null) {
            keys.add(admin)
            // Its own removals stop counting with it, so this record names them again.
            for (k in records.revokedBy(admin)) if (keys.none { it.contentEquals(k) }) keys.add(k)
            keep = records.admitted(admin).filterNot { k -> keys.any { it.contentEquals(k) } }
        }
        val r = Records.revoke(keys, tag, this.device, now, caSigner, keep, adminCA)
        records.add(r, groupCA)
        computers.removeAll { it.device == device }
        computerAdmins.remove(device)
        return r
    }

    /**
     * Gives a device another name: a device record like its newest one with
     * that name, which names it everywhere, since the newest record of a
     * device counts (section 10). An admin renames any device, itself and
     * the root included. name is trimmed; it must have 1 to 64 bytes and no
     * control characters.
     */
    fun rename(device: String, name: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        val n = name.trim()
        if (n.isEmpty() || validName(n) != n) throw Failure(INVALID_NAME)
        return record(device, n, d.role, d.key, caSigner, now, d.adminKey, d.os)
    }

    /**
     * Unfreezes an admin computer that another admin froze (section 10,
     * rule 4): a thaw record that ends every freeze of it. The root and the
     * admin phones do it; Remove takes the computer out for good instead.
     */
    fun thaw(device: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        val admin = d.adminKey
        if (!d.frozen || admin == null) throw Failure("not frozen")
        val r = Records.thaw(records.freezesOf(admin), tag, this.device, now, caSigner, adminCA)
        records.add(r, groupCA)
        return r
    }

    /**
     * Makes a computer an admin (section 10, "A computer as admin"): the
     * root issues an admin CA for the admin key the computer's hello offered
     * (a SubjectPublicKeyInfo) and signs its device record again, naming that
     * CA. It returns the admin CA, for the admin message, and the record to
     * send. Only the root makes admins.
     */
    fun makeAdmin(device: String, adminKey: ByteArray, rootSigner: CertificateSigner, now: Instant): Pair<ByteArray, Member.Record> {
        if (!isRoot) throw Failure("only the root makes admins")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        if (d.role != "full") throw Failure("not a computer")
        if (d.frozen) throw Failure("frozen: unfreeze it or remove it")
        val ca = GroupCertificates.adminCA(device, adminKey, currentRoot, rootSigner)
        val r = record(device, d.name, d.role, d.key, rootSigner, now, Records.keyHashOfCert(ca), d.os)
        computerAdmins[device] = ca
        return ca to r
    }

    /** The admin CA this phone issued for an admin key a computer offers, while that computer is still listed as an admin. */
    fun computerAdminCA(adminKey: ByteArray): ByteArray? {
        val listed = devices.filter { it.admin }.map { it.id }.toSet()
        return computerAdmins.entries.firstOrNull { (id, ca) ->
            id in listed && runCatching { CertificateInfo(ca).publicKey }.getOrNull()?.contentEquals(adminKey) == true
        }?.value
    }

    /**
     * Admits a listening device over a pairing connection whose TLS
     * handshake is done (section 6, "The joiner listens"): joinerCert is the
     * device's certificate, already checked against the QR code's
     * fingerprint, and sessionID the TLS exporter's output. The device gets
     * a member certificate from this phone's CA and the group CA, never a
     * key. A phone that sent an admin key becomes an admin when this phone is
     * the root and makeAdmin is set: it gets an admin CA for that key. On
     * success a computer is in computers, where one admitted again replaces
     * its entry, and every device has its record. A computer keeps those of
     * addrs that are on a home network, where the phone dialed it.
     */
    fun admit(
        t: FrameTransport,
        code: String,
        joinerCert: ByteArray,
        sessionID: ByteArray,
        caSigner: CertificateSigner,
        now: Instant,
        makeAdmin: Boolean = true,
        addrs: List<String> = emptyList(),
    ): PairingMember.Admitted {
        if (!isAdmin) throw Failure("this phone is no admin")
        val first = groupCA
        val later = roots
        val root = currentRoot
        val ca = signingCA
        val issuer = adminCA
        val canMakeAdmins = isRoot
        var adminKey: ByteArray? = null
        val admitted = PairingMember.admit(t, code, memberCert, joinerCert, sessionID, Pairing.MemberAD(device, tag)) { dev, publicKey, info ->
            val cert = GroupCertificates.member(dev, publicKey, ca, caSigner, now)
            val key = info.adminKey
            val forAdmin = if (Pairing.Info.isPhone(info.os) && key != null && makeAdmin && canMakeAdmins) {
                adminKey = key
                GroupCertificates.adminCA(dev, key, root, caSigner)
            } else {
                null
            }
            Pairing.Welcome(cert, first, issuer, forAdmin, later.ifEmpty { null })
        }
        val name = validName(admitted.info.name)
        val key = Records.keyHashOfCert(admitted.cert)
        if (Pairing.Info.isPhone(admitted.info.os)) {
            record(admitted.device, name, "phone", key, caSigner, now, adminKey?.let { Records.keyHash(it) }, admitted.info.os)
            return admitted
        }
        computers.removeAll { it.device == admitted.device }
        computers.add(Computer(admitted.device, admitted.info.name, admitted.info.os, admitted.cert, now, addrs.filter(JoinCode::isHome)))
        val role = if (admitted.info.role == Pairing.Info.LITE) "lite" else "full"
        record(admitted.device, name, role, key, caSigner, now, os = admitted.info.os)
        return admitted
    }

    /** The group as JSON, to save it. */
    fun toJson(): ByteArray = Wire.encode(
        Wire.obj(
            "device" to Wire.str(device),
            "group_ca" to Wire.bytes(groupCA),
            "roots" to Wire.list(roots),
            "member_cert" to Wire.bytes(memberCert),
            "member_issuer" to Wire.bytes(memberIssuer),
            "is_root" to JsonPrimitive(isRoot),
            "admin_ca" to Wire.bytes(adminCA),
            "computers" to JsonArray(
                computers.map {
                    Wire.obj(
                        "device" to Wire.str(it.device),
                        "name" to Wire.str(it.name),
                        "os" to Wire.str(it.os),
                        "cert" to Wire.bytes(it.cert),
                        "admitted_ms" to Wire.num(it.admitted.toEpochMilli()),
                        "addrs" to JsonArray(it.addrs.map { a -> JsonPrimitive(a) }),
                    )
                },
            ),
            "records" to Wire.parse(records.toJson()),
            "computer_admins" to JsonObject(computerAdmins.mapValues { Wire.bytes(it.value)!! }),
        ),
    )

    /** Saves the group in one step, so a crash leaves the old file or the new one. */
    fun save(file: File) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(toJson())
        if (!tmp.renameTo(file)) {
            file.delete()
            if (!tmp.renameTo(file)) throw java.io.IOException("cannot save ${file.path}")
        }
    }

    companion object {
        /**
         * Creates a group: a root CA for caSigner's key, a member certificate
         * for this phone's member key (a SubjectPublicKeyInfo), and the
         * phone's own device record under name.
         */
        fun create(caSigner: CertificateSigner, memberKey: ByteArray, now: Instant, name: String = "Android"): PhoneGroup {
            val ca = GroupCertificates.groupCA(caSigner, now, pathLength = 1)
            val device = SyncEngine.newID()
            val cert = GroupCertificates.member(device, memberKey, ca, caSigner, now)
            val g = PhoneGroup(device, ca, cert)
            g.record(device, validName(name), "phone", Records.keyHash(memberKey), caSigner, now, os = "android")
            return g
        }

        /** The message of the Failure for a name that the records do not accept. */
        const val INVALID_NAME = "a device name has 1 to 64 bytes and no control characters"

        /** A name that the records accept: 1 to 64 bytes without control characters, or "Android". */
        fun validName(s: String): String {
            val out = StringBuilder()
            var i = 0
            while (i < s.length) {
                val cp = s.codePointAt(i)
                i += Character.charCount(cp)
                if (Character.getType(cp) == Character.CONTROL.toInt()) continue
                val ch = String(Character.toChars(cp))
                if ((out.toString() + ch).toByteArray().size > 64) break
                out.append(ch)
            }
            return out.toString().ifEmpty { "Android" }
        }

        /**
         * The group a phone joins, from the welcome the admitting phone sent
         * and PairingJoiner checked: a member of it, and an admin when the
         * welcome carries its admin CA. The records arrive from the computers.
         */
        fun joined(j: PairingJoiner.Joined): PhoneGroup {
            val g = PhoneGroup(j.device, j.welcome.groupCA, j.welcome.cert)
            g.memberIssuer = j.welcome.issuer
            g.isRoot = false
            g.adminCA = j.welcome.adminCA
            g.roots = j.welcome.roots.orEmpty()
            return g
        }

        /** A group saved with toJson. */
        fun fromJson(data: ByteArray): PhoneGroup {
            val o = Wire.parse(data) ?: throw Failure("not a saved group")
            try {
                val g = PhoneGroup(
                    o.optString("device") ?: throw Failure("no device"),
                    o.optBytes("group_ca") ?: throw Failure("no group CA"),
                    o.optBytes("member_cert") ?: throw Failure("no member certificate"),
                )
                g.roots = o.optBytesList("roots").orEmpty()
                g.memberIssuer = o.optBytes("member_issuer")
                g.isRoot = (o.opt("is_root") as? JsonPrimitive)?.booleanOrNull ?: true
                g.adminCA = o.optBytes("admin_ca")
                for (c in o.optArray("computers").orEmpty()) {
                    val co = c as? JsonObject ?: continue
                    g.computers.add(
                        Computer(
                            co.optString("device") ?: continue,
                            co.optString("name") ?: "",
                            co.optString("os") ?: "linux",
                            co.optBytes("cert") ?: continue,
                            Instant.ofEpochMilli(co.optLong("admitted_ms") ?: 0),
                            co.optArray("addrs").orEmpty().mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.filter(JoinCode::isHome),
                        ),
                    )
                }
                o.optObject("records")?.let { g.records = RecordSet.fromJson(Wire.encode(it)) }
                o.optObject("computer_admins")?.forEach { (k, _) -> o.optObject("computer_admins")!!.optBytes(k)?.let { g.computerAdmins[k] = it } }
                return g
            } catch (e: WireTypeException) {
                throw Failure("not a saved group: ${e.message}")
            }
        }

        /** Reads a saved group; null when there is none. */
        fun load(file: File): PhoneGroup? = if (file.exists()) fromJson(file.readBytes()) else null
    }
}
