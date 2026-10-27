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

    /**
     * The computer keeps its keys in a file, which a thief with it can copy
     * and then act as an admin: the user allows it after a warning
     * (docs/protocol.md, section 17).
     */
    class FileKey : Exception("its keys sit in a file")

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

    /** Adds records from other members, then follows the roots they lead to when they differ from this phone's; returns the new records. */
    fun add(rs: List<Member.Record>): List<Member.Record> {
        val fresh = records.addAll(rs, groupCA)
        adoptRoots()
        return fresh
    }

    /**
     * Takes the roots of the records when they differ from roots, compared by content, so a root the records do not
     * name never stays trusted; an empty set says nothing yet.
     */
    private fun adoptRoots() {
        val path = records.roots
        if (records.records.isNotEmpty() && (path.size != roots.size || path.zip(roots).any { (a, b) -> !a.contentEquals(b) })) roots = path
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
        store: String? = null,
        kind: String? = null,
        proof: String? = null,
    ): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        val r = Records.device(device, name, role, key, tag, this.device, now, caSigner, admin, adminCA, os, store, kind, proof)
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
        keep.removeAll { k -> d.keys.any { it.contentEquals(k) } || k.contentEqualsOrNull(d.adminKey) }
        val out = mutableListOf(Records.root(newRoot, tag, device, now, adminSigner, myCA))
        records.add(out[0], groupCA)
        out.add(Records.revoke(listOf(oldRoot) + d.keys + listOfNotNull(d.adminKey), tag, device, now, rootSigner, keep))
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
        // Every key the device had in the group goes, so none of them stays a member nobody sees.
        val keys = d.keys.toMutableList()
        var keep: List<ByteArray>? = null
        val admin = d.adminKey
        if (admin != null) {
            // A watch's record names its admin CA as its key already.
            if (keys.none { it.contentEquals(admin) }) keys.add(admin)
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
        return record(device, n, d.role, d.key, caSigner, now, d.adminKey, d.os, d.store, d.kind, d.proof)
    }

    /**
     * A command that sets a computer's sync mode (docs/protocol.md,
     * section 15), signed with this phone's root or admin key; the caller
     * sends it to that computer alone.
     */
    fun modeCommand(to: String, mode: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.mode(to, mode, tag, device, now, caSigner, adminCA)
    }

    /**
     * A paste command that puts text where the focus of the member to is
     * (docs/protocol.md, section 15; design.md, "Remote paste"), by method
     * "paste" or "type", then Enter when enter is set; signed as
     * modeCommand.
     */
    fun pasteCommand(to: String, text: String, method: String, enter: Boolean, secret: Boolean, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.paste(to, text, method, enter, if (secret) "secret" else "text", tag, device, now, caSigner, adminCA)
    }

    /**
     * An action command that runs the quick action name on the member to,
     * signed with this phone's root or admin key; the member defines what
     * it does.
     */
    fun actionCommand(to: String, name: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.action(to, name, tag, device, now, caSigner, adminCA)
    }

    /** An actions-off command that turns every quick action off on the member to. */
    fun actionsOffCommand(to: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.actionsOff(to, tag, device, now, caSigner, adminCA)
    }

    /**
     * A hub command that makes the admin computer to the group's hub in
     * place of this phone (docs/protocol.md, section 11, "Moving the hub"),
     * signed with this phone's root or admin key, with the hub's clients
     * and its forwarder ("ip:port" and the pin of its key).
     */
    fun hubCommand(
        to: String,
        forwarder: Pair<String, String>?,
        clients: List<PhoneHub.Client>,
        caSigner: CertificateSigner,
        now: Instant,
    ): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        if (!records.mayHost(to)) throw Failure("only the group's root or an admin can be its hub")
        return Commands.hub(to, forwarder, emptyList(), clients.filter { it.device != to }, tag, device, now, caSigner, adminCA)
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
     * send. Only the root makes admins. keyStore is where the computer's
     * hello says its keys live; one that keeps them in a file becomes an
     * admin only with allowFileKey, else it throws FileKey.
     */
    fun makeAdmin(
        device: String,
        adminKey: ByteArray,
        rootSigner: CertificateSigner,
        now: Instant,
        keyStore: String? = null,
        allowFileKey: Boolean = false,
    ): Pair<ByteArray, Member.Record> {
        if (!isRoot) throw Failure("only the root makes admins")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        if (d.role != "full") throw Failure("not a computer")
        if (d.frozen) throw Failure("frozen: unfreeze it or remove it")
        val proven = d.store == Records.PROVEN
        val store = if (proven) d.store else Records.storeOf(keyStore, d.role)
        if (store == Records.FILE && !allowFileKey) throw FileKey()
        val ca = GroupCertificates.adminCA(device, adminKey, currentRoot, rootSigner)
        val r = record(
            device, d.name, d.role, d.key, rootSigner, now, Records.keyHashOfCert(ca), d.os, store,
            d.kind.takeIf { proven }, d.proof.takeIf { proven },
        )
        computerAdmins[device] = ca
        return ca to r
    }

    /**
     * Makes a watch an admin (section 10, rule 8): the root issues an admin
     * CA for the key the watch made in its Keystore or Secure Enclave
     * (adminKey, a SubjectPublicKeyInfo) and signs the watch's device
     * record, whose key and admin both name that CA, since a watch has no
     * member key. device is the ID the watch picked, os "wearos" or
     * "watchos". It returns the admin CA, for the watch, and the record to
     * send. Only the root does it; the watch checked its lock screen before
     * it made the key.
     */
    fun addWatch(
        device: String,
        name: String,
        os: String,
        adminKey: ByteArray,
        rootSigner: CertificateSigner,
        now: Instant,
    ): Pair<ByteArray, Member.Record> {
        if (!isRoot) throw Failure("only the root makes admins")
        if (device.length != 32 || device.any { it !in "0123456789abcdef" } || os !in setOf("wearos", "watchos") || devices.any { it.id == device }) {
            throw Failure(NOT_A_WATCH)
        }
        val n = name.trim()
        if (n.isEmpty() || validName(n) != n) throw Failure(INVALID_NAME)
        val ca = GroupCertificates.adminCA(device, adminKey, currentRoot, rootSigner)
        val key = Records.keyHashOfCert(ca)
        return ca to record(device, n, "watch", key, rootSigner, now, key, os, Records.HARDWARE)
    }

    /**
     * Checks the attestation a device sent of its member key (section 17,
     * "Evidence") and, on the root, returns a new device record with what
     * it shows when that differs from the device's record; null when there
     * is nothing to record. chain is the certificate chain the device
     * presented, leaf first. Throws AndroidAttestation.Invalid for a proof
     * of nothing.
     */
    fun evidence(
        device: String,
        chain: List<ByteArray>,
        e: Member.Evidence,
        rootSigner: CertificateSigner,
        now: Instant,
        roots: List<ByteArray>? = null,
        revoked: Set<String> = emptySet(),
    ): Member.Record? {
        if (!isRoot || chain.isEmpty() || e.format != Member.Evidence.ANDROID || e.key != Member.Evidence.MEMBER) return null
        val key = Records.keyHashOfCert(chain[0])
        val d = devices.firstOrNull { it.id == device && it.key.contentEquals(key) } ?: return null
        if (e.groupTag != null && e.groupTag != tag) throw AndroidAttestation.Invalid("an attestation made for another group")
        val challenge = try {
            Attestation.challenge(e.groupTag ?: "", ByteArray(0), e.salt)
        } catch (x: IllegalArgumentException) {
            throw AndroidAttestation.Invalid(x.message ?: "a bad salt")
        }
        val r = try {
            AndroidAttestation.check(e.chain, CertificateInfo(chain[0]).publicKey, challenge, AndroidAttestation.Policy(revoked = revoked, roots = roots))
        } catch (x: AndroidAttestation.Invalid) {
            // Revoked: the keys may still be in hardware, as the hello
            // says, but Google no longer vouches for the chain.
            if (!x.revoked) throw x
            if (d.store != Records.PROVEN) return null
            return record(device, d.name, d.role, d.key, rootSigner, now, d.adminKey, d.os, Records.HARDWARE, d.kind, null)
        }
        if (d.store == r.store && (d.kind ?: "") == r.kind) return null
        val proof = if (r.store == Records.PROVEN) sha256(e.chain[0]).joinToString("") { "%02x".format(it) } else null
        return record(device, d.name, d.role, d.key, rootSigner, now, d.adminKey, d.os, r.store, r.kind.ifEmpty { null }, proof)
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
     * addrs that are on a home network, where the phone dialed it. With
     * invitation, the device dialed this phone, the hub, with a remote
     * invitation (section 12): code is unused and the device never becomes
     * an admin.
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
        invitation: PairingMember.Invitation? = null,
    ): PairingMember.Admitted {
        if (!isAdmin) throw Failure("this phone is no admin")
        val first = groupCA
        val later = roots
        val root = currentRoot
        val ca = signingCA
        val issuer = adminCA
        val canMakeAdmins = isRoot && invitation == null
        var adminKey: ByteArray? = null
        val taken = { dev: String -> dev == device || records.knows(dev) }
        val admitted = PairingMember.admit(t, code, memberCert, joinerCert, sessionID, Pairing.MemberAD(device, tag), taken, invitation) { dev, publicKey, info ->
            val cert = GroupCertificates.member(dev, publicKey, ca, caSigner, now)
            val key = info.adminKey
            val forAdmin = if (Pairing.Info.isPhone(info.os) && key != null && makeAdmin && canMakeAdmins) {
                adminKey = key
                GroupCertificates.adminCA(dev, key, root, caSigner)
            } else {
                null
            }
            Pairing.Welcome(cert, first, issuer, forAdmin, later.ifEmpty { null }, if (later.isEmpty()) null else records.pathRecords)
        }
        val name = validName(admitted.info.name)
        val key = Records.keyHashOfCert(admitted.cert)
        if (Pairing.Info.isPhone(admitted.info.os)) {
            record(admitted.device, name, "phone", key, caSigner, now, adminKey?.let { Records.keyHash(it) }, admitted.info.os, Records.HARDWARE)
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
            g.record(device, validName(name), "phone", Records.keyHash(memberKey), caSigner, now, os = "android", store = Records.HARDWARE)
            return g
        }

        /** The message of the Failure for a name that the records do not accept. */
        const val INVALID_NAME = "a device name has 1 to 64 bytes and no control characters"
        const val NOT_A_WATCH = "the watch's request names a device ID or system that is not a new watch's"

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
            // The records that lead to the roots stay with the group, so the roots are those its records name.
            g.records.addAll(j.welcome.records.orEmpty(), j.welcome.groupCA)
            g.roots = g.records.roots
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
