// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import java.time.Instant
import java.util.Base64

/**
 * The group's signed device, revocation and root records (docs/protocol.md,
 * section 10), as internal/group/records.go makes and reads them. The root
 * phone signs them with the root key, without a chain; an admin signs them
 * with its admin CA key, and the chain holds the admin CA.
 */
object Records {
    const val VERSION = 1

    /** A record body; the fields depend on its type. */
    data class Body(
        val v: Int = VERSION,
        val type: String,
        val group: String,
        val timeMS: Long,
        val by: String? = null,
        // device
        val device: String? = null,
        val name: String? = null,
        val role: String? = null,
        val os: String? = null,
        val key: ByteArray? = null,
        val admin: ByteArray? = null,
        // revoke
        val keys: List<ByteArray>? = null,
        val keep: List<ByteArray>? = null,
        // root
        val root: ByteArray? = null,
    ) {
        fun encode(): ByteArray = Wire.encode(
            Wire.obj(
                "v" to Wire.num(v.toLong()),
                "type" to Wire.str(type),
                "group" to Wire.str(group),
                "time_ms" to Wire.num(timeMS),
                "by" to Wire.str(by),
                "device" to Wire.str(device),
                "name" to Wire.str(name),
                "role" to Wire.str(role),
                "os" to Wire.str(os),
                "key" to Wire.bytes(key),
                "admin" to Wire.bytes(admin),
                "keys" to Wire.list(keys),
                "keep" to Wire.list(keep),
                "root" to Wire.bytes(root),
            ),
        )

        companion object {
            /** The body in data, or null when it does not decode. */
            fun decode(data: ByteArray): Body? {
                val o = Wire.parse(data) ?: return null
                return try {
                    Body(
                        v = o.optLong("v")?.toInt() ?: return null,
                        type = o.optString("type") ?: return null,
                        group = o.optString("group") ?: return null,
                        timeMS = o.optLong("time_ms") ?: return null,
                        by = o.optString("by"),
                        device = o.optString("device"),
                        name = o.optString("name"),
                        role = o.optString("role"),
                        os = o.optString("os"),
                        key = o.optBytes("key"),
                        admin = o.optBytes("admin"),
                        keys = o.optBytesList("keys"),
                        keep = o.optBytesList("keep"),
                        root = o.optBytes("root"),
                    )
                } catch (e: WireTypeException) {
                    null
                }
            }
        }
    }

    /** The hash that names a key in records: SHA-256 over a SubjectPublicKeyInfo. */
    fun keyHash(spki: ByteArray): ByteArray = sha256(spki)

    /** The hash of the key a certificate certifies. */
    fun keyHashOfCert(cert: ByteArray): ByteArray = keyHash(CertificateInfo(cert).publicKey)

    /** A record's ID: SHA-256 over its body. */
    fun id(r: Member.Record): ByteArray = sha256(r.body)

    /** Signs a body with the group CA key (the phone's root), or with an admin CA key when adminCA is that CA's certificate. */
    fun sign(body: Body, signer: CertificateSigner, adminCA: ByteArray? = null): Member.Record {
        val data = body.encode()
        return Member.Record(data, signer.signature(data), adminCA?.let { listOf(it) })
    }

    /** A device record. admin is the key hash of the device's admin CA, for an admin. */
    fun device(
        device: String,
        name: String,
        role: String,
        key: ByteArray,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        admin: ByteArray? = null,
        adminCA: ByteArray? = null,
        os: String? = null,
    ): Member.Record =
        sign(
            Body(type = "device", group = group, timeMS = now.toEpochMilli(), by = by, device = device, name = name, role = role, os = os, key = key, admin = admin),
            signer,
            adminCA,
        )

    /** The role a record names, with the roles of earlier records read as today's: "linux" and "mac" as "full", "iphone" as "shortcut". */
    fun role(r: String?): String = when (r) {
        "linux", "mac" -> "full"
        "iphone" -> "shortcut"
        else -> r ?: ""
    }

    /** The system a record names, or the one its earlier role implies; null when neither tells. */
    fun os(b: Body): String? = b.os ?: when (b.role) {
        "mac" -> "macos"
        "iphone", "shortcut" -> "ios"
        else -> null
    }

    /** A revocation record for keys; keep names the keys of devices that a revoked admin admitted and that stay. */
    fun revoke(
        keys: List<ByteArray>,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        keep: List<ByteArray>? = null,
        adminCA: ByteArray? = null,
    ): Member.Record = sign(Body(type = "revoke", group = group, timeMS = now.toEpochMilli(), by = by, keys = keys, keep = keep), signer, adminCA)

    /** A root record that hands the group to newRoot, a phone's root CA. */
    fun root(newRoot: ByteArray, group: String, by: String, now: Instant, signer: CertificateSigner, adminCA: ByteArray? = null): Member.Record =
        sign(Body(type = "root", group = group, timeMS = now.toEpochMilli(), by = by, root = newRoot), signer, adminCA)
}

/** Bytes compared by content, for sets and maps. */
internal data class Key(val hex: String) {
    constructor(b: ByteArray) : this(b.toHex())
}

/**
 * The record set of a group: verified records, which only grow, and what
 * they say. Like the Go side, what it says depends on the set alone.
 */
class RecordSet {
    private val list = mutableListOf<Member.Record>()
    val records: List<Member.Record> get() = list

    /** The records each admin CA signed ([MAX_PER_ADMIN]). */
    private val perSigner = mutableMapOf<Key, Int>()

    /** The group's first root, which names it; the first add sets it. */
    var groupCA: ByteArray? = null
        internal set

    /** A device as the list shows it. */
    data class Device(
        val id: String,
        val name: String,
        /** "full", "phone", "lite" or "shortcut". */
        val role: String,
        val key: ByteArray,
        /** Whether it is an admin whose admin CA is not revoked. */
        val admin: Boolean = false,
        /** The key hash of its admin CA, for an admin. */
        val adminKey: ByteArray? = null,
        /** Its operating system; null when its record does not tell. */
        val os: String? = null,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Device && id == other.id && name == other.name && role == other.role && os == other.os && key.contentEquals(other.key) &&
                admin == other.admin && adminKey.contentEqualsOrNull(other.adminKey)

        override fun hashCode(): Int = id.hashCode()
    }

    private fun known(id: ByteArray): Boolean = list.any { Records.id(it).contentEquals(id) }

    /**
     * Adds a record signed under one of the group's roots, by the root's
     * key or by an admin CA the root certified (its chain holds that CA),
     * unless it is known; reports whether it was new. Records of another
     * group are refused, and so is a record signed under a root that no
     * root record in the set names yet.
     */
    fun add(r: Member.Record, groupCA: ByteArray): Boolean {
        if (this.groupCA == null) this.groupCA = groupCA
        if (!this.groupCA.contentEqualsOrNull(groupCA) || known(Records.id(r)) || list.size >= MAX) return false
        val body = Records.Body.decode(r.body) ?: return false
        if (body.v != Records.VERSION || body.group != GroupCertificates.tag(groupCA)) return false
        val anchor = anchor(r, knownRoots(groupCA)) ?: return false
        if (body.type == "root") {
            val pathLength = runCatching { ParsedCertificate(anchor.first).pathLength }.getOrNull()
            val root = body.root ?: return false
            if (pathLength != 1 || runCatching { GroupCertificates.checkRoot(root) }.isFailure) return false
        }
        if (!r.chain.isNullOrEmpty()) {
            val signer = Key(anchor.second)
            val n = perSigner[signer] ?: 0
            if (n >= MAX_PER_ADMIN) return false
            perSigner[signer] = n + 1
        }
        list.add(r)
        return true
    }

    /**
     * Adds every record of rs that is valid, until nothing new is added,
     * so that a record signed under a new root is taken together with the
     * root record that names it, in any order; returns the new ones.
     */
    fun addAll(rs: List<Member.Record>, groupCA: ByteArray): List<Member.Record> {
        val fresh = mutableListOf<Member.Record>()
        var pending = rs
        while (true) {
            val rest = mutableListOf<Member.Record>()
            var rooted = false
            for (r in pending) {
                if (add(r, groupCA)) {
                    fresh.add(r)
                    rooted = rooted || Records.Body.decode(r.body)?.type == "root"
                } else if (!known(Records.id(r))) {
                    rest.add(r)
                }
            }
            if (!rooted || rest.isEmpty()) return fresh
            pending = rest
        }
    }

    /** The roots records may be signed under: the group CA and the new root of every root record in the set. */
    private fun knownRoots(groupCA: ByteArray): List<ByteArray> {
        val roots = mutableListOf(groupCA)
        for (r in list) {
            val b = Records.Body.decode(r.body) ?: continue
            val root = b.root
            if (b.type == "root" && root != null && roots.none { it.contentEquals(root) }) roots.add(root)
        }
        return roots
    }

    private class Entry(
        val record: Member.Record,
        val body: Records.Body,
        /** The key hash of the signer: a root, or an admin CA. */
        val signer: Key,
        /** The key hash of the root it was signed under. */
        val anchor: Key,
    )

    /**
     * What the set says, worked out once for a question: the records with
     * their signers, the revoked keys and the path of roots. Revocations
     * are worked out in strata that do not depend on each other in a
     * circle, as Go's group.Records.eval (docs/protocol.md, section 10,
     * rules 2 and 3).
     */
    private class Eval(set: RecordSet) {
        val entries: List<Entry>
        val revoked = mutableSetOf<Key>()

        /** The records that revoked each key. */
        val revokers = mutableMapOf<Key, MutableList<Entry>>()

        /** The admin CAs of admin phones, which a root recorded. */
        val phoneAdmin = mutableSetOf<Key>()

        /** The known roots: the group CA and the new roots that a known root or an admin phone under one handed the group to. */
        var known: Set<Key> = emptySet()

        /** The roots from the group CA to the current one, DER. */
        val path = mutableListOf<ByteArray>()
        val onPath = mutableSetOf<Key>()

        init {
            val groupCA = set.groupCA
            if (groupCA == null) {
                entries = emptyList()
            } else {
                val roots = set.knownRoots(groupCA)
                entries = set.list.mapNotNull { r ->
                    val b = Records.Body.decode(r.body) ?: return@mapNotNull null
                    val a = anchor(r, roots) ?: return@mapNotNull null
                    val anchor = runCatching { Records.keyHashOfCert(a.first) }.getOrNull() ?: return@mapNotNull null
                    Entry(r, b, Key(a.second), Key(anchor))
                }
                evaluate(groupCA, roots)
                // From each root, the root record under it that counts and
                // whose new root has the smallest SHA-256 leads to the next.
                path.add(groupCA)
                onPath.add(runCatching { Key(Records.keyHashOfCert(groupCA)) }.getOrDefault(Key("")))
                while (true) {
                    val cur = runCatching { Key(Records.keyHashOfCert(path.last())) }.getOrNull() ?: break
                    val next = entries.mapNotNull { e ->
                        val root = e.body.root
                        if (e.body.type != "root" || e.anchor != cur || root == null) return@mapNotNull null
                        val k = runCatching { Key(Records.keyHashOfCert(root)) }.getOrNull() ?: return@mapNotNull null
                        if (k in onPath || e.signer in revoked || !fromRoot(e) || !mayHandOver(e)) null else root to k
                    }.minWithOrNull { x, y -> compareBytes(sha256(x.first), sha256(y.first)) } ?: break
                    path.add(next.first)
                    onPath.add(next.second)
                }
            }
        }

        private fun rootKey(der: ByteArray): Key? = runCatching { Key(Records.keyHashOfCert(der)) }.getOrNull()

        /** Whether a known root's own key signed e. */
        fun rootSigned(e: Entry): Boolean = e.signer == e.anchor && e.anchor in known

        /** Whether the signer of a root record may hand the group over: a known root's own key or an admin phone's admin CA, never a computer's. */
        fun mayHandOver(e: Entry): Boolean = rootSigned(e) || (e.signer in phoneAdmin && e.anchor in known)

        /** The admin CA key that e, a device record of a phone signed by the own key of one of roots, names; null for any other record. */
        private fun phoneAdminOf(e: Entry, roots: Set<Key>): Key? {
            val admin = e.body.admin ?: return null
            if (e.body.type != "device" || Records.role(e.body.role) != "phone" || e.signer != e.anchor || e.signer !in roots) return null
            return Key(admin)
        }

        private fun evaluate(groupCA: ByteArray, roots: List<ByteArray>) {
            val all = roots.mapNotNull(::rootKey).toSet()
            // The known roots, until nothing is added.
            val k = mutableSetOf<Key>()
            rootKey(groupCA)?.let(k::add)
            while (true) {
                val phones = entries.mapNotNull { phoneAdminOf(it, k) }.toSet()
                var grew = false
                for (e in entries) {
                    val root = e.body.root ?: continue
                    if (e.body.type != "root" || e.anchor !in k || (e.signer != e.anchor && e.signer !in phones)) continue
                    val rk = rootKey(root) ?: continue
                    if (k.add(rk)) grew = true
                }
                if (!grew) break
            }
            known = k
            val byRoot = mutableMapOf<Key, MutableList<Entry>>()
            val privileged = all.toMutableSet()
            for (e in entries) {
                if (e.body.type == "revoke" && rootSigned(e)) {
                    for (key in e.body.keys.orEmpty()) byRoot.getOrPut(Key(key)) { mutableListOf() }.add(e)
                } else if (e.body.type == "device") {
                    e.body.admin?.let { privileged.add(Key(it)) }
                }
                if (e.signer != e.anchor) privileged.add(e.signer)
            }
            fun standsForRoots(issuer: Key, key: Key): Boolean =
                byRoot[issuer].orEmpty().all { r -> r.body.keep.orEmpty().any { Key(it) == key } }
            for (e in entries) {
                val a = phoneAdminOf(e, known) ?: continue
                if (standsForRoots(e.signer, a)) phoneAdmin.add(a)
            }
            val disabled = mutableSetOf<Key>()
            for (e in entries) {
                val fromPhone = e.signer in phoneAdmin && e.anchor in known
                if (e.body.type != "revoke" || !(rootSigned(e) || fromPhone)) continue
                for (raw in e.body.keys.orEmpty()) {
                    val key = Key(raw)
                    if (key in privileged && (rootSigned(e) || key !in known)) {
                        disabled.add(key)
                        revoked.add(key)
                        revokers.getOrPut(key) { mutableListOf() }.add(e)
                    }
                }
            }
            for (e in entries) {
                if (e.body.type != "revoke") continue
                val keys = e.body.keys.orEmpty().map { Key(it) }
                val counts = if (e.signer == e.anchor) {
                    e.anchor in known
                } else {
                    e.anchor in known && e.signer !in disabled && standsForRoots(e.anchor, e.signer) &&
                        keys.none { it in known || (it in privileged && e.signer !in phoneAdmin) }
                }
                if (!counts) continue
                for (key in keys) {
                    val rs = revokers.getOrPut(key) { mutableListOf() }
                    if (rs.none { it === e }) {
                        rs.add(e)
                        revoked.add(key)
                    }
                }
            }
        }

        /** Whether issuer is revoked only by records that keep the key k, as when an admin is removed and the devices it admitted stay. */
        fun kept(issuer: Key, k: Key): Boolean {
            val rs = revokers[issuer].orEmpty()
            return rs.isNotEmpty() && rs.all { e -> e.body.keep.orEmpty().any { Key(it) == k } }
        }

        /** Whether what issuer certified, the key k, still stands. */
        fun issued(issuer: Key, k: Key): Boolean = issuer !in revoked || kept(issuer, k)

        /** Whether the admin CA that signed a record still stands under its root; a root's own signature always does. */
        fun fromRoot(e: Entry): Boolean = e.signer == e.anchor || issued(e.anchor, e.signer)
    }

    /** The revoked keys (docs/protocol.md, section 10, rule 3). */
    val revoked: Set<String> get() = Eval(this).revoked.map { it.hex }.toSet()

    /** Whether a key hash is revoked. */
    fun isRevoked(keyHash: ByteArray): Boolean = Key(keyHash) in Eval(this).revoked

    /** The roots that took the group over from the group CA, in order, DER; the last is the current root. Empty when it was never handed over. */
    val roots: List<ByteArray> get() = Eval(this).path.drop(1)

    /**
     * Why a member certificate chain (leaf first, then its admin CA when
     * one issued it) is refused, or null; the chain is verified already. A
     * certificate is refused when its key is revoked, or its issuer's key
     * is revoked and not every record that revoked the issuer keeps it:
     * for the leaf and, when an admin CA issued it, for that admin CA under
     * its root.
     */
    fun refused(chain: List<ByteArray>): String? {
        val leafCert = chain.firstOrNull() ?: return "no certificate"
        var leaf = runCatching { Key(Records.keyHashOfCert(leafCert)) }.getOrNull() ?: return "no certificate"
        val ev = Eval(this)
        if (leaf in ev.revoked) return "the device was removed from the group"
        var top = leafCert
        // The issuer is the certificate that signed the leaf, wherever it is
        // in the chain: a peer may add certificates it does not need.
        if (ev.path.none { GroupCertificates.signed(leafCert, it) }) {
            val issuer = chain.drop(1).firstOrNull { GroupCertificates.signed(leafCert, it) }
                ?: return "the certificate's issuer is not in its chain"
            val admin = runCatching { Key(Records.keyHashOfCert(issuer)) }.getOrNull()
                ?: return "the certificate's issuer is not in its chain"
            if (!ev.issued(admin, leaf)) return "the admin that admitted the device was removed"
            top = issuer
            leaf = admin
        }
        val root = ev.path.firstOrNull { GroupCertificates.signed(top, it) }
        if (root != null) {
            val rk = runCatching { Key(Records.keyHashOfCert(root)) }.getOrNull()
            if (rk != null && !ev.issued(rk, leaf)) return "the certificate is from a root that handed the group over"
        }
        return null
    }

    /**
     * The devices list: the latest device record that counts for each
     * device (by time, then record ID), less the revoked keys, sorted by
     * name. A device record counts when it was signed under a root on the
     * path, by an admin CA that still stands under it, and its signer is
     * not revoked, or every revocation of the signer keeps the device's key.
     */
    val devices: List<Device>
        get() {
            val ev = Eval(this)
            val latest = mutableMapOf<String, Entry>()
            for (e in ev.entries) {
                val b = e.body
                if (b.type != "device") continue
                val d = b.device ?: continue
                if (e.anchor !in ev.onPath || !ev.fromRoot(e) || !ev.issued(e.signer, Key(b.key ?: ByteArray(0)))) continue
                val cur = latest[d]
                if (cur != null) {
                    val newer = if (b.timeMS != cur.body.timeMS) {
                        b.timeMS > cur.body.timeMS
                    } else {
                        compareBytes(Records.id(e.record), Records.id(cur.record)) >= 0
                    }
                    if (!newer) continue
                }
                latest[d] = e
            }
            return latest.mapNotNull { (d, e) ->
                val key = e.body.key ?: return@mapNotNull null
                if (Key(key) in ev.revoked) return@mapNotNull null
                Device(d, e.body.name ?: d, Records.role(e.body.role), key, e.body.admin?.let { Key(it) !in ev.revoked } ?: false, e.body.admin, Records.os(e.body))
            }.sortedWith(compareBy({ it.name }, { it.id }))
        }

    /**
     * The keys that revocations signed by the admin CA with key hash admin
     * revoked and that count: what the record that removes that admin
     * names again, so its removals stand once its own records no longer
     * count (section 10).
     */
    fun revokedBy(admin: ByteArray): List<ByteArray> {
        val ev = Eval(this)
        val keys = mutableListOf<ByteArray>()
        for (e in ev.entries) {
            if (e.body.type != "revoke" || e.signer != Key(admin)) continue
            for (k in e.body.keys.orEmpty()) {
                if (ev.revokers[Key(k)].orEmpty().any { it === e } && keys.none { it.contentEquals(k) }) keys.add(k)
            }
        }
        return keys
    }

    /**
     * The keys of the devices whose records the CA with key hash admin
     * signed (an admin CA, or a root's own key): the devices it admitted,
     * which stay when it is removed.
     */
    fun admitted(admin: ByteArray): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        for (e in Eval(this).entries) {
            val k = e.body.key
            if (e.body.type == "device" && e.signer == Key(admin) && k != null && keys.none { it.contentEquals(k) }) keys.add(k)
        }
        return keys
    }

    /**
     * The phone that holds the root: the one whose own record the current
     * root's key signed (a phone records itself when it makes the group,
     * and again when it takes the group over).
     */
    val rootDevice: String?
        get() {
            val ev = Eval(this)
            val cur = ev.path.lastOrNull()?.let { runCatching { Key(Records.keyHashOfCert(it)) }.getOrNull() } ?: return null
            return ev.entries.filter {
                it.signer == cur && it.body.type == "device" && it.body.role == "phone" && it.body.device != null && it.body.device == it.body.by
            }.maxByOrNull { it.body.timeMS }?.body?.device
        }

    /**
     * Whether device may be the group's hub for sync away from home: the
     * root (a device whose own record the current root's key signed, a
     * phone or a computer, as Go's Records.RootDevice) or a device listed as
     * an admin whose admin CA is not revoked (docs/protocol.md, section 11).
     */
    fun mayHost(device: String): Boolean {
        if (devices.any { it.id == device && it.admin }) return true
        val ev = Eval(this)
        val cur = ev.path.lastOrNull()?.let { runCatching { Key(Records.keyHashOfCert(it)) }.getOrNull() } ?: return false
        val own = ev.entries.filter {
            it.signer == cur && it.body.type == "device" && Records.role(it.body.role) in setOf("phone", "full") &&
                it.body.device != null && it.body.device == it.body.by
        }.maxByOrNull { it.body.timeMS } ?: return false
        val key = own.body.key ?: return false
        return own.body.device == device && Key(key) !in ev.revoked
    }

    /** SHA-256 over the sorted record IDs, base64, as the hello carries it; null for an empty set. */
    val digest: String?
        get() {
            if (list.isEmpty()) return null
            val ids = list.map { Records.id(it) }.sortedWith { a, b -> compareBytes(a, b) }
            val h = java.security.MessageDigest.getInstance("SHA-256")
            for (id in ids) h.update(id)
            return Base64.getEncoder().encodeToString(h.digest())
        }

    /** The set as JSON, to keep it: the group CA and the records. */
    fun toJson(): ByteArray = Wire.encode(
        Wire.obj("group_ca" to Wire.bytes(groupCA), "records" to kotlinx.serialization.json.JsonArray(list.map { it.toJson() })),
    )

    companion object {
        /** Records beyond this many are refused. */
        const val MAX = 4096

        /** Records one admin CA signs at most, so a stolen admin cannot fill the set. */
        const val MAX_PER_ADMIN = 1024

        /** A set kept with toJson; records that no longer verify are dropped. */
        fun fromJson(data: ByteArray): RecordSet {
            val s = RecordSet()
            val o = Wire.parse(data) ?: return s
            val ca = runCatching { o.optBytes("group_ca") }.getOrNull() ?: return s
            val rs = runCatching { o.optArray("records")?.map { Member.Record.fromJson(it as kotlinx.serialization.json.JsonObject) } }.getOrNull()
            s.addAll(rs.orEmpty(), ca)
            s.groupCA = ca
            return s
        }

        /**
         * The root a record was signed under and the key hash of its signer:
         * a root's own key without a chain, an admin CA under a root with one;
         * null when the signature is not valid under any of roots.
         */
        private fun anchor(r: Member.Record, roots: List<ByteArray>): Pair<ByteArray, ByteArray>? {
            val chain = r.chain.orEmpty()
            return when (chain.size) {
                0 -> {
                    for (root in roots) {
                        val spki = runCatching { CertificateInfo(root).publicKey }.getOrNull() ?: continue
                        if (verifySignature(spki, r.body, r.sig)) return root to Records.keyHash(spki)
                    }
                    null
                }
                1 -> {
                    val root = roots.firstOrNull { runCatching { GroupCertificates.checkAdminCA(chain[0], it) }.isSuccess } ?: return null
                    val spki = runCatching { CertificateInfo(chain[0]).publicKey }.getOrNull() ?: return null
                    if (verifySignature(spki, r.body, r.sig)) root to Records.keyHash(spki) else null
                }
                else -> null
            }
        }
    }
}

/** Compares bytes as unsigned, lexicographically, as Swift's and Go's byte comparisons do. */
internal fun compareBytes(a: ByteArray, b: ByteArray): Int {
    for (i in 0 until minOf(a.size, b.size)) {
        val c = (a[i].toInt() and 0xff).compareTo(b[i].toInt() and 0xff)
        if (c != 0) return c
    }
    return a.size.compareTo(b.size)
}
