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
        // freeze: the records of the frozen admins that still count; thaw:
        // the freeze records it ends. Both are record IDs.
        val records: List<ByteArray>? = null,
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
                "records" to Wire.list(records),
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
                        records = o.optBytesList("records"),
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

    /** A thaw record that ends the freeze records with the IDs freezes (docs/protocol.md, section 10, rule 4). */
    fun thaw(freezes: List<ByteArray>, group: String, by: String, now: Instant, signer: CertificateSigner, adminCA: ByteArray? = null): Member.Record =
        sign(Body(type = "thaw", group = group, timeMS = now.toEpochMilli(), by = by, records = freezes), signer, adminCA)

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

    /** The records each signer signed, an admin CA or a root's own key ([MAX_PER_ADMIN]). */
    private val perSigner = mutableMapOf<Key, Int>()

    /**
     * The roots records may be signed under: the group CA and the new root of every root record that may make it a
     * known root ([mayBeKnown]); the other root records wait in [pending], as Go's group.Records.
     */
    private val rootList = mutableListOf<ByteArray>()
    private val pending = mutableListOf<Triple<ByteArray, Key, Key>>() // the new root, its anchor and its signer

    /** For each root, the admin CAs that device records its own key signed name ([NAMED_PHONE] or [NAMED_OTHER]), and the roles of its own device records. */
    private val named = mutableMapOf<Key, MutableMap<Key, Int>>()
    private val own = mutableMapOf<Key, Int>()

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
        /** An admin computer another admin froze: no admin until the root or an admin phone unfreezes it, and refused. */
        val frozen: Boolean = false,
        /** Every key that a counting device record names for it and that is not revoked, key among them: what removing it revokes. */
        val keys: List<ByteArray> = listOf(key),
    ) {
        override fun equals(other: Any?): Boolean =
            other is Device && id == other.id && name == other.name && role == other.role && os == other.os && key.contentEquals(other.key) &&
                admin == other.admin && adminKey.contentEqualsOrNull(other.adminKey) && frozen == other.frozen &&
                keys.size == other.keys.size && keys.zip(other.keys).all { (a, b) -> a.contentEquals(b) }

        override fun hashCode(): Int = id.hashCode()
    }

    private fun known(id: ByteArray): Boolean = list.any { Records.id(it).contentEquals(id) }

    /**
     * Adds a record signed under one of the group's roots, by the root's
     * key or by an admin CA the root certified (its chain holds that CA),
     * unless it is known; reports whether it was new. Records of another
     * group are refused, and so is a record signed under a root that no
     * root record in the set may make known yet. The limits are checked
     * after the signature: [MAX_PER_ADMIN] for each signer, and past [MAX]
     * only records a path root's own key signed, up to [MAX_PER_ADMIN] more.
     */
    fun add(r: Member.Record, groupCA: ByteArray): Boolean {
        if (this.groupCA == null) this.groupCA = groupCA
        if (!this.groupCA.contentEqualsOrNull(groupCA) || known(Records.id(r))) return false
        if (rootList.isEmpty()) rootList.add(groupCA)
        val body = Records.Body.decode(r.body) ?: return false
        if (body.v != Records.VERSION || body.group != GroupCertificates.tag(groupCA)) return false
        val anchor = anchor(r, rootList) ?: return false
        val anchorKey = runCatching { Key(Records.keyHashOfCert(anchor.first)) }.getOrNull() ?: return false
        if (body.type == "root") {
            val pathLength = runCatching { ParsedCertificate(anchor.first).pathLength }.getOrNull()
            val root = body.root ?: return false
            if (pathLength != 1 || runCatching { GroupCertificates.checkRoot(root) }.isFailure) return false
        }
        val signer = Key(anchor.second)
        val n = perSigner[signer] ?: 0
        if (n >= MAX_PER_ADMIN) return false
        if (list.size >= MAX && (list.size >= MAX + MAX_PER_ADMIN || signer != anchorKey || anchorKey !in Eval(this).onPath)) return false
        perSigner[signer] = n + 1
        list.add(r)
        if (body.type == "device" && signer == anchorKey) {
            val bit = if (Records.role(body.role) == "phone") NAMED_PHONE else NAMED_OTHER
            body.admin?.let { a -> named.getOrPut(anchorKey) { mutableMapOf() }.merge(Key(a), bit) { x, y -> x or y } }
            if (body.device != null && body.device == body.by) own.merge(anchorKey, bit) { x, y -> x or y }
        }
        body.root?.let { if (body.type == "root") pending.add(Triple(it, anchorKey, signer)) }
        promote()
        return true
    }

    /** Moves the root records of [pending] that may make their new root known into [rootList], until none does. */
    private fun promote() {
        var grew = true
        while (grew) {
            grew = false
            val iter = pending.iterator()
            while (iter.hasNext()) {
                val (root, anchor, signer) = iter.next()
                if (!mayBeKnown(anchor, signer)) continue
                iter.remove()
                if (rootList.none { r -> r.contentEquals(root) }) {
                    rootList.add(root)
                    grew = true
                }
            }
        }
    }

    /**
     * Whether a root record signed under anchor by signer may make its new root a known root, leaving out the
     * revocations and freezes that can still stop it: the root's own key signed it, or an admin CA that a phone's
     * device record from that root's own key names, or one a computer's names when that root is a computer. A root
     * that a computer's admin CA names in a phone's group is never known, so nothing signed under it enters the set.
     */
    private fun mayBeKnown(anchor: Key, signer: Key): Boolean {
        val n = named[anchor]?.get(signer) ?: 0
        return signer == anchor || (n and NAMED_PHONE) != 0 || ((n and NAMED_OTHER) != 0 && own[anchor] == NAMED_OTHER)
    }

    /**
     * Adds every record of rs that is valid, until nothing new is added,
     * so that a record signed under a new root is taken together with the
     * records that make that root known, in any order; returns the new ones.
     */
    fun addAll(rs: List<Member.Record>, groupCA: ByteArray): List<Member.Record> {
        val fresh = mutableListOf<Member.Record>()
        var pending = rs
        while (true) {
            val rest = mutableListOf<Member.Record>()
            val roots = rootList.size
            for (r in pending) {
                if (add(r, groupCA)) {
                    fresh.add(r)
                } else if (!known(Records.id(r))) {
                    rest.add(r)
                }
            }
            if (rootList.size == roots || rest.isEmpty()) return fresh
            pending = rest
        }
    }

    /** The roots records may be signed under ([rootList]). */
    private fun knownRoots(groupCA: ByteArray): List<ByteArray> = rootList.ifEmpty { listOf(groupCA) }

    private class Entry(
        val record: Member.Record,
        val body: Records.Body,
        /** The record ID. */
        val id: Key,
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

        /**
         * The known roots: the group CA and the new roots that a known root or an admin phone under one handed the
         * group to, or an admin computer under a root that is a computer.
         */
        var known: Set<Key> = emptySet()

        /** The freezes that count, for each frozen admin CA (rule 4). */
        val freezes = mutableMapOf<Key, MutableList<Entry>>()

        /** The device keys of the frozen admins. */
        val frozenKeys = mutableSetOf<Key>()

        /** The roots from the group CA to the current one, DER. */
        val path = mutableListOf<ByteArray>()

        /** The root records that lead along [path], one for each root after the group CA. */
        val steps = mutableListOf<Entry>()
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
                    Entry(r, b, Key(Records.id(r)), Key(a.second), Key(anchor))
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
                        if (k in onPath || e.signer in revoked || !fromRoot(e) || !mayHandOver(e)) null else Triple(root, k, e)
                    }.minWithOrNull { x, y -> compareBytes(sha256(x.first), sha256(y.first)) } ?: break
                    path.add(next.first)
                    onPath.add(next.second)
                    steps.add(next.third)
                }
            }
        }

        private fun rootKey(der: ByteArray): Key? = runCatching { Key(Records.keyHashOfCert(der)) }.getOrNull()

        /** Whether a known root's own key signed e. */
        fun rootSigned(e: Entry): Boolean = e.signer == e.anchor && e.anchor in known

        /**
         * Whether the signer of a root record may hand the group over: a known root's own key, an admin phone's
         * admin CA, or a computer's admin CA when the root it replaces is a computer too (computerHandOver).
         */
        fun mayHandOver(e: Entry): Boolean =
            rootSigned(e) || (e.signer in phoneAdmin && e.anchor in known) || (e.anchor in known && computerHandOver(e))

        /**
         * Whether e, a root record, was signed by the admin CA of a computer under its anchor, a root that is a
         * computer itself, and only that root's own records stop it: a revocation of the admin CA, or a freeze of it
         * that the root or another admin CA it certified (and did not revoke) signed and the root did not thaw, as
         * Go's group.Records.computerHandOver (docs/protocol.md, section 10, rule 2).
         */
        private fun computerHandOver(e: Entry): Boolean {
            if (e.body.root == null || e.signer == e.anchor) return false
            val root = e.anchor
            val admins = mutableSetOf<Key>()
            val revokedByRoot = mutableSetOf<Key>()
            val thawed = mutableSetOf<Key>()
            var computer = false
            for (o in entries) {
                val b = o.body
                if (o.signer != root || o.anchor != root) continue
                when (b.type) {
                    "revoke" -> b.keys.orEmpty().forEach { revokedByRoot.add(Key(it)) }
                    "thaw" -> b.records.orEmpty().forEach { thawed.add(Key(it)) }
                    "device" -> {
                        val own = b.device != null && b.device == b.by
                        if (own && Records.role(b.role) == "phone") return false
                        if (own && Records.role(b.role) == "full") computer = true
                        if (b.admin != null && Records.role(b.role) != "phone") admins.add(Key(b.admin))
                    }
                }
            }
            if (!computer || e.signer !in admins || e.signer in revokedByRoot) return false
            return entries.none { o ->
                o.body.type == "freeze" && o.anchor == root && o.body.keys.orEmpty().any { Key(it) == e.signer } &&
                    o.id !in thawed && (o.signer == root || (o.signer in admins && o.signer !in revokedByRoot))
            }
        }

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
                    if (e.body.type != "root" || e.anchor !in k) continue
                    if (e.signer != e.anchor && e.signer !in phones && !computerHandOver(e)) continue
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
            // The device keys of each computer's admin CA, and the freezes that
            // a root or an admin phone ended.
            val computers = mutableMapOf<Key, MutableList<Key>>()
            val thawed = mutableSetOf<Key>()
            for (e in entries) {
                val b = e.body
                val admin = b.admin
                val key = b.key
                if (b.type == "device" && admin != null && key != null && Records.role(b.role) != "phone" && rootSigned(e) && Key(admin) !in phoneAdmin) {
                    computers.getOrPut(Key(admin)) { mutableListOf() }.add(Key(key))
                } else if (b.type == "thaw" && (rootSigned(e) || (e.signer in phoneAdmin && e.anchor in known && e.signer !in disabled))) {
                    b.records.orEmpty().forEach { thawed.add(Key(it)) }
                }
            }
            // A frozen admin's freezes still count, so two admins that freeze
            // each other both stay frozen until the root or an admin phone
            // decides.
            for (e in entries) {
                if (e.body.type != "freeze" || e.id in thawed || e.anchor !in known) continue
                if (e.signer != e.anchor && (e.signer in disabled || !standsForRoots(e.anchor, e.signer))) continue
                val keys = e.body.keys.orEmpty().map { Key(it) }
                if (keys.isEmpty() || keys.any { it !in computers }) continue
                for (key in keys) {
                    freezes.getOrPut(key) { mutableListOf() }.add(e)
                    frozenKeys.addAll(computers[key].orEmpty())
                }
            }
            for (e in entries) {
                if (e.body.type != "revoke" || !kept(e)) continue
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

        /** Whether every freeze of e's signer names e, as for the records of an admin that is not frozen. */
        fun kept(e: Entry): Boolean =
            freezes[e.signer].orEmpty().all { f -> f.body.records.orEmpty().any { Key(it) == e.id } }

        /** Whether a key is frozen: a frozen admin CA, or the device key of a frozen admin. */
        fun frozen(k: Key): Boolean = k in freezes || k in frozenKeys

        /** Whether a device record counts. */
        fun counts(e: Entry): Boolean =
            e.anchor in onPath && fromRoot(e) && issued(e.signer, Key(e.body.key ?: ByteArray(0))) && kept(e)

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

    /** Whether a key hash is frozen (docs/protocol.md, section 10, rule 4): a computer's admin CA that a freeze names, or such an admin's device key. */
    fun isFrozen(keyHash: ByteArray): Boolean = Eval(this).frozen(Key(keyHash))

    /**
     * Whether a command (docs/protocol.md, section 15) is signed by an
     * admin of the group now: a root on the path, or an admin CA under one
     * that is neither revoked nor frozen, as Go's Records.VerifyCommand.
     */
    fun signedByAdmin(c: Member.Record): Boolean {
        val groupCA = groupCA ?: return false
        val a = anchor(c, knownRoots(groupCA)) ?: return false
        val anchor = runCatching { Key(Records.keyHashOfCert(a.first)) }.getOrNull() ?: return false
        val body = Records.Body(v = Records.VERSION, type = "command", group = "", timeMS = 0)
        val e = Entry(c, body, Key(Records.id(c)), Key(a.second), anchor)
        val ev = Eval(this)
        return anchor in ev.onPath && e.signer !in ev.revoked && !ev.frozen(e.signer) && ev.fromRoot(e)
    }

    /** The IDs of the freezes of the admin CA with key hash admin that count: what a thaw of it ends. */
    fun freezesOf(admin: ByteArray): List<ByteArray> =
        Eval(this).freezes[Key(admin)].orEmpty().map { Records.id(it.record) }.sortedWith { a, b -> compareBytes(a, b) }

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
        if (ev.frozen(leaf)) return "the device is a frozen admin"
        var top = leafCert
        // The issuer is the certificate that signed the leaf, wherever it is
        // in the chain: a peer may add certificates it does not need.
        if (ev.path.none { GroupCertificates.signed(leafCert, it) }) {
            val issuer = chain.drop(1).firstOrNull { GroupCertificates.signed(leafCert, it) }
                ?: return "the certificate's issuer is not in its chain"
            val admin = runCatching { Key(Records.keyHashOfCert(issuer)) }.getOrNull()
                ?: return "the certificate's issuer is not in its chain"
            if (!ev.issued(admin, leaf)) return "the admin that admitted the device was removed"
            // A frozen admin's certificates hold only for devices the records
            // already list.
            if (ev.frozen(admin) && ev.entries.none { it.body.type == "device" && it.body.key?.let { k -> Key(k) } == leaf && ev.counts(it) }) {
                return "the admin that certified the device is frozen"
            }
            top = issuer
            leaf = admin
        }
        // The chain must end at a root on the path: a root that only the identity trusts, as one a Welcome
        // named, is no anchor.
        val root = ev.path.firstOrNull { GroupCertificates.signed(top, it) } ?: return "the certificate is not from a root of the group"
        val rk = runCatching { Key(Records.keyHashOfCert(root)) }.getOrNull()
        if (rk != null && !ev.issued(rk, leaf)) return "the certificate is from a root that handed the group over"
        return null
    }

    /**
     * The records that lead to the path: each root record on it and, for one an admin CA signed, the device records
     * its root's own key signed that name that admin CA or the root's own device, as Go's Records.PathRecords. A new
     * member gets them in the Welcome's records (docs/protocol.md, section 5).
     */
    val pathRecords: List<Member.Record>
        get() {
            val ev = Eval(this)
            val out = mutableListOf<Member.Record>()
            for (st in ev.steps) {
                out.add(st.record)
                if (st.signer == st.anchor) continue
                ev.entries.filter { e ->
                    val b = e.body
                    b.type == "device" && e.signer == st.anchor && e.anchor == st.anchor &&
                        ((b.device != null && b.device == b.by) || b.admin?.let { Key(it) } == st.signer)
                }.sortedWith { a, b -> compareBytes(Records.id(a.record), Records.id(b.record)) }.forEach { out.add(it.record) }
            }
            return out
        }

    /**
     * The records that say who governs the group, as Go's Records.AuthorityRecords: the path records, every record
     * that is no device record (revocations, freezes, thaws, roots), and of the device records a root signed with its
     * own key those of a root's own device and of every device that one of them ever made an admin, all of them, so
     * that a later one that demotes it counts. A phone hub sends them to its forwarder (docs/protocol.md, section 13);
     * the other devices' records, with their names, stay in the group.
     */
    val authorityRecords: List<Member.Record>
        get() {
            val seen = mutableSetOf<String>()
            val out = mutableListOf<Member.Record>()
            fun add(r: Member.Record) {
                if (seen.add(Key(Records.id(r)).hex)) out.add(r)
            }
            pathRecords.forEach(::add)
            val ev = Eval(this)
            val governs = ev.entries.filter { e ->
                val b = e.body
                b.type == "device" && e.signer == e.anchor && (b.admin != null || (b.device != null && b.device == b.by))
            }.mapNotNull { it.body.device }.toSet()
            for (e in ev.entries.sortedBy { it.id.hex }) {
                if (e.body.type != "device" || (e.signer == e.anchor && e.body.device in governs)) add(e.record)
            }
            return out
        }

    /**
     * The devices list: the latest device record that counts for each
     * device (by time, then record ID) among those whose key is not
     * revoked, sorted by name. A device record counts when it was signed
     * under a root on the path, by an admin CA that still stands under it,
     * and its signer is not revoked, or every revocation of the signer keeps
     * the device's key. A device whose records name more than one key stays
     * listed while any of them is not revoked, as Go's Records.Devices.
     */
    val devices: List<Device>
        get() {
            val ev = Eval(this)
            val latest = mutableMapOf<String, Entry>()
            val keys = mutableMapOf<String, MutableList<ByteArray>>()
            for (e in ev.entries.sortedBy { it.id.hex }) { // by record ID, as Go, so the keys come in the same order
                val b = e.body
                if (b.type != "device") continue
                val d = b.device ?: continue
                val k = b.key ?: continue
                if (!ev.counts(e) || Key(k) in ev.revoked) continue
                val ks = keys.getOrPut(d) { mutableListOf() }
                if (ks.none { it.contentEquals(k) }) ks.add(k)
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
                val admin = e.body.admin?.let { Key(it) }
                Device(
                    d, e.body.name ?: d, Records.role(e.body.role), key, admin?.let { it !in ev.revoked && !ev.frozen(it) } ?: false, e.body.admin,
                    Records.os(e.body), ev.frozen(Key(key)) || (admin != null && ev.frozen(admin)), keys[d].orEmpty(),
                )
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
        val ev = Eval(this)
        for (e in ev.entries) {
            val k = e.body.key
            if (e.body.type == "device" && e.signer == Key(admin) && k != null && ev.kept(e) && keys.none { it.contentEquals(k) }) keys.add(k)
        }
        return keys
    }

    /** Whether a valid device record names the device ID, with any key and whether or not it counts: an ID a new device may not take (section 6). */
    fun knows(device: String): Boolean = list.any { Records.Body.decode(it.body)?.let { b -> b.type == "device" && b.device == device } == true }

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
     * phone or a computer, as Go's Records.RootMember) or a device listed as
     * an admin whose admin CA is not revoked (docs/protocol.md, section 11).
     * Only by device ID: MemberNode passes on an offer only from a peer
     * that mayHost(device, chain) takes, which also checks the key.
     */
    fun mayHost(device: String): Boolean =
        devices.any { it.id == device && it.admin } || rootMember()?.let { (id, key) -> id == device && key !in Eval(this).revoked } == true

    /**
     * mayHost for a peer whose verified certificate chain (leaf first) is
     * chain: the record that makes it the root or an admin must name the
     * key of its certificate, since a device ID alone is what a joining
     * device picks itself.
     */
    fun mayHost(device: String, chain: List<ByteArray>): Boolean {
        val leaf = chain.firstOrNull() ?: return false
        val key = runCatching { Key(Records.keyHashOfCert(leaf)) }.getOrNull() ?: return false
        if (devices.any { it.id == device && it.admin && Key(it.key) == key }) return true
        val (id, own) = rootMember() ?: return false
        return id == device && own == key && key !in Eval(this).revoked
    }

    /**
     * The devices that may be the group's hub, highest first, as Go's
     * Records.HubOrder (docs/protocol.md, section 11, "Several hubs"):
     * phones before computers, within each the root first, then by device ID.
     */
    val hubOrder: List<String>
        get() {
            val root = rootMember()?.takeIf { (_, key) -> key !in Eval(this).revoked }?.first
            return devices.filter { it.id == root || it.admin }
                .sortedWith(compareBy<Device>({ it.role != "phone" }, { it.id != root }, { it.id }))
                .map { it.id }
        }

    /** The root's own device and its key: the newest full or phone device record the current root signed for itself. */
    private fun rootMember(): Pair<String, Key>? {
        val ev = Eval(this)
        val cur = ev.path.lastOrNull()?.let { runCatching { Key(Records.keyHashOfCert(it)) }.getOrNull() } ?: return null
        val own = ev.entries.filter {
            it.signer == cur && it.body.type == "device" && Records.role(it.body.role) in setOf("phone", "full") &&
                it.body.device != null && it.body.device == it.body.by
        }.maxByOrNull { it.body.timeMS } ?: return null
        return (own.body.device ?: return null) to Key(own.body.key ?: return null)
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

        /**
         * Records one signer (an admin CA, or a root's own key) signs at most, so a stolen admin cannot fill the set;
         * past [MAX] the set still takes this many records from a path root's own key, so it takes the root's removal
         * of an admin that filled it.
         */
        const val MAX_PER_ADMIN = 1024

        private const val NAMED_PHONE = 1
        private const val NAMED_OTHER = 2

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
