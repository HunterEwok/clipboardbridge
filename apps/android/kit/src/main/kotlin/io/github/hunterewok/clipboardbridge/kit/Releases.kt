// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * The signed files that describe a release (docs/protocol.md, section 16),
 * checked as internal/release does: keys.json, in which a root key
 * certifies the release keys; release.json, which lists a release's files
 * with their hashes; and a channel file such as stable.json, which names
 * the current release of its channel until it expires. The same keys.json
 * certifies the status key that signs attest-status.json, the mirror of
 * Google's revocation list for Android attestations (section 17).
 */
object Releases {
    /** The largest body a file may carry. */
    const val MAX_BODY = 256 shl 10

    /** The longest a keys or channel file may stay valid after it was signed. */
    const val MAX_LIFETIME_MS = 100L * 24 * 3600 * 1000

    /** The longest attest-status.json stays valid after it was signed. */
    const val MAX_STATUS_LIFETIME_MS = 8L * 24 * 3600 * 1000

    /** The pinned root keys (SubjectPublicKeyInfos, DER); empty until the project's root keys exist. */
    val roots: List<ByteArray> = emptyList()

    const val USE_RELEASE = "release"
    const val USE_STATUS = "status"

    class Refused(message: String) : Exception(message)

    /** The envelope of every release file; key is SHA-256 of the signer's SubjectPublicKeyInfo. */
    class File(val body: ByteArray, val sig: ByteArray, val key: ByteArray) {
        /** SHA-256 over the body, which names a release.json. */
        val hash: ByteArray get() = sha256(body)

        internal fun verify(spkis: List<ByteArray>) {
            if (body.size > MAX_BODY) throw Refused("the file is too large")
            val spki = spkis.firstOrNull { sha256(it).contentEquals(key) } ?: throw Refused("the signature is not valid")
            if (!verifySignature(spki, body, sig)) throw Refused("the signature is not valid")
        }

        companion object {
            fun fromJson(o: JsonObject): File =
                File(o.optBytes("body") ?: ByteArray(0), o.optBytes("sig") ?: ByteArray(0), o.optBytes("key") ?: ByteArray(0))
        }
    }

    class Asset(val name: String, val size: Long, val sha256: String, val binaries: List<Pair<String, String>>)

    class Release(val version: String, val channel: String, val minFrom: String, val files: List<Asset>, val docker: Pair<String, String>?) {
        /** Whether a device at installed may update to this release in one step, or must first take minFrom. */
        fun direct(installed: String): Boolean = minFrom.isEmpty() || compare(installed, minFrom) >= 0

        /** Checks that data is the release's file name. */
        fun checkFile(name: String, data: ByteArray) {
            val a = files.firstOrNull { it.name == name } ?: throw Refused("$name is not in the release")
            if (a.size != data.size.toLong() || hex(sha256(data)) != a.sha256) throw Refused("$name does not match release.json")
        }
    }

    /** What a device keeps between checks: the highest sequence numbers and version it has taken. */
    data class Seen(val keysSeq: Long = 0, val channelSeq: Long = 0, val version: String = "", val statusSeq: Long = 0)

    /** The body of attest-status.json: the serial numbers Google's list revokes, as AndroidAttestation.Policy takes them. */
    class Status(val seq: Long, val timeMS: Long, val expiresMS: Long, val sourceMS: Long, val androidRevoked: List<String>)

    private val VERSION = Regex("^(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})(-rc\\.([1-9][0-9]{0,5}))?$")
    private val CHANNEL = Regex("^[a-z][a-z0-9-]{0,31}$")
    private val SHA256 = Regex("^[0-9a-f]{64}$")
    private val ASSET = Regex("^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
    private val BINARY = Regex("^[A-Za-z0-9_][A-Za-z0-9._/-]{0,255}$")
    private val DIGEST = Regex("^sha256:[0-9a-f]{64}$")
    private val SERIAL = Regex("^(0|[1-9a-f][0-9a-f]{0,63})$")

    /** X, Y, Z and the release candidate's number, Int.MAX_VALUE for a release. */
    private fun parseVersion(s: String): List<Int>? {
        val m = VERSION.matchEntire(s) ?: return null
        val g = m.groupValues
        return listOf(g[1].toInt(), g[2].toInt(), g[3].toInt(), if (g[5].isEmpty()) Int.MAX_VALUE else g[5].toInt())
    }

    /** Compares two versions X.Y.Z or X.Y.Z-rc.N, a release candidate before its release; a string that is not a version sorts below every version. */
    fun compare(a: String, b: String): Int {
        val pa = parseVersion(a)
        val pb = parseVersion(b)
        if (pa == null || pb == null) return (if (pa != null) 1 else 0) - (if (pb != null) 1 else 0)
        for (i in 0 until 4) if (pa[i] != pb[i]) return pa[i].compareTo(pb[i]).coerceIn(-1, 1)
        return 0
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun decode(body: ByteArray, type: String): JsonObject {
        val o = Wire.parse(body) ?: throw Refused("the file is not valid")
        val t = o.optString("type")
        if (t != type) throw Refused("the file is a \"$t\", not a \"$type\"")
        if (o.optLong("v") != 1L) throw Refused("unknown version")
        return o
    }

    private fun lifetime(o: JsonObject, max: Long = MAX_LIFETIME_MS): Long {
        val time = o.optLong("time_ms") ?: 0
        val expires = o.optLong("expires_ms") ?: 0
        if (expires <= time || expires - time > max) throw Refused("the file's lifetime is out of range")
        return expires
    }

    /** The keys of keys.json by use; a key of a use this reader does not know signs nothing. */
    private class Keys(val seq: Long, val expiresMS: Long, val uses: List<Pair<String, ByteArray>>) {
        fun spkis(use: String): List<ByteArray> = uses.filter { it.first == use }.map { it.second }
    }

    private fun decodeKeys(body: ByteArray): Keys {
        val o = decode(body, "keys")
        val seq = o.optLong("seq") ?: 0
        if (seq <= 0) throw Refused("keys.json has no sequence number")
        val expires = lifetime(o)
        val keys = o.optArray("keys")?.map { it.jsonObject } ?: emptyList()
        if (keys.isEmpty() || keys.size > 8) throw Refused("keys.json must hold 1 to 8 keys")
        val uses = keys.map { k ->
            val name = k.optString("name") ?: ""
            if (name.isEmpty() || name.toByteArray().size > 64) throw Refused("a key has no valid name")
            val spki = k.optBytes("key") ?: ByteArray(0)
            if (p256PublicKey(spki) == null) throw Refused("a key is not P-256")
            (k.optString("use") ?: USE_RELEASE) to spki
        }
        return Keys(seq, expires, uses)
    }

    private fun decodeRelease(body: ByteArray): Release {
        val o = decode(body, "release")
        val version = o.optString("version") ?: ""
        val minFrom = o.optString("min_from") ?: ""
        if (parseVersion(version) == null || (minFrom.isNotEmpty() && parseVersion(minFrom) == null)) {
            throw Refused("release.json names no valid version")
        }
        val channel = o.optString("channel") ?: ""
        val entries = o.optArray("files")?.map { it.jsonObject } ?: emptyList()
        if (!CHANNEL.matches(channel) || entries.isEmpty() || entries.size > 256) throw Refused("release.json is not valid")
        val names = HashSet<String>()
        val files = entries.map { a ->
            val name = a.optString("name") ?: ""
            if (!ASSET.matches(name) || !names.add(name)) throw Refused("\"$name\" is not a valid file name")
            val size = a.optLong("size") ?: -1
            val sum = a.optString("sha256") ?: ""
            val bins = a.optArray("binaries")?.map { it.jsonObject } ?: emptyList()
            if (size < 0 || !SHA256.matches(sum) || bins.size > 64) throw Refused("the entry for $name is not valid")
            Asset(name, size, sum, bins.map { b ->
                val bn = b.optString("name") ?: ""
                val bs = b.optString("sha256") ?: ""
                if (!BINARY.matches(bn) || ".." in bn || !SHA256.matches(bs)) throw Refused("a binary in $name is not valid")
                bn to bs
            })
        }
        val docker = o.optObject("docker")?.let { d ->
            val image = d.optString("image") ?: ""
            val digest = d.optString("digest") ?: ""
            if (image.isEmpty() || !DIGEST.matches(digest)) throw Refused("the Docker image is not valid")
            image to digest
        }
        return Release(version, channel, minFrom, files, docker)
    }

    /**
     * Checks a channel file and the release.json it names: keys.json under
     * the pinned roots (SubjectPublicKeyInfos, DER), the channel file and
     * release.json under its release keys, the channel's name, both expiries,
     * and that nothing is older than seen. Returns the release and the Seen
     * to keep.
     */
    fun check(keys: File, channel: File, release: File, roots: List<ByteArray>, name: String, nowMS: Long, seen: Seen): Pair<Release, Seen> {
        val k = verifyKeys(keys, roots, nowMS, seen)
        val (cSeq, cRelease, cHash) = try {
            channel.verify(k.spkis(USE_RELEASE))
            val o = decode(channel.body, "channel")
            val c = o.optString("channel") ?: ""
            val seq = o.optLong("seq") ?: 0
            if (!CHANNEL.matches(c) || seq <= 0) throw Refused("the channel file is not valid")
            val expires = lifetime(o)
            val rel = o.optString("release") ?: ""
            val hash = o.optString("release_sha256") ?: ""
            if (parseVersion(rel) == null || !SHA256.matches(hash)) throw Refused("the channel file names no valid release")
            if (c != name) throw Refused("the file is for the channel \"$c\"")
            if (nowMS >= expires) throw Refused("the file has expired")
            if (seq < seen.channelSeq) throw Refused("the file is older than one already seen")
            Triple(seq, rel, hash)
        } catch (e: Refused) {
            fail("$name.json", e)
        }
        val r = try {
            release.verify(k.spkis(USE_RELEASE))
            if (hex(release.hash) != cHash) throw Refused("it is not the release $name.json names")
            decodeRelease(release.body).also {
                if (it.version != cRelease || it.channel != name) throw Refused("it is ${it.version} on ${it.channel}, $name.json names $cRelease")
                if (seen.version.isNotEmpty() && compare(it.version, seen.version) < 0) throw Refused("it is older than a release already seen")
            }
        } catch (e: Refused) {
            fail("release.json", e)
        }
        val version = if (seen.version.isNotEmpty() && compare(seen.version, r.version) > 0) seen.version else r.version
        return r to Seen(k.seq, cSeq, version, seen.statusSeq)
    }

    private fun fail(file: String, e: Refused): Nothing = throw Refused("$file: ${e.message}")

    private fun verifyKeys(keys: File, roots: List<ByteArray>, nowMS: Long, seen: Seen): Keys = try {
        keys.verify(roots)
        decodeKeys(keys.body).also {
            if (nowMS >= it.expiresMS) throw Refused("the file has expired")
            if (it.seq < seen.keysSeq) throw Refused("the file is older than one already seen")
        }
    } catch (e: Refused) {
        fail("keys.json", e)
    }

    private fun serialLess(a: String, b: String): Boolean = if (a.length != b.length) a.length < b.length else a < b

    /**
     * Checks attest-status.json: keys.json under the pinned roots, the list
     * under a status key of it, its expiry, and that neither is older than
     * seen. Returns the list and the Seen to keep.
     */
    fun checkStatus(keys: File, status: File, roots: List<ByteArray>, nowMS: Long, seen: Seen): Pair<Status, Seen> {
        val k = verifyKeys(keys, roots, nowMS, seen)
        val st = try {
            status.verify(k.spkis(USE_STATUS))
            val o = decode(status.body, "attest-status")
            val seq = o.optLong("seq") ?: 0
            if (seq <= 0) throw Refused("attest-status.json has no sequence number")
            val expires = lifetime(o, MAX_STATUS_LIFETIME_MS)
            val list = o.optArray("android_revoked")?.map { e ->
                (e as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw Refused("attest-status.json lists a number that is not a string")
            } ?: throw Refused("attest-status.json has no list")
            list.forEachIndexed { i, s ->
                if (!SERIAL.matches(s) || (i > 0 && !serialLess(list[i - 1], s))) throw Refused("\"$s\" is not a serial number in order")
            }
            if (nowMS >= expires) throw Refused("the file has expired")
            if (seq < seen.statusSeq) throw Refused("the file is older than one already seen")
            Status(seq, o.optLong("time_ms") ?: 0, expires, o.optLong("source_ms") ?: 0, list)
        } catch (e: Refused) {
            fail("attest-status.json", e)
        }
        return st to seen.copy(keysSeq = k.seq, statusSeq = st.seq)
    }
}
