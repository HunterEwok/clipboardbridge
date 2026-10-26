// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import java.io.Closeable
import java.io.OutputStream
import java.security.MessageDigest

/**
 * The images and files a member holds whole, which it serves to its peers
 * (docs/protocol.md, section 4, "Content"), as Go's node.Content.
 */
interface ContentStore {
    /** The part whose SHA-256 is sum, or null when this phone does not hold all of it. The node closes it. */
    fun open(sum: ByteArray): ContentSource?
}

/** One part a ContentStore opened. */
interface ContentSource : Closeable {
    val size: Long

    /** Reads length bytes from offset, which are all there. */
    fun read(offset: Long, length: Int): ByteArray

    override fun close() {}
}

/**
 * A ContentStore in memory, for the phone's own copies: it keeps the parts
 * of the last few manifests it was given, at most maxBytes together.
 */
class MemoryContent(private val maxBytes: Long = Media.MAX_MEDIA) : ContentStore {
    private val parts = LinkedHashMap<String, ByteArray>()

    /** Keeps the bytes of a part, dropping the oldest beyond maxBytes; it returns its SHA-256. */
    fun put(bytes: ByteArray): ByteArray = synchronized(this) {
        val sum = sha256(bytes)
        val key = sum.toHex()
        parts.remove(key)
        parts[key] = bytes
        var total = parts.values.sumOf { it.size.toLong() }
        val it = parts.entries.iterator()
        while (total > maxBytes && parts.size > 1 && it.hasNext()) {
            val e = it.next()
            if (e.key == key) continue
            total -= e.value.size
            it.remove()
        }
        sum
    }

    override fun open(sum: ByteArray): ContentSource? = synchronized(this) {
        parts[sum.toHex()]?.let { b ->
            object : ContentSource {
                override val size = b.size.toLong()
                override fun read(offset: Long, length: Int) = b.copyOfRange(offset.toInt(), offset.toInt() + length)
            }
        }
    }

    companion object {
        fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    }
}

/** Fetching the content of media events from the connected members. */
object Content {
    /**
     * The manifest of clipboard data: one part per type, such as an image
     * as "image/png" or "image/jpeg", whose bytes store keeps to serve them.
     */
    fun manifest(store: MemoryContent, data: List<Pair<String, ByteArray>>): Media.Manifest {
        val parts = data.map { (type, bytes) -> Media.Part(type = type, size = bytes.size.toLong(), sha256 = store.put(bytes)) }
        return Media.Manifest(parts.sumOf { it.size }, parts)
    }

    class TooLarge(val size: Long, val limit: Long) : Exception("the copy is $size bytes, more than the limit of $limit")

    /**
     * Fetches part of event from the connected members that serve content,
     * its origin first, into out, and checks its hash. It throws when no
     * member has it whole, the part is over limit or does not match.
     */
    fun fetch(node: MemberNode, event: Member.Event, part: Media.Part, out: () -> OutputStream, limit: Long = Media.MAX_MEDIA) {
        val sum = part.sha256 ?: throw IllegalArgumentException("a folder has no content")
        if (part.size > limit) throw TooLarge(part.size, limit)
        val peers = node.mediaPeers.sortedBy { if (it == event.origin) 0 else 1 }
        if (peers.isEmpty()) throw MemberNode.ProtocolException("no member that serves images and files is connected")
        var last: Exception? = null
        for (p in peers) {
            val h = MessageDigest.getInstance("SHA-256")
            try {
                out().use { o ->
                    node.fetch(p, sum, part.size) { _, data ->
                        h.update(data)
                        o.write(data)
                    }
                }
                if (h.digest().contentEquals(sum)) return
                last = MemberNode.ProtocolException("the part does not match its hash")
            } catch (e: InterruptedException) {
                throw e
            } catch (e: Exception) {
                last = e
            }
        }
        throw last!!
    }

    /** The bytes of part of event, as fetch gets them. */
    fun bytes(node: MemberNode, event: Member.Event, part: Media.Part, limit: Long = Media.MAX_MEDIA): ByteArray {
        var b = java.io.ByteArrayOutputStream()
        fetch(node, event, part, { java.io.ByteArrayOutputStream().also { b = it } }, limit)
        return b.toByteArray()
    }
}
