// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The manifest of a media event: images or files (docs/protocol.md,
 * section 4, "Media"), checked as Go's package clip does. The kit takes the
 * event and its plain-text alternative; fetching the content comes later.
 */
object Media {
    /** The largest copy, all its parts together, that the group carries. */
    const val MAX_MEDIA = 1L shl 30
    const val MAX_PARTS = 10_000
    const val MAX_TYPES = 8
    const val MAX_PATHS = 512 shl 10
    const val MAX_PATH = 4096
    const val MAX_NAME = 255

    /** The largest plain-text alternative of a media event, in bytes of UTF-8. */
    const val MAX_ALT_TEXT = 256 shl 10

    val TYPES = setOf("image/png", "image/jpeg", "text/html")

    /** What a media event's content is. */
    data class Manifest(val size: Long, val parts: List<Part>) {
        /** Whether it is a copy of files, not clipboard data. */
        val isFiles: Boolean get() = parts.firstOrNull()?.path != null

        /** Whether it passes Go's Manifest.Validate. */
        val isValid: Boolean
            get() {
                if (parts.isEmpty() || parts.size > MAX_PARTS) return false
                val files = isFiles
                if (!files && parts.size > MAX_TYPES) return false
                var total = 0L
                var paths = 0
                val seen = HashSet<String>()
                for (p in parts) {
                    val key = if (files) {
                        if (p.path == null || p.type != null || !checkPath(p.path)) return false
                        paths += p.path.toByteArray().size
                        p.path
                    } else {
                        if (p.type == null || p.dir || p.type !in TYPES) return false
                        p.type
                    }
                    if (!seen.add(key)) return false
                    if (p.dir) {
                        if (p.size != 0L || p.sha256 != null) return false
                        continue
                    }
                    if (p.sha256?.size != 32 || p.size < 0 || p.size > MAX_MEDIA) return false
                    total += p.size
                }
                if (paths > MAX_PATHS || total != size || total > MAX_MEDIA) return false
                if (files) {
                    val dirs = parts.associate { it.path!! to it.dir }
                    for (p in parts) {
                        var i = p.path!!.indexOf('/')
                        while (i >= 0) {
                            if (dirs[p.path.substring(0, i)] == false) return false
                            i = p.path.indexOf('/', i + 1)
                        }
                    }
                }
                return true
            }

        fun toJson(): JsonObject = Wire.obj(
            "size" to Wire.num(size),
            "parts" to JsonArray(parts.map { it.toJson() }),
        )

        companion object {
            fun fromJson(o: JsonObject): Manifest = Manifest(
                o.optLong("size") ?: 0,
                o.optArray("parts")?.map { Part.fromJson(it as? JsonObject ?: throw WireTypeException("parts: not an object")) } ?: emptyList(),
            )
        }
    }

    /** One item of a manifest: clipboard data of a type, or a file or folder at a path. */
    class Part(
        val type: String? = null,
        val path: String? = null,
        val dir: Boolean = false,
        val size: Long = 0,
        val sha256: ByteArray? = null,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Part && type == other.type && path == other.path && dir == other.dir && size == other.size &&
                sha256.contentEqualsOrNull(other.sha256)

        override fun hashCode(): Int = (type ?: path).hashCode()

        fun toJson(): JsonObject = Wire.obj(
            "type" to Wire.str(type),
            "path" to Wire.str(path),
            "dir" to if (dir) JsonPrimitive(true) else null,
            "size" to Wire.num(size.takeIf { it != 0L }),
            "sha256" to Wire.bytes(sha256?.takeIf { it.isNotEmpty() }),
        )

        companion object {
            fun fromJson(o: JsonObject): Part = Part(
                o.optString("type")?.takeIf { it.isNotEmpty() },
                o.optString("path")?.takeIf { it.isNotEmpty() },
                o.optBool("dir") ?: false,
                o.optLong("size") ?: 0,
                // An empty hash stays: a folder has none, as in Go, not even an empty one.
                o.optBytes("sha256"),
            )
        }
    }

    /** Whether path is names joined by "/", each one checkName takes, at most MAX_PATH bytes. */
    fun checkPath(path: String): Boolean =
        path.isNotEmpty() && path.toByteArray().size <= MAX_PATH && path.split('/').all { checkName(it) }

    /**
     * A name that checkName takes, made of one a system gave, as Go's
     * clip.CleanName: the characters it does not allow become "_", a
     * reserved name gets "_" after its base and one that ends in a dot or a
     * space gets "_" after it.
     */
    fun cleanName(given: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < given.length) {
            val cp = given.codePointAt(i)
            i += Character.charCount(cp)
            val bad = cp in 0xd800..0xdfff || cp < 0x20 || cp == 0x7f || cp in 0x80..0x9f || (cp < 0x80 && cp.toChar() in "/\\:*?\"<>|")
            if (bad) sb.append('_') else sb.appendCodePoint(cp)
        }
        // What fixName adds can take the name past MAX_NAME, so the name
        // loses characters at its end until the fixed name fits.
        var name = sb.toString()
        while (true) {
            if (name.isEmpty() || name == "." || name == "..") return "_"
            val fixed = fixName(name)
            if (fixed.toByteArray().size <= MAX_NAME) return fixed
            val cp = name.codePointBefore(name.length)
            name = name.substring(0, name.length - Character.charCount(cp))
        }
    }

    /** Gives a reserved name "_" after its base and one that ends in a dot or a space "_" after it. */
    private fun fixName(given: String): String {
        var name = given
        // CON.txt becomes CON_.txt: Windows reserves the base with any extension.
        if (reserved(name)) name = name.substringBefore('.') + "_" + if ('.' in name) "." + name.substringAfter('.') else ""
        if (name.endsWith('.') || name.endsWith(' ')) name += "_"
        return name
    }

    /**
     * Whether a name of a path is one every system can hold, as Go's
     * clip.CheckName decides: 1 to 255 bytes, not "." or "..", no control
     * characters, separators or characters Windows does not allow, no dot
     * or space at the end, no name Windows reserves.
     */
    fun checkName(name: String): Boolean {
        val bytes = name.toByteArray().size
        if (bytes == 0 || bytes > MAX_NAME || name == "." || name == "..") return false
        if (name.any { it in "/\\:*?\"<>|" || it < ' ' || it == '\u007f' || it in '\u0080'..'\u009f' }) return false
        if (name.endsWith('.') || name.endsWith(' ')) return false
        return !reserved(name)
    }

    /** Whether name, before its first dot, is a device name of Windows: CON, PRN, AUX, NUL, COM1 to COM9 and LPT1 to LPT9, in any case. */
    private fun reserved(name: String): Boolean {
        val base = name.substringBefore('.').uppercase()
        if (base in setOf("CON", "PRN", "AUX", "NUL")) return true
        return base.length == 4 && (base.startsWith("COM") || base.startsWith("LPT")) && base[3] in '1'..'9'
    }
}
