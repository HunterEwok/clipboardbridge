// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Base64

/**
 * The pairing messages of docs/protocol.md, section 6, encoded as the Go
 * side encodes them: JSON objects whose byte fields are standard base64,
 * in frames of a 4-byte big-endian length.
 */
object Pairing {
    /** The ALPN protocol of pairing connections. */
    const val ALPN = "clipboardbridge-pair/1"

    /** The TLS exporter label for the CPace session ID. */
    const val EXPORTER_LABEL = "EXPERIMENTAL-clipboardbridge-pair-v1"

    /** Frames larger than this are refused. */
    const val MAX_FRAME = 64 shl 10

    private val CHANNEL_PREFIX = "clipboardbridge pair v1\u0000".toByteArray()

    /** One frame of the exchange; each uses some of the fields. */
    class Frame(
        val msg: ByteArray? = null,
        val ad: ByteArray? = null,
        val tag: ByteArray? = null,
        val welcome: Welcome? = null,
        val error: String? = null,
        val ok: Boolean? = null,
    ) {
        fun toJson(): JsonObject = Wire.obj(
            "msg" to Wire.bytes(msg),
            "ad" to Wire.bytes(ad),
            "tag" to Wire.bytes(tag),
            "welcome" to welcome?.toJson(),
            "error" to Wire.str(error),
            "ok" to ok?.let { JsonPrimitive(it) },
        )

        companion object {
            fun fromJson(o: JsonObject): Frame = Frame(
                msg = o.optBytes("msg"),
                ad = o.optBytes("ad"),
                tag = o.optBytes("tag"),
                welcome = o.optObject("welcome")?.let { Welcome.fromJson(it) },
                error = o.optString("error"),
                ok = o.opt("ok")?.let { (it as? JsonPrimitive)?.takeIf { p -> !p.isString }?.booleanOrNull ?: throw WireTypeException("ok") },
            )
        }
    }

    /**
     * What a new device receives: its member certificate, the group CA
     * and, for a Linux device in a group rooted in a Linux member, the CA
     * keys. A phone root never sends keys; it may send a joining phone its
     * admin CA.
     */
    class Welcome(
        val cert: ByteArray,
        /** The group's first root, which names it. */
        val groupCA: ByteArray,
        /** The admin CA that issued cert and the admitting phone's own certificate; null when the group CA did. */
        val issuer: ByteArray? = null,
        /** For a phone that joins as an admin: the admin CA the root issued for the admin key the phone sent in its Info. */
        val adminCA: ByteArray? = null,
        /** The roots that took a phone group over from groupCA, in order; null when it was never handed over (section 10, "Roots"). */
        val roots: List<ByteArray>? = null,
        /** The records that lead to roots (RecordSet.pathRecords), by which the joiner checks them; null with roots. */
        val records: List<Member.Record>? = null,
        val groupCAKey: ByteArray? = null,
        val phoneCA: ByteArray? = null,
        val phoneCAKey: ByteArray? = null,
    ) {
        fun toJson(): JsonObject = Wire.obj(
            "cert" to Wire.bytes(cert),
            "issuer" to Wire.bytes(issuer),
            "group_ca" to Wire.bytes(groupCA),
            "roots" to Wire.list(roots),
            "records" to records?.let { rs -> kotlinx.serialization.json.JsonArray(rs.map { it.toJson() }) },
            "group_ca_key" to Wire.bytes(groupCAKey),
            "phone_ca" to Wire.bytes(phoneCA),
            "phone_ca_key" to Wire.bytes(phoneCAKey),
            "admin_ca" to Wire.bytes(adminCA),
        )

        companion object {
            fun fromJson(o: JsonObject): Welcome = Welcome(
                cert = o.optBytes("cert") ?: throw WireTypeException("welcome without cert"),
                groupCA = o.optBytes("group_ca") ?: throw WireTypeException("welcome without group_ca"),
                issuer = o.optBytes("issuer"),
                adminCA = o.optBytes("admin_ca"),
                roots = o.optBytesList("roots"),
                records = o.optArray("records")?.map { Member.Record.fromJson(it as? JsonObject ?: throw WireTypeException("a record is not an object")) },
                groupCAKey = o.optBytes("group_ca_key"),
                phoneCA = o.optBytes("phone_ca"),
                phoneCAKey = o.optBytes("phone_ca_key"),
            )
        }
    }

    /** The joiner's CPace associated data. */
    data class Info(
        val name: String,
        /** "linux", "windows", "macos", "ios" for an iPhone with the app, "android", or "none" for a lite member's firmware. */
        val os: String,
        /** A phone's admin key, a SubjectPublicKeyInfo, for the admin CA the root may issue it; only from a phone. */
        val adminKey: ByteArray? = null,
        /** LITE for a lite member, which only dials and never holds CA keys; null for a full device. */
        val role: String? = null,
    ) {
        /**
         * Checks it as the member does: a known OS, a printable name of 1
         * to 64 bytes, a known role, and an admin key only from a phone, a
         * P-256 one.
         */
        val isValid: Boolean
            get() {
                if ((os !in OSES && !(os == "none" && role == LITE)) || name.isEmpty() || name.toByteArray().size > 64 || hasControl(name)) return false
                if (role != null && role != LITE) return false
                val k = adminKey ?: return true
                return isPhone(os) && p256PublicKey(k) != null
            }

        fun encode(): ByteArray = Wire.encode(Wire.obj("name" to Wire.str(name), "os" to Wire.str(os), "admin_key" to Wire.bytes(adminKey), "role" to Wire.str(role)))

        override fun equals(other: Any?): Boolean =
            other is Info && name == other.name && os == other.os && adminKey.contentEqualsOrNull(other.adminKey) && role == other.role

        override fun hashCode(): Int = name.hashCode()

        companion object {
            val OSES = setOf("linux", "windows", "macos", "ios", "android")

            /** The role of a lite member. */
            const val LITE = "lite"

            /** Whether a joiner's OS is a phone's, which joins as a phone and may become an admin. */
            fun isPhone(os: String): Boolean = os == "ios" || os == "android"

            fun decode(data: ByteArray): Info? {
                val o = Wire.parse(data) ?: return null
                return try {
                    Info(o.optString("name") ?: return null, o.optString("os") ?: return null, o.optBytes("admin_key"), o.optString("role"))
                } catch (e: WireTypeException) {
                    null
                }
            }
        }
    }

    /** The member's CPace associated data. */
    data class MemberAD(val device: String, val group: String) {
        fun encode(): ByteArray = Wire.encode(Wire.obj("device" to Wire.str(device), "group" to Wire.str(group)))

        companion object {
            fun decode(data: ByteArray): MemberAD? {
                val o = Wire.parse(data) ?: return null
                return try {
                    MemberAD(o.optString("device") ?: return null, o.optString("group") ?: return null)
                } catch (e: WireTypeException) {
                    null
                }
            }
        }
    }

    /** The error codes that travel in frames. Anything else means "refused". */
    enum class ErrorCode(val wire: String) {
        WRONG_CODE("wrong-code"), CLOSED("closed"), BUSY("busy"), EXPIRED("expired"), TOO_MANY("too-many"), TAKEN("taken"), REFUSED("refused");

        companion object {
            fun of(wire: String): ErrorCode = entries.firstOrNull { it.wire == wire } ?: REFUSED
        }
    }

    class FrameException(message: String) : Exception(message)

    /** The CPace channel identifier: the prefix, then SHA-256 of the member's and the joiner's certificate, in that order. */
    fun channelID(memberCert: ByteArray, joinerCert: ByteArray): ByteArray = CHANNEL_PREFIX + sha256(memberCert) + sha256(joinerCert)

    /** The fingerprint a join QR code carries: SHA-256 of the certificate, in base64url without padding. */
    fun fingerprint(cert: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(cert))

    /** Encodes a frame: the length, then the JSON. */
    fun encode(f: Frame): ByteArray {
        val body = Wire.encode(f.toJson())
        if (body.size > MAX_FRAME) throw FrameException("frame too large")
        return Member.frame(body)
    }

    /** Decodes the body of a frame whose length was read already. */
    fun decode(body: ByteArray): Frame {
        val o = Wire.parse(body) ?: throw FrameException("not a frame")
        return try {
            Frame.fromJson(o)
        } catch (e: WireTypeException) {
            throw FrameException("not a frame: ${e.message}")
        }
    }

    /** The length a frame header announces, or an error when too large. */
    fun length(header: ByteArray): Int =
        try {
            Member.length(header, MAX_FRAME)
        } catch (e: Member.WireException) {
            throw FrameException(e.message ?: "bad frame header")
        }

    internal fun hasControl(s: String): Boolean = s.codePoints().anyMatch { Character.getType(it) == Character.CONTROL.toInt() }
}

/**
 * What the QR code of cbb pair carries (docs/protocol.md, section 7):
 * clipboardbridge://join?code=123456&addr=host:port&fp=...
 */
data class JoinCode(val code: String, val addrs: List<String>, val fingerprint: String) {
    /** Whether the code is six digits, as the computer expects. */
    val codeIsValid: Boolean get() = code.length == 6 && code.all { it in '0'..'9' }

    /** The text of the QR code, as cbb pair shows it. */
    val qrText: String
        get() {
            val items = listOf("code" to code) + addrs.take(MAX_ADDRS).map { "addr" to it } + listOf("fp" to fingerprint)
            return "clipboardbridge://join?" + items.joinToString("&") { "${it.first}=${escape(it.second)}" }
        }

    companion object {
        /** At most this many addresses are kept. */
        const val MAX_ADDRS = 4

        /**
         * Parses the text of a join QR code; null when it is not one. Unknown
         * fields are ignored, and addresses without a port are dropped.
         */
        fun parse(text: String): JoinCode? {
            val t = text.trim()
            val sep = t.indexOf("://")
            if (sep < 0 || !t.substring(0, sep).equals("clipboardbridge", ignoreCase = true)) return null
            val rest = t.substring(sep + 3).substringBefore('#')
            val host = rest.takeWhile { it != '/' && it != '?' }
            if (!host.equals("join", ignoreCase = true)) return null
            val query = rest.substringAfter('?', "")
            val items = query.split('&').filter { it.isNotEmpty() }.mapNotNull { item ->
                val k = unescape(item.substringBefore('=')) ?: return@mapNotNull null
                val v = unescape(item.substringAfter('=', "")) ?: return@mapNotNull null
                k to v
            }
            val code = items.firstOrNull { it.first == "code" }?.second
            if (code.isNullOrEmpty()) return null
            val fp = items.firstOrNull { it.first == "fp" }?.second ?: ""
            val addrs = items.filter { it.first == "addr" }.map { it.second }.filter { hasPort(it) }.take(MAX_ADDRS)
            return JoinCode(code, addrs, fp)
        }

        /** Whether a host:port, or [IPv6]:port, has a port. */
        internal fun hasPort(a: String): Boolean {
            val i = a.lastIndexOf(':')
            if (i < 0) return false
            val port = a.substring(i + 1).toIntOrNull() ?: return false
            if (port !in 1..65535 || !a.substring(i + 1).all { it in '0'..'9' }) return false
            val host = a.substring(0, i)
            if (host.startsWith("[")) return host.endsWith("]")
            return host.isNotEmpty() && ':' !in host
        }

        /** Whether a host:port, or [IPv6]:port, is on a home network: a private IPv4 or unique local IPv6 address. */
        fun isHome(a: String): Boolean {
            if (!hasPort(a)) return false
            val host = a.substring(0, a.lastIndexOf(':'))
            return if (host.startsWith("[")) LocalAddresses.isHomeIPv6(host.substring(1, host.length - 1)) else LocalAddresses.isHomeIPv4(host)
        }

        private val random = SecureRandom()

        /** A new six-digit code. */
        fun newCode(): String = "%06d".format(random.nextInt(1_000_000))

        /** host:port, or [IPv6]:port, as a QR code carries an address. */
        fun address(host: String, port: Int): String = if (':' in host) "[$host]:$port" else "$host:$port"

        /** Percent-decoding, as URL components decode a query; null for a bad escape or bad UTF-8. */
        private fun unescape(s: String): String? {
            val b = s.toByteArray()
            val out = ByteArrayOutputStream()
            var i = 0
            while (i < b.size) {
                if (b[i] == '%'.code.toByte()) {
                    if (i + 2 >= b.size) return null
                    val h = String(b, i + 1, 2, Charsets.US_ASCII).toIntOrNull(16) ?: return null
                    out.write(h)
                    i += 3
                } else {
                    out.write(b[i].toInt())
                    i++
                }
            }
            val bytes = out.toByteArray()
            val decoded = String(bytes, Charsets.UTF_8)
            return if (decoded.toByteArray().contentEquals(bytes)) decoded else null
        }

        private fun escape(s: String): String {
            val sb = StringBuilder()
            for (byte in s.toByteArray()) {
                val c = byte.toInt() and 0xff
                val ch = c.toChar()
                if (ch in 'a'..'z' || ch in 'A'..'Z' || ch in '0'..'9' || ch in "-._~") sb.append(ch) else sb.append("%%%02X".format(c))
            }
            return sb.toString()
        }
    }
}
