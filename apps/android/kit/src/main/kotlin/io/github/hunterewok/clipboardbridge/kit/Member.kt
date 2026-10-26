// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The member protocol of docs/protocol.md, sections 4 and 5, as the Go side
 * speaks it (internal/node, internal/clip, internal/hlc): frames of a
 * 4-byte big-endian length and a JSON message, a hello first, then events,
 * pings, records and goodbyes.
 */
object Member {
    /** The sync modes (design.md, "Sync modes"). */
    val MODES = setOf("own", "shared", "receive", "send")

    /** Whether a device in sync mode mode takes the group's copies into its clipboard by itself; a device without a mode (null) shares. */
    fun receives(mode: String?): Boolean = mode == null || mode == "shared" || mode == "receive"

    /** Whether a device in sync mode mode sends its own copies to the group by itself. */
    fun sends(mode: String?): Boolean = mode == null || mode == "shared" || mode == "send"

    /** The ALPN protocol of member connections. */
    const val ALPN = "clipboardbridge/1"

    /** Frames larger than this close the connection. */
    const val MAX_FRAME = 7 shl 20

    /** A side that wrote nothing for this long, in milliseconds, sends a ping. */
    const val PING_EVERY_MS = 5_000L

    /** A connection silent for this long, in milliseconds, is dead. */
    const val TIMEOUT_MS = 15_000L

    /** Texts are at most this many bytes of UTF-8. */
    const val MAX_TEXT = 1 shl 20

    /** What kind of member is at the other end: FULL is a computer with the service (Linux, Windows or macOS). */
    enum class Role(val wire: String) {
        FULL("full"), PHONE("phone"), LITE("lite");

        companion object {
            fun of(s: String): Role? = entries.firstOrNull { it.wire == s }
        }
    }

    /** The kind of a text: a secret is kept only briefly (section 5). */
    enum class Kind(val wire: String) {
        TEXT("text"), SECRET("secret");

        companion object {
            fun of(s: String): Kind? = entries.firstOrNull { it.wire == s }
        }
    }

    /** How a text reached the member that made the event. */
    enum class Via(val wire: String) {
        COPY("copy"),
        /** Sent from a phone: the app, or the iPhone shortcut. */
        PHONE("phone"),
        UNIVERSAL_CLIPBOARD("universal-clipboard");

        companion object {
            /** Also takes "iphone", the name before phones other than the iPhone. */
            fun of(s: String): Via? = if (s == "iphone") PHONE else entries.firstOrNull { it.wire == s }
        }
    }

    /**
     * A hybrid logical clock timestamp: milliseconds since the Unix epoch
     * and a counter, written as "<wall>.<logical>".
     */
    data class Timestamp(val wall: Long, val logical: Long) : Comparable<Timestamp> {
        override fun compareTo(other: Timestamp): Int =
            if (wall != other.wall) wall.compareTo(other.wall) else logical.compareTo(other.logical)

        override fun toString(): String = "$wall.$logical"

        val isZero: Boolean get() = wall == 0L && logical == 0L

        companion object {
            /** The last millisecond of 9999. */
            const val MAX_WALL = 253_402_300_799_999L
            private const val MAX_LOGICAL = 0xffff_ffffL
            val ZERO = Timestamp(0, 0)

            /**
             * Parses the text form: two decimal numbers and a dot, no sign or
             * spaces, the wall time at most MAX_WALL.
             */
            fun parse(text: String): Timestamp? {
                val parts = text.split(".")
                if (parts.size != 2 || parts.any { p -> p.isEmpty() || !p.all { it in '0'..'9' } }) return null
                val w = parts[0].toBigInteger()
                val l = parts[1].toBigInteger()
                if (w > MAX_WALL.toBigInteger() || l > MAX_LOGICAL.toBigInteger()) return null
                return Timestamp(w.toLong(), l.toLong())
            }
        }
    }

    /** One copy, as it travels between members. */
    data class Event(
        val id: String,
        val origin: String,
        val via: Via = Via.COPY,
        val time: Timestamp,
        /** Milliseconds since the copy, as of the moment the frame is written. */
        val ageMS: Long = 0,
        val kind: Kind,
        /** The text; "" only in the mark of a secret. */
        val text: String,
    ) {
        /** Whether it is the mark of a secret: the event without its text. */
        val isMark: Boolean get() = kind == Kind.SECRET && text.isEmpty()

        /** The mark of this event: a secret without its text, as a hello carries it. */
        val mark: Event get() = if (kind == Kind.SECRET) copy(text = "") else this

        /** Checks an event received from another member, as Go's Event.Validate does. */
        val isValid: Boolean
            get() {
                if (!GroupCertificates.isDeviceID(id) || !GroupCertificates.isDeviceID(origin) ||
                    time.isZero || time.wall > Timestamp.MAX_WALL || ageMS < 0
                ) {
                    return false
                }
                return isMark || (text.isNotEmpty() && text.toByteArray().size <= MAX_TEXT)
            }

        /** Whether it sorts after f: by time, then by ID, so every member orders any two events the same way. */
        fun isLater(than: Event): Boolean = if (time != than.time) time > than.time else id > than.id

        fun toJson(): JsonObject = Wire.obj(
            "id" to Wire.str(id),
            "origin" to Wire.str(origin),
            "via" to Wire.str(via.wire.takeIf { via != Via.COPY }), // absent means copy
            "time" to Wire.str(time.toString()),
            "age_ms" to Wire.num(ageMS),
            "kind" to Wire.str(kind.wire),
            "text" to Wire.str(text),
        )

        companion object {
            /** The event in o, or null when it does not decode. */
            fun fromJson(o: JsonObject): Event? =
                try {
                    Event(
                        id = o.optString("id") ?: return null,
                        origin = o.optString("origin") ?: return null,
                        via = o.optString("via")?.let { Via.of(it) ?: return null } ?: Via.COPY,
                        time = Timestamp.parse(o.optString("time") ?: return null) ?: return null,
                        ageMS = o.optLong("age_ms") ?: 0,
                        kind = Kind.of(o.optString("kind") ?: return null) ?: return null,
                        text = o.optString("text") ?: "",
                    )
                } catch (e: WireTypeException) {
                    null
                }

            fun fromJson(e: JsonElement?): Event? = (e as? JsonObject)?.let { fromJson(it) }
        }
    }

    /** The first message of each side. */
    data class Hello(
        /** The sender's wall clock, milliseconds since the Unix epoch; for skew reports only. */
        val wallMS: Long,
        /** The sender's current event; a secret only as its mark. null when there is none, or when it did not decode. */
        val current: Event? = null,
        /** The digest of the sender's records (section 10). */
        val records: String? = null,
        /** The sender's device name. */
        val name: String? = null,
        /** The sender's operating system: "linux", "windows", "macos", "ios", "android" or "none"; shown, never trusted. */
        val os: String? = null,
        /**
         * From a computer that is no admin yet: the SubjectPublicKeyInfo of
         * its admin key, for the root to certify (section 10, "A computer as admin").
         */
        val adminKey: ByteArray? = null,
        /** The sender's WireGuard public key, 32 bytes, for the group's hub (section 11). */
        val tunnelKey: ByteArray? = null,
        /**
         * With tunnelKey, the preshared key the sender chose for its
         * tunnels, 32 bytes, so every hub of the group uses the same one
         * (section 11, "Several hubs"); null from an older member.
         */
        val tunnelPSK: ByteArray? = null,
        /** What the sender says about its device, for showing. */
        val device: DeviceInfo? = null,
        /** The sender's sync mode: "own", "shared", "receive" or "send"; null from a member without one, which shares. */
        val mode: String? = null,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Hello && wallMS == other.wallMS && current == other.current && records == other.records &&
                name == other.name && os == other.os && adminKey.contentEqualsOrNull(other.adminKey) &&
                tunnelKey.contentEqualsOrNull(other.tunnelKey) &&
                tunnelPSK.contentEqualsOrNull(other.tunnelPSK) && device == other.device && mode == other.mode

        override fun hashCode(): Int = wallMS.hashCode()
    }

    /**
     * What a hello says about the sender's device (section 4, "Device"): its
     * form, its system's version, its own version and its network card's MAC
     * address. Shown, never trusted; any field may be absent.
     */
    data class DeviceInfo(
        val form: String? = null,
        val osVersion: String? = null,
        val version: String? = null,
        val mac: String? = null,
    ) {
        /**
         * The same without its invalid fields: an unknown form, a version
         * longer than 32 bytes or with control characters, a MAC address
         * other than six lowercase hex bytes with colons; null when nothing
         * is left.
         */
        val cleaned: DeviceInfo?
            get() {
                fun short(s: String?): String? =
                    s?.takeIf { it.isNotEmpty() && it.toByteArray().size <= 32 && it.none { c -> Character.isISOControl(c) } }
                val d = DeviceInfo(
                    form = form?.takeIf { it in FORMS },
                    osVersion = short(osVersion),
                    version = short(version),
                    mac = mac?.takeIf { MAC.matches(it) },
                )
                return d.takeIf { it != DeviceInfo() }
            }

        fun toJson(): JsonObject = Wire.obj(
            "form" to Wire.str(form),
            "os_version" to Wire.str(osVersion),
            "version" to Wire.str(version),
            "mac" to Wire.str(mac),
        )

        companion object {
            /** The forms a device may name, for its icon. */
            val FORMS = listOf("laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other")
            private val MAC = Regex("^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

            /** The device of a hello, null when it does not decode. */
            fun fromJson(e: JsonElement?): DeviceInfo? = (e as? JsonObject)?.let {
                runCatching {
                    DeviceInfo(it.optString("form"), it.optString("os_version"), it.optString("version"), it.optString("mac"))
                }.getOrNull()
            }
        }
    }

    /**
     * The group's hub's answer to the tunnel key a hello carried (section
     * 11): the hub's WireGuard public key, this member's own preshared key,
     * the hub's addresses away from home, "ip:port" or "[ipv6]:port", the
     * group's obfuscation settings as JSON text, null for plain WireGuard,
     * and the way to the hub's forwarder over VLESS as JSON text, null
     * without it. The kit keeps both as they came and the tunnel reads them.
     */
    class TunnelOffer(
        val hubKey: ByteArray,
        val psk: ByteArray,
        val endpoints: List<String> = emptyList(),
        val obfuscation: String? = null,
        val vless: String? = null,
        /**
         * In an offer the hub passes on when it hands the hub over, the
         * device that is the hub now (section 11, "Moving the hub"); null
         * when the sender is the hub.
         */
        val hub: String? = null,
        /**
         * Whether the sender is no hub any more and hands its clients over
         * to hub: the client forgets the sender's own offer.
         */
        val moved: Boolean = false,
    ) {
        /** Whether both keys are 32 bytes, as a tunnel needs. */
        val isValid: Boolean get() = hubKey.size == 32 && psk.size == 32 && endpoints.size <= 8

        /** The same offer with another preshared key and hub, and moved set. */
        fun with(psk: ByteArray, hub: String?, moved: Boolean = false): TunnelOffer =
            TunnelOffer(hubKey, psk, endpoints, obfuscation, vless, hub, moved)

        override fun equals(other: Any?): Boolean =
            other is TunnelOffer && hubKey.contentEquals(other.hubKey) && psk.contentEquals(other.psk) && endpoints == other.endpoints &&
                obfuscation == other.obfuscation && vless == other.vless && hub == other.hub && moved == other.moved

        override fun hashCode(): Int = hubKey.contentHashCode()

        fun toJson(): JsonObject = Wire.obj(
            "hub_key" to Wire.bytes(hubKey),
            "psk" to Wire.bytes(psk),
            "endpoints" to endpoints.takeIf { it.isNotEmpty() }?.let { l -> JsonArray(l.map { Wire.str(it)!! }) },
            "obfuscation" to obfuscation?.let { Json.parseToJsonElement(it) },
            "vless" to vless?.let { Json.parseToJsonElement(it) },
            "hub" to Wire.str(hub),
            "moved" to if (moved) JsonPrimitive(true) else null,
        )

        companion object {
            fun fromJson(o: JsonObject): TunnelOffer = TunnelOffer(
                o.optBytes("hub_key") ?: ByteArray(0),
                o.optBytes("psk") ?: ByteArray(0),
                o.optArray("endpoints")?.map {
                    (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: throw WireTypeException("endpoints: not a string")
                } ?: emptyList(),
                o.optObject("obfuscation")?.toString(),
                o.optObject("vless")?.toString(),
                o.optString("hub"),
                o.optBool("moved") ?: false,
            )
        }
    }

    /**
     * What a hub tells the group's other hubs (section 11, "Several hubs"):
     * whether it serves as the hub now, its offer without a preshared key,
     * and its clients, itself among them, with their keys.
     */
    class HubShare(val serving: Boolean = false, val offer: TunnelOffer? = null, val clients: List<PhoneHub.Client> = emptyList()) {
        override fun equals(other: Any?): Boolean =
            other is HubShare && serving == other.serving && offer == other.offer &&
                clients.map { Triple(it.device, it.key.toList(), it.psk.toList()) } ==
                other.clients.map { Triple(it.device, it.key.toList(), it.psk.toList()) }

        override fun hashCode(): Int = clients.size

        fun toJson(): JsonObject = Wire.obj(
            "serving" to if (serving) JsonPrimitive(true) else null,
            "offer" to offer?.toJson(),
            "clients" to clients.takeIf { it.isNotEmpty() }?.let { l -> JsonArray(l.map { it.toJson() }) },
        )

        companion object {
            fun fromJson(o: JsonObject): HubShare = HubShare(
                o.optBool("serving") ?: false,
                o.optObject("offer")?.let { TunnelOffer.fromJson(it) },
                o.optArray("clients")?.map { PhoneHub.Client.fromJson(it as? JsonObject ?: throw WireTypeException("clients: not an object")) }
                    ?: emptyList(),
            )
        }
    }

    /** A signed record of the group (section 10), carried as it came. */
    class Record(val body: ByteArray, val sig: ByteArray, val chain: List<ByteArray>? = null) {
        override fun equals(other: Any?): Boolean =
            other is Record && body.contentEquals(other.body) && sig.contentEquals(other.sig) &&
                (chain?.map { it.toList() }) == (other.chain?.map { it.toList() })

        override fun hashCode(): Int = body.contentHashCode()

        fun toJson(): JsonObject = Wire.obj("body" to Wire.bytes(body), "sig" to Wire.bytes(sig), "chain" to Wire.list(chain))

        companion object {
            fun fromJson(o: JsonObject): Record =
                Record(o.optBytes("body") ?: ByteArray(0), o.optBytes("sig") ?: ByteArray(0), o.optBytesList("chain"))
        }
    }

    /** The answer to a command (section 15): its ID, "done", "refused" or "failed", and why for the last two. */
    data class CommandResult(
        val id: String,
        val status: String,
        val reason: String? = null,
        /** In the result of a hub command, the new hub's offer without a preshared key (section 11, "Moving the hub"). */
        val tunnel: TunnelOffer? = null,
    ) {
        val done: Boolean get() = status == "done"

        fun toJson(): JsonObject =
            Wire.obj("id" to Wire.str(id), "status" to Wire.str(status), "reason" to Wire.str(reason), "tunnel" to tunnel?.toJson())

        companion object {
            fun fromJson(o: JsonObject): CommandResult = CommandResult(
                o.optString("id") ?: "",
                o.optString("status") ?: "",
                o.optString("reason"),
                o.optObject("tunnel")?.let { runCatching { TunnelOffer.fromJson(it) }.getOrNull() },
            )
        }
    }

    /** One message of the protocol. */
    sealed class Message {
        data class Hello(val role: Role, val hello: Member.Hello) : Message()

        /** An event; null when it did not decode, for example from a newer version, which is dropped without ending the connection. */
        data class Event(val event: Member.Event?) : Message()

        object Ping : Message()

        object Bye : Message()

        /** A renewed member certificate for the receiver, DER, and the admin CA that issued it when an admin did. */
        class Cert(val cert: ByteArray, val issuer: ByteArray? = null) : Message() {
            override fun equals(other: Any?): Boolean =
                other is Cert && cert.contentEquals(other.cert) && issuer.contentEqualsOrNull(other.issuer)

            override fun hashCode(): Int = cert.contentHashCode()
        }

        data class Records(val records: List<Record>) : Message()

        /** From the root: the receiver's admin CA, DER, for the admin key its hello offered. */
        class Admin(val adminCA: ByteArray) : Message() {
            override fun equals(other: Any?): Boolean = other is Admin && adminCA.contentEquals(other.adminCA)

            override fun hashCode(): Int = adminCA.contentHashCode()
        }

        /** From the group's hub: its offer for the tunnel key the receiver's hello carried; null when absent. */
        data class Tunnel(val offer: TunnelOffer?) : Message()

        /**
         * Between the group's hubs (section 11, "Several hubs"): whether the
         * sender serves as the hub, its offer without a preshared key, and
         * its clients with their keys, so any hub can take them.
         */
        data class Hubs(val share: HubShare) : Message()

        /** From an admin: a command signed for the receiver (section 15). */
        data class Command(val command: Record) : Message()

        /** The answer to a command. */
        data class Result(val result: CommandResult) : Message()

        /** A type from a newer version, ignored. */
        data class Unknown(val type: String) : Message()
    }

    class WireException(message: String) : Exception(message)

    /** The JSON of a message. */
    fun toJson(m: Message): JsonObject = when (m) {
        is Message.Hello -> Wire.obj(
            "t" to Wire.str("hello"),
            "role" to Wire.str(m.role.wire),
            "hello" to Wire.obj(
                "wall_ms" to Wire.num(m.hello.wallMS),
                "current" to m.hello.current?.toJson(),
                "records" to Wire.str(m.hello.records),
                "name" to Wire.str(m.hello.name),
                "os" to Wire.str(m.hello.os),
                "device" to m.hello.device?.toJson(),
                "admin_key" to Wire.bytes(m.hello.adminKey),
                "tunnel_key" to Wire.bytes(m.hello.tunnelKey),
                "tunnel_psk" to Wire.bytes(m.hello.tunnelPSK),
                "mode" to Wire.str(m.hello.mode),
            ),
        )
        is Message.Event -> Wire.obj("t" to Wire.str("event"), "event" to m.event?.toJson())
        Message.Ping -> Wire.obj("t" to Wire.str("ping"))
        Message.Bye -> Wire.obj("t" to Wire.str("bye"))
        is Message.Cert -> Wire.obj("t" to Wire.str("cert"), "cert" to Wire.bytes(m.cert), "issuer" to Wire.bytes(m.issuer))
        is Message.Records -> Wire.obj("t" to Wire.str("records"), "records" to JsonArray(m.records.map { it.toJson() }))
        is Message.Admin -> Wire.obj("t" to Wire.str("admin"), "admin_ca" to Wire.bytes(m.adminCA))
        is Message.Tunnel -> Wire.obj("t" to Wire.str("tunnel"), "tunnel" to m.offer?.toJson())
        is Message.Hubs -> Wire.obj("t" to Wire.str("hubs"), "hubs" to m.share.toJson())
        is Message.Command -> Wire.obj("t" to Wire.str("command"), "command" to m.command.toJson())
        is Message.Result -> Wire.obj("t" to Wire.str("result"), "result" to m.result.toJson())
        is Message.Unknown -> Wire.obj("t" to Wire.str(m.type))
    }

    /** Encodes a message as a frame: the length, then the JSON. */
    fun encode(m: Message): ByteArray {
        val body = Wire.encode(toJson(m))
        if (body.size > MAX_FRAME) throw WireException("frame too large")
        return frame(body)
    }

    internal fun frame(body: ByteArray): ByteArray {
        val n = body.size
        return byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()) + body
    }

    /** The length a frame header announces, or an error when too large. */
    fun length(header: ByteArray, max: Int = MAX_FRAME): Int {
        if (header.size != 4) throw WireException("short frame header")
        val n = header.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
        if (n > max) throw WireException("frame too large")
        return n.toInt()
    }

    /**
     * Decodes the body of a frame. A hello whose role is unknown or whose
     * hello object does not decode is an error; an event that does not
     * decode is an Event(null).
     */
    fun decode(body: ByteArray): Message {
        val o = Wire.parse(body) ?: throw WireException("not a message")
        try {
            return when (val t = o.optString("t") ?: throw WireException("not a message")) {
                "hello" -> {
                    val role = o.optString("role")?.let { Role.of(it) } ?: throw WireException("bad hello: unknown role")
                    val h = o.optObject("hello") ?: throw WireException("bad hello: no hello object")
                    Message.Hello(
                        role,
                        Hello(
                            wallMS = h.optLong("wall_ms") ?: 0,
                            current = Event.fromJson(h.opt("current")),
                            records = h.optString("records"),
                            name = h.optString("name"),
                            os = h.optString("os"),
                            adminKey = h.optBytes("admin_key"),
                            tunnelKey = h.optBytes("tunnel_key"),
                            tunnelPSK = h.optBytes("tunnel_psk"),
                            device = DeviceInfo.fromJson(h.opt("device")),
                            mode = h.optString("mode")?.takeIf { it in MODES },
                        ),
                    )
                }
                "event" -> Message.Event(Event.fromJson(o.opt("event")))
                "ping" -> Message.Ping
                "bye" -> Message.Bye
                "cert" -> Message.Cert(o.optBytes("cert") ?: ByteArray(0), o.optBytes("issuer"))
                "records" -> Message.Records(
                    o.optArray("records")?.map { Record.fromJson(it as? JsonObject ?: throw WireTypeException("records")) } ?: emptyList(),
                )
                "admin" -> Message.Admin(o.optBytes("admin_ca") ?: ByteArray(0))
                "tunnel" -> Message.Tunnel(o.optObject("tunnel")?.let { TunnelOffer.fromJson(it) })
                "hubs" -> o.optObject("hubs")?.let { Message.Hubs(HubShare.fromJson(it)) } ?: Message.Unknown(t)
                "command" -> o.optObject("command")?.let { Message.Command(Record.fromJson(it)) } ?: Message.Unknown(t)
                "result" -> o.optObject("result")?.let { Message.Result(CommandResult.fromJson(it)) } ?: Message.Unknown(t)
                else -> Message.Unknown(t)
            }
        } catch (e: WireTypeException) {
            throw WireException("not a message: ${e.message}")
        }
    }
}

internal fun ByteArray?.contentEqualsOrNull(other: ByteArray?): Boolean =
    if (this == null) other == null else other != null && contentEquals(other)
