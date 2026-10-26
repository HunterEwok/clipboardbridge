// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import java.security.SecureRandom
import java.time.Instant

/**
 * Commands (docs/protocol.md, section 15): an admin's order for one member,
 * signed like a record and never stored, as internal/group/command.go makes
 * them: one sets the receiver's sync mode, another makes the receiver, an
 * admin computer, the group's hub in place of this phone; a paste command
 * puts a text where the receiver's focus is, and paste-off turns remote
 * paste off on the receiver (design.md, "Remote paste"); an action command
 * runs one of the receiver's quick actions by its name, and actions-off
 * turns them all off there (roadmap.md, "Quick actions").
 */
object Commands {
    /** How long after signing a command expires; the receivers take at most 30 s. */
    const val LIFETIME_MS = 30_000L

    /** A new command ID: 128 random bits in hex. */
    fun newID(): String = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }

    /**
     * A mode command for the device to, signed with the root key (adminCA
     * null) or with an admin CA key, adminCA being that CA's certificate.
     */
    fun mode(
        to: String,
        mode: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
    ): Member.Record {
        require(mode in Member.MODES) { "unknown sync mode $mode" }
        val ms = now.toEpochMilli()
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(Records.VERSION.toLong()),
                "type" to Wire.str("mode"),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
                "mode" to Wire.str(mode),
            ),
        )
        return Member.Record(body, signer.signature(body), adminCA?.let { listOf(it) })
    }

    /**
     * A hub command for the admin computer to (section 11, "Moving the
     * hub"): it becomes the group's hub, reached through the forwarder
     * (endpoint "ip:port" and the pin of its key) and at endpoints, and
     * takes clients, the old hub's, with the keys they have. Signed as mode.
     */
    fun hub(
        to: String,
        forwarder: Pair<String, String>?,
        endpoints: List<String>,
        clients: List<PhoneHub.Client>,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
    ): Member.Record {
        require(forwarder != null || endpoints.isNotEmpty()) { "the new hub needs a forwarder or an address" }
        require(endpoints.size <= 8 && clients.size <= MAX_HUB_CLIENTS) { "too many addresses or clients" }
        val ms = now.toEpochMilli()
        val order = Wire.obj(
            "forwarder" to forwarder?.let { (ep, pin) -> Wire.obj("endpoint" to Wire.str(ep), "key" to Wire.str(pin)) },
            "endpoints" to endpoints.takeIf { it.isNotEmpty() }?.let { l -> JsonArray(l.map { Wire.str(it)!! }) },
            "clients" to clients.takeIf { it.isNotEmpty() }?.let { l -> JsonArray(l.map<PhoneHub.Client, JsonElement> { it.toJson() }) },
        )
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(Records.VERSION.toLong()),
                "type" to Wire.str("hub"),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
                "hub" to order,
            ),
        )
        return Member.Record(body, signer.signature(body), adminCA?.let { listOf(it) })
    }

    /** The longest text of a paste command, in bytes of UTF-8, and of one typed key by key. */
    const val MAX_PASTE_TEXT = 1 shl 20
    const val MAX_TYPE_TEXT = 4 shl 10

    /**
     * A paste command for the device to: put text where its focus is, by
     * method "paste" (the clipboard and the paste keys) or "type", then
     * press Enter when enter is set; kind is "text" or "secret". Signed as
     * mode.
     */
    fun paste(
        to: String,
        text: String,
        method: String = "paste",
        enter: Boolean = false,
        kind: String = "text",
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
    ): Member.Record {
        val limit = when (method) {
            "paste" -> MAX_PASTE_TEXT
            "type" -> MAX_TYPE_TEXT
            else -> throw IllegalArgumentException("a paste is paste or type, not $method")
        }
        require(kind == "text" || kind == "secret") { "a paste is text or secret, not $kind" }
        val n = text.toByteArray().size
        require(n in 1..limit) { "the text is empty or longer than $limit bytes" }
        val ms = now.toEpochMilli()
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(Records.VERSION.toLong()),
                "type" to Wire.str("paste"),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
                "mode" to Wire.str(method),
                "enter" to if (enter) JsonPrimitive(true) else null,
                "kind" to Wire.str(kind),
                "text" to Wire.str(text),
            ),
        )
        return Member.Record(body, signer.signature(body), adminCA?.let { listOf(it) })
    }

    /** A paste-off command for the device to: it turns remote paste off there. Signed as mode. */
    fun pasteOff(
        to: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
    ): Member.Record {
        val ms = now.toEpochMilli()
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(Records.VERSION.toLong()),
                "type" to Wire.str("paste-off"),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
            ),
        )
        return Member.Record(body, signer.signature(body), adminCA?.let { listOf(it) })
    }

    /** The longest name of a quick action. */
    const val MAX_ACTION_NAME = 32

    /** The most quick actions a hello lists. */
    const val MAX_HELLO_ACTIONS = 64

    /** The presets every computer knows, in the order the apps show them. */
    val PRESETS = listOf("lock", "sleep", "reboot", "shutdown", "cancel-shutdown", "restart")

    /** Whether name is a quick action's name: 1 to 32 of a-z, 0-9 and -, starting with a letter. */
    fun validActionName(name: String): Boolean =
        name.length in 1..MAX_ACTION_NAME && name[0] in 'a'..'z' && name.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }

    /** An action command for the device to: run its quick action name, which only the receiver defines. Signed as mode. */
    fun action(
        to: String,
        name: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
    ): Member.Record {
        require(validActionName(name)) { "$name is not an action's name" }
        return signed("action", to, group, by, now, signer, adminCA, id, "action" to Wire.str(name))
    }

    /** An actions-off command for the device to: it turns every quick action off there. Signed as mode. */
    fun actionsOff(
        to: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
    ): Member.Record = signed("actions-off", to, group, by, now, signer, adminCA, id)

    private fun signed(
        type: String,
        to: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray?,
        id: String,
        vararg extra: Pair<String, JsonElement?>,
    ): Member.Record {
        val ms = now.toEpochMilli()
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(Records.VERSION.toLong()),
                "type" to Wire.str(type),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
                *extra,
            ),
        )
        return Member.Record(body, signer.signature(body), adminCA?.let { listOf(it) })
    }

    /** The most clients a hub command hands over, as many as a hub keeps. */
    const val MAX_HUB_CLIENTS = 256

    /** How far ahead of the receiver's clock a command's time may be. */
    const val AHEAD_MS = 60_000L

    /** The most bytes of a command's body, as Go takes: a hub command carries up to 256 clients' keys, a paste up to 1 MiB of text. */
    private const val MAX_BODY = 64 shl 10
    private const val MAX_PASTE_BODY = 2 shl 20

    /** What a command orders, as its receiver checked it. mode is set for a mode or paste command, enter, kind and text for a paste. */
    data class Body(
        val type: String,
        val group: String,
        val by: String,
        val to: String,
        val id: String,
        val timeMS: Long,
        val expiresMS: Long,
        val mode: String?,
        val enter: Boolean = false,
        val kind: String? = null,
        val text: String? = null,
        val action: String? = null,
    )

    /** Why a command was refused, in words for the sender. */
    class Refused(message: String) : Exception(message)

    /**
     * Checks command c for the member self at nowMS, as Go's
     * Records.VerifyCommand: an admin of the group signed it now (records
     * says), it is for self in this group, it has not expired and was not
     * signed in the future. The caller keeps the replay cache; a mode
     * command's mode is not checked against [Member.MODES] here.
     */
    fun verify(c: Member.Record, records: RecordSet, self: String, nowMS: Long): Body {
        if (c.body.size > MAX_PASTE_BODY) throw Refused("the command is too large")
        val o = Wire.parse(c.body) ?: throw Refused("the command is not valid")
        val type = o.optString("type")
        if (type != "paste" && c.body.size > MAX_BODY) throw Refused("the command is too large")
        val b = Body(
            type = type ?: "",
            group = o.optString("group") ?: "",
            by = o.optString("by") ?: "",
            to = o.optString("to") ?: "",
            id = o.optString("id") ?: "",
            timeMS = o.optLong("time_ms") ?: 0,
            expiresMS = o.optLong("expires_ms") ?: 0,
            mode = o.optString("mode"),
            enter = o.optBool("enter") ?: false,
            kind = o.optString("kind"),
            text = o.optString("text"),
            action = o.optString("action"),
        )
        if (o.optLong("v") != Records.VERSION.toLong()) throw Refused("unknown command version")
        if (b.id.length != 32 || b.id.any { it !in "0123456789abcdef" }) throw Refused("the command has no valid ID")
        if (type != "paste" && (b.enter || b.kind != null || b.text != null)) throw Refused("a $type command carries a paste")
        if (type != "action" && b.action != null) throw Refused("a $type command names an action")
        when (type) {
            "mode" -> if (b.mode.isNullOrEmpty() || o.opt("hub") != null) throw Refused("a mode command names no mode")
            "hub" -> if (o.opt("hub") == null || !b.mode.isNullOrEmpty()) throw Refused("a hub command has no order")
            "paste-off", "actions-off" -> if (o.opt("hub") != null || !b.mode.isNullOrEmpty()) throw Refused("a $type command carries an order")
            "action" -> {
                if (o.opt("hub") != null || !b.mode.isNullOrEmpty()) throw Refused("an action command carries an order")
                if (!validActionName(b.action ?: "")) throw Refused("an action command names no valid action")
            }
            "paste" -> {
                val limit = when (b.mode) {
                    "paste" -> MAX_PASTE_TEXT
                    "type" -> MAX_TYPE_TEXT
                    else -> throw Refused("a paste command's way is not paste or type")
                }
                if (o.opt("hub") != null) throw Refused("a paste command carries a hub order")
                if (b.kind != "text" && b.kind != "secret") throw Refused("a paste command's kind is not text or secret")
                val n = b.text?.toByteArray()?.size ?: 0
                if (n == 0) throw Refused("a paste command has no text")
                if (n > limit) throw Refused("a paste command's text is longer than $limit bytes")
            }
            else -> throw Refused("unknown command type $type")
        }
        if (b.to.length != 32 || b.to.any { it !in "0123456789abcdef" }) throw Refused("the command names no valid device")
        if (b.expiresMS <= b.timeMS || b.expiresMS - b.timeMS > LIFETIME_MS) throw Refused("the command's lifetime is not valid")
        val ca = records.groupCA ?: throw Refused("this device has no records of its group yet")
        if (b.group != GroupCertificates.tag(ca)) throw Refused("the command is for another group")
        if (b.to != self) throw Refused("the command is for another device")
        if (!records.signedByAdmin(c)) throw Refused("the command's signer is not an admin of the group")
        if (b.expiresMS <= nowMS) throw Refused("the command expired; check the clocks of both devices")
        if (b.timeMS > nowMS + AHEAD_MS) throw Refused("the command was signed in the future; check the clocks of both devices")
        return b
    }

    /** The ID in a command's body, or null when it has none. */
    fun idOf(c: Member.Record): String? = Wire.parse(c.body)?.optString("id")
}
