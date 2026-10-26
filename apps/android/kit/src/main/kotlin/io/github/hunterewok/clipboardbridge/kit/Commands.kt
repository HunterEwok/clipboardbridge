// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import java.security.SecureRandom
import java.time.Instant

/**
 * Commands (docs/protocol.md, section 15): an admin's order for one member,
 * signed like a record and never stored, as internal/group/command.go makes
 * them: one sets the receiver's sync mode, another makes the receiver, an
 * admin computer, the group's hub in place of this phone.
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

    /** The most clients a hub command hands over, as many as a hub keeps. */
    const val MAX_HUB_CLIENTS = 256

    /** How far ahead of the receiver's clock a command's time may be. */
    const val AHEAD_MS = 60_000L

    /** The most bytes of a command's body, as Go takes: a hub command carries up to 256 clients' keys. */
    private const val MAX_BODY = 64 shl 10

    /** What a command orders, as its receiver checked it. mode is set for a mode command. */
    data class Body(val type: String, val group: String, val by: String, val to: String, val id: String, val timeMS: Long, val expiresMS: Long, val mode: String?)

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
        if (c.body.size > MAX_BODY) throw Refused("the command is too large")
        val o = Wire.parse(c.body) ?: throw Refused("the command is not valid")
        val type = o.optString("type")
        val b = Body(
            type = type ?: "",
            group = o.optString("group") ?: "",
            by = o.optString("by") ?: "",
            to = o.optString("to") ?: "",
            id = o.optString("id") ?: "",
            timeMS = o.optLong("time_ms") ?: 0,
            expiresMS = o.optLong("expires_ms") ?: 0,
            mode = o.optString("mode"),
        )
        if (o.optLong("v") != Records.VERSION.toLong()) throw Refused("unknown command version")
        if (b.id.length != 32 || b.id.any { it !in "0123456789abcdef" }) throw Refused("the command has no valid ID")
        when (type) {
            "mode" -> if (b.mode.isNullOrEmpty() || o.opt("hub") != null) throw Refused("a mode command names no mode")
            "hub" -> if (o.opt("hub") == null || !b.mode.isNullOrEmpty()) throw Refused("a hub command has no order")
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
