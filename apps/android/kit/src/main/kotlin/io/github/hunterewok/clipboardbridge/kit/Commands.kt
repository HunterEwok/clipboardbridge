// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import java.security.SecureRandom
import java.time.Instant

/**
 * Commands (docs/protocol.md, section 15): an admin's order for one member,
 * signed like a record and never stored, as internal/group/command.go makes
 * them. The only one so far sets the receiver's sync mode.
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

    /** The ID in a command's body, or null when it has none. */
    fun idOf(c: Member.Record): String? = Wire.parse(c.body)?.optString("id")
}
