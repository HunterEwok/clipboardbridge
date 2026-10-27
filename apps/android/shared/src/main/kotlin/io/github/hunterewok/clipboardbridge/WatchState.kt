// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

/**
 * What the phone tells its Wear OS watch, through the Wearable Data Layer:
 * the watch shows the group as the phone sees it (docs/apps.md, Wear OS),
 * as the iPhone's WatchState does for the Apple Watch. Never the clipboard.
 */
data class WatchState(
    val hasGroup: Boolean = false,
    val devices: List<Device> = emptyList(),
    /** null without a group. */
    val away: Away? = null,
    /** The latest events, newest first. */
    val events: List<String> = emptyList(),
    /** The phone's colour, by its name in Tokens.colors. */
    val color: String = "terminal",
    /** Whether the phone shows the error under its messages (its Settings); the watch does as it does. */
    val details: Boolean = false,
) {
    data class Device(val id: String, val name: String, val form: String, val online: Boolean)

    /** Where sync away from home stands, as the phone's Settings say it. */
    enum class Away(val key: String) {
        OFF("off"), AT_HOME("atHome"), CONNECTING("connecting"), CONNECTED("connected"), WAITING("waiting");

        companion object {
            fun of(key: String?): Away? = entries.firstOrNull { it.key == key }
        }
    }

    /**
     * The watch's answer to the root phone's CERTIFY_PATH (docs/protocol.md,
     * section 10, rule 8): the key it made, under the device ID it picked,
     * or why it made none (refused, NOT_PROTECTED or another reason).
     */
    data class KeyRequest(val device: String = "", val name: String = "", val key: ByteArray = ByteArray(0), val refused: String? = null) {
        fun encode(): ByteArray = JSONObject()
            .put("device", device)
            .put("name", name)
            .put("key", Base64.getEncoder().encodeToString(key))
            .put("refused", refused ?: JSONObject.NULL)
            .toString()
            .toByteArray()

        override fun equals(other: Any?): Boolean =
            other is KeyRequest && device == other.device && name == other.name && key.contentEquals(other.key) && refused == other.refused

        override fun hashCode(): Int = device.hashCode()

        companion object {
            fun decode(data: ByteArray?): KeyRequest? = data?.let {
                runCatching {
                    val o = JSONObject(String(it))
                    KeyRequest(
                        o.optString("device"), o.optString("name"), Base64.getDecoder().decode(o.optString("key")),
                        if (o.isNull("refused")) null else o.optString("refused"),
                    )
                }.getOrNull()
            }
        }
    }

    /** What the root gave the watch: its admin CA, in the group with that tag. */
    data class Admission(val device: String, val adminCA: ByteArray, val group: String) {
        fun encode(): ByteArray = JSONObject()
            .put("device", device)
            .put("adminCA", Base64.getEncoder().encodeToString(adminCA))
            .put("group", group)
            .toString()
            .toByteArray()

        override fun equals(other: Any?): Boolean =
            other is Admission && device == other.device && adminCA.contentEquals(other.adminCA) && group == other.group

        override fun hashCode(): Int = device.hashCode()

        companion object {
            fun decode(data: ByteArray?): Admission? = data?.let {
                runCatching {
                    val o = JSONObject(String(it))
                    Admission(o.getString("device"), Base64.getDecoder().decode(o.getString("adminCA")), o.getString("group"))
                }.getOrNull()
            }
        }
    }

    fun encode(): ByteArray = JSONObject()
        .put("hasGroup", hasGroup)
        .put(
            "devices",
            JSONArray(devices.map { JSONObject().put("id", it.id).put("name", it.name).put("form", it.form).put("online", it.online) }),
        )
        .put("away", away?.key ?: JSONObject.NULL)
        .put("events", JSONArray(events))
        .put("color", color)
        .put("details", details)
        .toString()
        .toByteArray()

    companion object {
        /** The data item with the state, which the phone replaces. */
        const val STATE_PATH = "/cbb/state"

        /** The watch's message that turns the phone's sync away from home on (1) or off (0). */
        const val AWAY_PATH = "/cbb/away"

        /** The root phone's ask that the watch make its admin key; the watch answers on KEY_PATH. */
        const val CERTIFY_PATH = "/cbb/certify"

        /** The watch's KeyRequest. */
        const val KEY_PATH = "/cbb/key"

        /** The root's Admission; the watch answers on ADMITTED_PATH with the device ID it kept, or nothing. */
        const val ADMITTED_PATH = "/cbb/admitted"

        /** Why a watch makes no key: it has no secure lock screen. */
        const val NOT_PROTECTED = "not-protected"

        /** The state the phone sent, or null for anything else. */
        fun decode(data: ByteArray?): WatchState? = data?.let {
            runCatching {
                val o = JSONObject(String(it))
                val ds = o.optJSONArray("devices") ?: JSONArray()
                val es = o.optJSONArray("events") ?: JSONArray()
                WatchState(
                    hasGroup = o.optBoolean("hasGroup"),
                    devices = (0 until ds.length()).map { i ->
                        val d = ds.getJSONObject(i)
                        Device(d.getString("id"), d.getString("name"), d.optString("form", "other"), d.optBoolean("online"))
                    },
                    away = if (o.isNull("away")) null else Away.of(o.optString("away")),
                    events = (0 until es.length()).map { i -> es.getString(i) },
                    color = o.optString("color", "terminal"),
                    details = o.optBoolean("details"),
                )
            }.getOrNull()
        }
    }
}
