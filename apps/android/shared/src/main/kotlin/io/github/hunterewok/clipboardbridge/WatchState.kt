// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import org.json.JSONArray
import org.json.JSONObject

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
