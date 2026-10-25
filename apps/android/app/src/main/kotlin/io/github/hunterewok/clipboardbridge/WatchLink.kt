// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.content.Context
import android.util.Log
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.PutDataRequest
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

/**
 * The phone's side of the Wear OS app (../wear): it hands the watch the
 * group as the app sees it, in a data item of the Wearable Data Layer, and
 * turns sync away from home on or off when the watch asks (docs/apps.md,
 * Wear OS). Without Google Play services there is no watch to tell.
 */
object WatchLink {
    private const val TAG = "clipboardbridge"
    private var last: WatchState? = null
    private var failed = false

    /** Sends the state when it changed; on the main thread. */
    fun update(context: Context, model: AppModel) {
        val state = state(model)
        if (state == last) return
        last = state
        val request = PutDataRequest.create(WatchState.STATE_PATH).setData(state.encode()).setUrgent()
        Wearable.getDataClient(context.applicationContext).putDataItem(request)
            .addOnSuccessListener { failed = false }
            .addOnFailureListener { e ->
                last = null
                // Once: a phone without Play services fails every time.
                if (!failed) Log.i(TAG, "watch not updated", e)
                failed = true
            }
    }

    fun state(model: AppModel) = WatchState(
        hasGroup = model.phase == AppModel.Phase.HOME,
        devices = model.computers.map { WatchState.Device(it.id, it.name, it.kind.form, it.online) },
        away = model.away?.let { a ->
            if (!a.on) {
                WatchState.Away.OFF
            } else {
                when (a.status) {
                    AwayFromHome.Status.AT_HOME -> WatchState.Away.AT_HOME
                    AwayFromHome.Status.CONNECTING -> WatchState.Away.CONNECTING
                    AwayFromHome.Status.CONNECTED -> WatchState.Away.CONNECTED
                    AwayFromHome.Status.OFF, AwayFromHome.Status.WAITING_FOR_HUB -> WatchState.Away.WAITING
                }
            }
        },
        events = model.notifier.recent,
        // The wallpaper's colours are the phone's own; the watch takes the default.
        color = model.color.takeIf { c -> Tokens.colors.any { it.name == c } } ?: Tokens.colors.first().name,
        details = model.settings.showsErrorDetails,
    )
}

/** The watch's away switch, the same as the one in Settings; Play services start it when the watch asks. */
class WatchListener : WearableListenerService() {
    override fun onMessageReceived(event: MessageEvent) {
        if (event.path != WatchState.AWAY_PATH) return
        val on = event.data.firstOrNull() == 1.toByte()
        val model = (application as ClipboardBridgeApp).model
        // On a thread of Play services': the model changes on the main thread.
        runBlocking(Dispatchers.Main) {
            model.refresh()
            model.setAway(on)
        }
    }
}
