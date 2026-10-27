// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.wear

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import androidx.annotation.StringRes
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import com.google.android.gms.wearable.DataClient
import com.google.android.gms.wearable.DataEvent
import com.google.android.gms.wearable.DataEventBuffer
import com.google.android.gms.wearable.Wearable
import io.github.hunterewok.clipboardbridge.WatchState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The group as the phone last told it, and the away switch, which asks the
 * phone; Compose state, changed on the main thread.
 */
class WearModel(private val context: Context, private val scope: CoroutineScope) : DataClient.OnDataChangedListener {
    /** A note under the switch, with the error underneath when details are on. */
    data class Note(@StringRes val text: Int, val detail: String? = null)

    var state by mutableStateOf(WatchState())
        private set

    /** Whether the phone is connected now; the state may be old without it. */
    var reachable by mutableStateOf(true)
        private set
    var switching by mutableStateOf(false)
        private set
    var note by mutableStateOf<Note?>(null)
        private set

    /** Whether the root phone certified this watch's admin key (WatchKey). */
    var admin by mutableStateOf(false)
        private set

    private val data = Wearable.getDataClient(context)

    fun start() {
        admin = WatchKey.admission(context) != null
        data.addListener(this)
        scope.launch {
            try {
                val items = data.dataItems.await()
                try {
                    items.firstOrNull { it.uri.path == WatchState.STATE_PATH }?.let { take(it.data) }
                } finally {
                    items.release()
                }
                reachable = Wearable.getNodeClient(context).connectedNodes.await().isNotEmpty()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "no state from the phone", e)
            }
        }
    }

    fun stop() {
        data.removeListener(this)
    }

    override fun onDataChanged(events: DataEventBuffer) {
        for (e in events) {
            if (e.type == DataEvent.TYPE_CHANGED && e.dataItem.uri.path == WatchState.STATE_PATH) take(e.dataItem.data)
        }
    }

    private fun take(bytes: ByteArray?) {
        WatchState.decode(bytes)?.let { state = it }
        reachable = true
    }

    /** Turns the phone's sync away from home on or off, as its Settings do. */
    fun setAway(on: Boolean) {
        if (switching) return
        switching = true
        note = null
        val before = state
        scope.launch {
            try {
                val nodes = Wearable.getNodeClient(context).connectedNodes.await()
                reachable = nodes.isNotEmpty()
                if (nodes.isEmpty()) {
                    note = Note(R.string.no_phone)
                    return@launch
                }
                val messages = Wearable.getMessageClient(context)
                nodes.forEach { messages.sendMessage(it.id, WatchState.AWAY_PATH, byteArrayOf(if (on) 1 else 0)).await() }
                // The phone answers with its new state; the same state when it could not switch.
                withTimeoutOrNull(ANSWER_MS) { snapshotFlow { state }.first { it != before } }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "away not switched", e)
                note = Note(R.string.no_answer, if (showsDetails) e.toString() else null)
            } finally {
                switching = false
            }
        }
    }

    /** As the phone's setting says, and always in a debug build. */
    private val showsDetails: Boolean
        get() = state.details || (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    companion object {
        private const val TAG = "clipboardbridge"
        private const val ANSWER_MS = 10_000L
    }
}
