// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.annotation.StringRes
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.github.hunterewok.clipboardbridge.kit.JoinCode
import io.github.hunterewok.clipboardbridge.kit.MemberNode
import io.github.hunterewok.clipboardbridge.kit.PairingJoiner
import io.github.hunterewok.clipboardbridge.kit.PairingMember
import io.github.hunterewok.clipboardbridge.kit.Pairing
import io.github.hunterewok.clipboardbridge.kit.PhoneGroup
import io.github.hunterewok.clipboardbridge.kit.TLSTransport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * What the app shows and does; the screens only read it and call it. Its
 * state is Compose state, changed on the main thread.
 */
class AppModel(private val app: Context) {
    enum class Phase { START, JOINING, HOME }

    /** One line about the last action, in plain words, and the error underneath when details are on. */
    data class Note(@StringRes val text: Int, val detail: String? = null, val error: Boolean = false)

    val settings = Settings(app)
    val notifier = Notifier(app).also { n ->
        // From the thread that saw the event: the watch hears of it on the main thread.
        n.onEvent = { Handler(Looper.getMainLooper()).post { WatchLink.update(app, this) } }
    }
    val group = LiveGroup(app).also { g ->
        g.onCopy = { text, kind -> Clipboard.write(app, text, kind) }
        // In the background too: the service keeps the connections that bring the records.
        // Off the node's thread, which may hold its own lock while it hands records over.
        g.onRecords = { Thread({ notifier.observe(g.devices) }, "events").start() }
    }

    var phase by mutableStateOf(if (group.hasGroup) Phase.HOME else Phase.START)
        private set
    var devices by mutableStateOf(group.devices)
        private set
    val computers: List<LiveGroup.Device> get() = devices.filter { !it.isSelf }
    var message by mutableStateOf<Note?>(null)
    var busy by mutableStateOf(false)
        private set

    /** The QR code this phone shows while it waits to join a group. */
    var joinCode by mutableStateOf<JoinCode?>(null)
        private set
    var isAdmin by mutableStateOf(group.isAdmin)
        private set

    /** The one-time note on the Start screen that this phone is ready. */
    var welcome by mutableStateOf(false)
        private set

    var color by mutableStateOf(settings.color)
        private set
    var appearance by mutableStateOf(settings.appearance)
        private set

    /** Sync away from home as Settings shows it: null without a group. */
    data class Away(val on: Boolean, val status: AwayFromHome.Status, val error: Note? = null)

    var away by mutableStateOf<Away?>(null)
        private set

    /** What turning it on or off said, when it failed. */
    var awayNote by mutableStateOf<Note?>(null)
        private set

    fun choose(color: String) {
        settings.color = color
        this.color = color
        WatchLink.update(app, this)
    }

    fun choose(appearance: Appearance) {
        settings.appearance = appearance
        this.appearance = appearance
    }

    /** Admits a scanned or pasted device; on success the app goes Home. */
    suspend fun scanned(text: String): Boolean {
        val jc = read(text)
        if (jc == null) {
            message = Note(R.string.not_a_code, error = true)
            return false
        }
        busy = true
        try {
            group.admit(jc)
            phase = Phase.HOME
            message = null
            return true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message = describe(e)
            return false
        } finally {
            busy = false
            update()
        }
    }

    /** At the first launch: makes this phone's own key and says so once, with what to do next. */
    suspend fun prepare() {
        if (phase != Phase.START || settings.welcomed) return
        try {
            withContext(Dispatchers.IO) { group.prepare() }
            welcome = true
        } catch (e: Exception) {
            message = describe(e)
        }
    }

    /** Hides the note for good. */
    fun dismissWelcome() {
        welcome = false
        settings.welcomed = true
    }

    /** Opens the screen that joins another phone's group. */
    fun startJoining() {
        dismissWelcome()
        message = null
        phase = Phase.JOINING
    }

    /**
     * Joins another phone's group: shows this phone's QR code until an
     * admin phone scans it, then goes Home. The join screen runs it as its
     * effect, so leaving the screen cancels it and stops listening.
     */
    suspend fun join() {
        try {
            group.join { code -> joinCode = code }
            update()
            phase = Phase.HOME
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message = describe(e)
        } finally {
            joinCode = null
        }
    }

    /** Leaves the join screen without joining. */
    fun cancelJoin() {
        joinCode = null
        message = null
        phase = Phase.START
    }

    /** The one big button. */
    suspend fun sync() {
        busy = true
        try {
            val board = Clipboard.readForSync(app)
            val (result, fetched) = withContext(Dispatchers.IO) { group.sync(board) }
            fetched?.let { (text, kind) -> Clipboard.write(app, text, kind) }
            message = Note(
                when (result) {
                    LiveGroup.SyncResult.SENT -> R.string.sent
                    LiveGroup.SyncResult.FETCHED -> R.string.fetched
                    LiveGroup.SyncResult.NOTHING_NEW -> R.string.nothing_new
                },
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message = describe(e)
        } finally {
            busy = false
            update()
        }
    }

    /**
     * The one button without the app: the tile, the notification, Share
     * and the selection menu. With the app perhaps just started for it, it
     * waits up to waitMS for a computer to connect; then it sends text, or
     * syncs by the button's rule. Returns what it says.
     */
    suspend fun syncFromOutside(text: String?, waitMS: Long = 5_000): Note {
        val deadline = System.currentTimeMillis() + waitMS
        while (group.hasGroup && System.currentTimeMillis() < deadline && !withContext(Dispatchers.IO) { group.online }) delay(250)
        if (text == null) {
            sync()
            return message ?: Note(R.string.nothing_new)
        }
        message = try {
            Note(if (withContext(Dispatchers.IO) { group.send(text) } == LiveGroup.SyncResult.SENT) R.string.sent else R.string.nothing_new)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        return message!!
    }

    /** Updates the devices and which of them are online. */
    suspend fun refresh() {
        update()
    }

    private suspend fun update() {
        val (d, admin) = withContext(Dispatchers.IO) { group.devices to group.isAdmin }
        devices = d
        isAdmin = admin
        notifier.observe(d)
        away = group.awayFromHome?.let { a ->
            // The last failure only while it is still trying; once connected or at home it is old news.
            val e = (a.lastError as? Exception)?.takeIf { a.status == AwayFromHome.Status.CONNECTING }
            notifier.away(a.isOn && e != null)
            // AwayFromHome logs each failure itself.
            Away(a.isOn, a.status, e?.let { describe(it, R.string.away_error, log = false) })
        }
        WatchLink.update(app, this)
    }

    /** Turns sync away from home on or off; the hub's answer comes on the next connection at home. */
    suspend fun setAway(on: Boolean) {
        awayNote = try {
            withContext(Dispatchers.IO) { group.setAwayFromHome(on) }
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Removes a device from the group. */
    suspend fun remove(id: String) {
        message = try {
            group.remove(id)
            Note(R.string.removed)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Gives a device another name. */
    suspend fun rename(id: String, name: String) {
        message = try {
            group.rename(id, name)
            Note(R.string.renamed)
        } catch (e: CancellationException) {
            throw e
        } catch (e: PhoneGroup.Failure) {
            if (e.message == PhoneGroup.INVALID_NAME) Note(R.string.rename_invalid, error = true) else describe(e)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Unfreezes an admin computer that another admin froze. */
    suspend fun unfreeze(id: String) {
        message = try {
            group.unfreeze(id)
            Note(R.string.unfrozen)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Sets a computer's sync mode; the reason it refused, if it does, shows under the message. */
    suspend fun setMode(id: String, mode: String) {
        message = try {
            group.setMode(id, mode)
            Note(R.string.mode_set)
        } catch (e: CancellationException) {
            throw e
        } catch (e: LiveGroup.CommandRefused) {
            Log.e(TAG, app.getString(R.string.error_command_refused), e)
            Note(R.string.error_command_refused, e.reason, error = true)
        } catch (e: MemberNode.ProtocolException) {
            describe(e, R.string.error_no_answer)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Makes a computer an admin. */
    suspend fun makeAdmin(id: String) {
        message = try {
            group.makeAdmin(id)
            Note(R.string.made_admin)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** The message for an error, with the error itself below it when details are on. The error is logged either way. */
    fun describe(e: Exception, @StringRes text: Int = summary(e), log: Boolean = true): Note {
        if (log) Log.e(TAG, app.getString(text), e)
        return Note(text, if (settings.showsErrorDetails) e.toString() + (e.cause?.let { "\n" + it } ?: "") else null, error = true)
    }

    companion object {
        private const val TAG = "clipboardbridge"

        /** Reads what the camera saw, or what the user pasted: the text of the QR code of cbb pair or of another phone. */
        fun read(text: String): JoinCode? {
            val jc = JoinCode.parse(text) ?: return null
            return if (jc.codeIsValid && jc.addrs.isNotEmpty() && jc.fingerprint.isNotEmpty()) jc else null
        }

        @StringRes
        fun summary(e: Exception): Int = when (e) {
            is LiveGroup.Failure -> when (e.kind) {
                LiveGroup.Failure.Kind.NOT_CONFIRMED -> R.string.error_not_confirmed
                LiveGroup.Failure.Kind.NO_NETWORK -> R.string.error_no_network
                LiveGroup.Failure.Kind.TIMED_OUT -> R.string.error_timed_out
                LiveGroup.Failure.Kind.TOO_MANY_WRONG_CODES -> R.string.error_too_many_codes
                LiveGroup.Failure.Kind.NOT_ADMIN -> R.string.error_not_admin
                LiveGroup.Failure.Kind.NO_COMPUTERS -> R.string.no_computers
                LiveGroup.Failure.Kind.NO_SCREEN, LiveGroup.Failure.Kind.UNREACHABLE -> R.string.error_unreachable
            }
            is Clipboard.Unreadable -> R.string.error_clipboard_unreadable
            is PairingMember.Failure ->
                if (e.code == Pairing.ErrorCode.WRONG_CODE) R.string.error_wrong_code else R.string.error_refused
            is PhoneGroup.Failure -> R.string.error_generic
            is PairingJoiner.Failure -> R.string.error_join
            is Keys.NoScreenLock -> R.string.error_no_screen_lock
            is Authenticator.Cancelled -> R.string.error_not_authenticated
            is TLSTransport.Failure, is java.io.IOException -> R.string.error_unreachable
            else -> R.string.error_generic
        }
    }
}
