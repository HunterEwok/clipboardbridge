// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import io.github.hunterewok.clipboardbridge.kit.Commands
import io.github.hunterewok.clipboardbridge.kit.Member
import io.github.hunterewok.clipboardbridge.kit.RemotePaste
import java.io.File
import java.io.IOException

/**
 * This phone as a remote paste target (docs/design.md, "Remote paste"):
 * a paste command an admin signed puts its text into the focused text
 * field of another app, through the accessibility service, once this
 * phone's user turned remote paste on. It keeps the switches, the limits
 * per sender and the log of the last pastes (never their text), and shows
 * a notification with the sender.
 */
class PasteReceiver(private val context: Context, dir: File) {
    private val settingsFile = File(dir, "paste-receive")
    private val logFile = File(dir, "pastes.json")
    private val limiter = RemotePaste.Limiter()

    var settings: RemotePaste.Settings
        get() = runCatching { RemotePaste.Settings.decode(settingsFile.readBytes()) }.getOrDefault(RemotePaste.Settings())
        set(s) = save(settingsFile, s.encode())

    /** The last pastes, oldest first. */
    val log: List<RemotePaste.Entry>
        get() = runCatching { RemotePaste.decodeLog(logFile.readBytes()) }.getOrDefault(emptyList())

    /** Carries out a paste command that Commands.verify took; name is the sender's, when known. */
    fun paste(body: Commands.Body, name: String?): Member.CommandResult {
        val set = settings
        val nowMS = System.currentTimeMillis()
        val res = when {
            !set.on -> refused(body, "remote paste is off on this device; its user turns it on in the app's settings")
            body.enter && !set.enter -> refused(body, "this device takes pastes without Enter only; its user allows Enter in the app's settings")
            !limiter.allow(body.by, nowMS) -> refused(body, "too many pastes: at most one a second and 30 a minute from one device")
            else -> inject(body, RemotePaste.clean(body.text ?: ""))
        }
        if (res.status == "done") {
            Log.i(TAG, "${body.by} pasted ${body.text?.length ?: 0} characters here")
            notifyPasted(name ?: body.by)
        } else {
            Log.w(TAG, "a paste from ${body.by}: ${res.status}: ${res.reason}")
        }
        if (body.kind != "secret") {
            val e = RemotePaste.Entry(
                nowMS, body.by, name, (body.text ?: "").toByteArray().size, body.mode ?: "paste",
                body.enter, res.status, res.reason,
            )
            try {
                save(logFile, RemotePaste.encodeLog(RemotePaste.appended(log, e)))
            } catch (e: IOException) {
                Log.e(TAG, "keeping the paste log", e)
            }
        }
        return res
    }

    /** Turns remote paste off, as a paste-off command from any admin does. */
    fun turnOff(): Member.CommandResult? = try {
        settings = RemotePaste.Settings()
        null
    } catch (e: IOException) {
        Log.e(TAG, "turning remote paste off", e)
        Member.CommandResult("", "failed", e.message)
    }

    private fun inject(body: Commands.Body, text: String): Member.CommandResult {
        if (text.isEmpty()) return refused(body, "the text has nothing that may be pasted: only control characters")
        val target = CopyWatcher.running
            ?: return refused(body, "this phone pastes through Clipboard Bridge's accessibility service, which is off; its user turns it on in the app's settings")
        return when (val r = target.inject(text, body.mode ?: "paste", body.enter, body.kind == "secret")) {
            null -> Member.CommandResult(body.id, "done")
            else -> Member.CommandResult(body.id, if (r.refused) "refused" else "failed", r.reason)
        }
    }

    private fun refused(body: Commands.Body, reason: String) = Member.CommandResult(body.id, "refused", reason)

    private fun notifyPasted(name: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.channel_pastes), NotificationManager.IMPORTANCE_LOW))
        val n = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.cbb_name))
            .setContentText(context.getString(R.string.pasted_from, name))
            .setAutoCancel(true)
            .setTimeoutAfter(60_000)
            .build()
        runCatching { nm.notify(NOTIFICATION, n) }.onFailure { Log.e(TAG, "notification not posted", it) }
    }

    private fun save(f: File, data: ByteArray) {
        f.parentFile?.mkdirs()
        val tmp = File(f.parentFile, f.name + ".tmp")
        tmp.writeBytes(data)
        if (!tmp.renameTo(f)) throw IOException("cannot save ${f.name}")
    }

    companion object {
        private const val TAG = "clipboardbridge"
        private const val CHANNEL = "pastes"
        private const val NOTIFICATION = 0x70617374
    }
}
