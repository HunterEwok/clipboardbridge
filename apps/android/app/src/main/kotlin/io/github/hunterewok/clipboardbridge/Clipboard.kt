// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import io.github.hunterewok.clipboardbridge.kit.Member
import io.github.hunterewok.clipboardbridge.kit.SyncEngine

/**
 * The phone's clipboard. Android lets an app read it only while the app has
 * the input focus; writing works at any time (docs/apps.md, "Android: the
 * clipboard without taps").
 */
object Clipboard {
    /** Counts the changes of the clipboard that the app learns of; a secret's timer compares it. */
    @Volatile
    private var changes = 0L

    /**
     * Notes that the clipboard changed: CopyWatcher saw a copy. A secret
     * written before then is no longer the clipboard's, so it stays.
     */
    @Synchronized
    fun changed() {
        changes++
    }

    /** The text on the clipboard, or null when there is none or the app may not read it now. */
    fun read(context: Context): String? {
        val cm = context.getSystemService(ClipboardManager::class.java)
        return runCatching { cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString() }.getOrNull()
    }

    /**
     * The clipboard holds something the app could not read as text: it may
     * not read it now, or it is not text. The button leaves it as it is
     * rather than put an older text over it.
     */
    class Unreadable(detail: String, cause: Throwable? = null) : Exception(detail, cause)

    /**
     * The text on the clipboard for the button, or null when it is empty;
     * throws Unreadable when it holds something else.
     */
    fun readForSync(context: Context): String? {
        val cm = context.getSystemService(ClipboardManager::class.java)
        val clip = try {
            cm.primaryClip
        } catch (e: Exception) {
            throw Unreadable("the clipboard could not be read", e)
        } ?: return null
        if (clip.itemCount == 0) return null
        clip.getItemAt(0).text?.let { return it.toString() }
        val d = clip.description
        throw Unreadable("items=${clip.itemCount} types=${(0 until d.mimeTypeCount).map { d.getMimeType(it) }}")
    }

    /**
     * Puts a text on the clipboard; a secret is marked sensitive, so the
     * system shows no preview of it, and goes after its remaining minute
     * while it is still there.
     */
    fun write(context: Context, text: String, kind: Member.Kind) {
        val cm = context.getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText("clipboardbridge", text)
        if (kind == Member.Kind.SECRET) {
            clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        }
        cm.setPrimaryClip(clip)
        changed()
        val written = changes
        if (kind == Member.Kind.SECRET) {
            Handler(Looper.getMainLooper()).postDelayed({
                // Only the secret itself goes. While the app may read the
                // clipboard, by its text; otherwise (the service writes
                // most secrets in the background) unless the app learned
                // of a change since (a copy CopyWatcher saw, or another
                // text it wrote), so that it does not stay for good.
                val now = read(context)
                if (if (now != null) now == text else changes == written) cm.clearPrimaryClip()
            }, SyncEngine.SECRET_TTL_MS)
        }
    }
}
