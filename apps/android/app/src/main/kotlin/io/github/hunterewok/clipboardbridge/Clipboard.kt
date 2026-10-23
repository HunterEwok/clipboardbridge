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
    /** The text on the clipboard, or null when there is none or the app may not read it now. */
    fun read(context: Context): String? {
        val cm = context.getSystemService(ClipboardManager::class.java)
        return runCatching { cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString() }.getOrNull()
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
        if (kind == Member.Kind.SECRET) {
            Handler(Looper.getMainLooper()).postDelayed({
                // Only the secret itself goes: the app reads the clipboard
                // only while it is in front, and another copy stays.
                if (read(context) == text) cm.clearPrimaryClip()
            }, SyncEngine.SECRET_TTL_MS)
        }
    }
}
