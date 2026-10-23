// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The one button without the app's screens, for a moment and transparent:
 * from the Quick Settings tile, the notification, the "cbb send" launcher
 * entry (for Quick Tap or a back-tap app), Share and the selection menu.
 * Once it has the input focus it reads the clipboard, which only an app
 * with the focus may, sends or fetches by the Home button's rule (or sends
 * the shared or selected text), says what it did in a toast and closes.
 */
class SendActivity : Activity() {
    private val scope = MainScope()
    private var started = false

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(Settings.localized(base))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val model = (application as ClipboardBridgeApp).model
        if (!model.group.hasGroup) {
            startActivity(Intent(this, MainActivity::class.java))
            finish()
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || started || isFinishing) return
        started = true
        val model = (application as ClipboardBridgeApp).model
        val text = sharedText(intent)
        scope.launch {
            val note = model.syncFromOutside(text)
            Toast.makeText(this@SendActivity, getString(note.text), Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        fun intent(context: Context): Intent =
            Intent(context, SendActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)

        /** The text of Share or of the selection menu; null to use the clipboard. */
        fun sharedText(intent: Intent?): String? = when (intent?.action) {
            Intent.ACTION_SEND -> intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
            Intent.ACTION_PROCESS_TEXT -> intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
            else -> null
        }?.takeIf { it.isNotEmpty() }
    }
}
