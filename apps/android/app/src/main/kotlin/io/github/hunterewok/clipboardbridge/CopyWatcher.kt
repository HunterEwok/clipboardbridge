// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.res.Resources
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityManager
import io.github.hunterewok.clipboardbridge.kit.Member
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * "Send my copies by themselves" (docs/apps.md, "Android: the clipboard
 * without taps"): an accessibility service that notices a copy, a click on
 * a "Copy" action or the system's clipboard overlay of Android 13 and
 * later, and then takes the input focus for a moment with a 1-pixel
 * overlay, reads the clipboard and sends it. If the overlay does not get
 * the focus, SendActivity does the same. It reads nothing on the screen
 * beyond what tells it that a copy happened.
 */
class CopyWatcher : AccessibilityService() {
    private val main = Handler(Looper.getMainLooper())
    private val scope = MainScope()
    private var overlay: View? = null
    private var lastCopy = 0L

    /** The labels of a copy action: the platform's in the system's language, and English. */
    private val copyLabels: Set<String> by lazy {
        setOfNotNull(runCatching { Resources.getSystem().getString(android.R.string.copy) }.getOrNull(), "Copy", "Copy text", "Copy link")
            .map { it.lowercase() }.toSet()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        val copied = when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_CLICKED -> isCopy(event)
            AccessibilityEvent.TYPE_WINDOWS_CHANGED -> clipboardOverlayShown()
            else -> false
        }
        if (copied) {
            Clipboard.changed()
            copied()
        }
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        removeOverlay()
        scope.cancel()
        super.onDestroy()
    }

    private fun isCopy(e: AccessibilityEvent): Boolean {
        val words = (e.text.map { it.toString() } + listOfNotNull(e.contentDescription?.toString())).map { it.trim().lowercase() }
        return words.any { it in copyLabels }
    }

    /** Whether the system's clipboard overlay, which Android 13 and later show after each copy, is on screen. */
    private fun clipboardOverlayShown(): Boolean = runCatching {
        windows.any { w -> w.title?.toString()?.contains("clipboard", ignoreCase = true) == true }
    }.getOrDefault(false)

    /** A copy happened: once per second at most, take the focus and send, in a sync mode that sends this phone's copies. */
    private fun copied() {
        if (!Member.sends((application as ClipboardBridgeApp).model.group.syncMode)) return
        val now = SystemClock.elapsedRealtime()
        if (now - lastCopy < 1_000) return
        lastCopy = now
        // The app that copied sets the clipboard right after the click.
        main.postDelayed({ focusAndSend() }, 150)
    }

    private fun focusAndSend() {
        if (overlay != null) return
        val wm = getSystemService(WindowManager::class.java)
        val view = object : View(this) {
            override fun onWindowFocusChanged(hasWindowFocus: Boolean) {
                super.onWindowFocusChanged(hasWindowFocus)
                if (hasWindowFocus) {
                    val text = Clipboard.read(context)
                    removeOverlay()
                    if (text != null) send(text)
                }
            }
        }
        val params = WindowManager.LayoutParams(
            1,
            1,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT,
        ).apply { gravity = Gravity.TOP or Gravity.START }
        if (runCatching { wm.addView(view, params) }.isFailure) {
            startActivity(SendActivity.intent(this))
            return
        }
        overlay = view
        main.postDelayed({
            if (overlay === view) {
                // No focus: the transparent activity gets it instead.
                removeOverlay()
                startActivity(SendActivity.intent(this))
            }
        }, 700)
    }

    private fun removeOverlay() {
        val v = overlay ?: return
        overlay = null
        runCatching { getSystemService(WindowManager::class.java).removeView(v) }
    }

    private fun send(text: String) {
        val model = (application as ClipboardBridgeApp).model
        scope.launch { runCatching { withContext(Dispatchers.IO) { model.group.send(text) } } }
    }

    companion object {
        /** Whether the user turned the service on. */
        fun isOn(context: Context): Boolean =
            context.getSystemService(AccessibilityManager::class.java)
                .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .any { it.resolveInfo.serviceInfo.packageName == context.packageName && it.resolveInfo.serviceInfo.name == CopyWatcher::class.java.name }
    }
}
