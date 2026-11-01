// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters

/**
 * The phone makes its own group and admits a computer of the bench's fleet
 * by its QR code's text, then syncs with it both ways
 * (docs/testbench-catalogue.md, A1 on Android). The steps share the app's
 * state in order: the group the first step makes is the next ones' group,
 * and Gradle uninstalls the app after the run.
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class GroupTest {
    @get:Rule val compose = createComposeRule()

    @get:Rule val permissions: GrantPermissionRule =
        if (Build.VERSION.SDK_INT >= 33) GrantPermissionRule.grant(Manifest.permission.CAMERA, Manifest.permission.POST_NOTIFICATIONS)
        else GrantPermissionRule.grant(Manifest.permission.CAMERA)

    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var model: AppModel

    private fun str(id: Int) = context.getString(id)

    @Before
    fun show() {
        assumeTrue("the bench's phone suite passes the helper's address", Bench.address != null)
        model = AppModel(context)
        compose.setContent { Root(model) }
        compose.waitForIdle()
    }

    /** Waits on the test's thread until ok holds, up to seconds. */
    private fun until(seconds: Int, what: String, ok: () -> Boolean) {
        val deadline = System.currentTimeMillis() + seconds * 1000L
        while (!ok()) {
            if (System.currentTimeMillis() > deadline) throw AssertionError("not within ${seconds}s: $what")
            Thread.sleep(250)
        }
    }

    private fun clipboard(): ClipboardManager = context.getSystemService(ClipboardManager::class.java)

    private fun setClip(text: String) = InstrumentationRegistry.getInstrumentation().runOnMainSync {
        clipboard().setPrimaryClip(ClipData.newPlainText("test", text))
    }

    private fun clip(): String? {
        var text: String? = null
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            text = clipboard().primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
        }
        return text
    }

    /** A1: Start, "Connect a new device", the QR code's text, Add: the phone's own group with the computer in it. */
    @Test
    fun a1_admitComputer() {
        assertEquals(AppModel.Phase.START, model.phase)
        compose.onNodeWithText(str(R.string.connect_device)).performClick()
        val (code, pairing) = Bench.pairCode(Bench.PC)
        compose.onNode(hasSetTextAction()).performTextInput(code)
        compose.onNodeWithText(str(R.string.add)).performClick()
        until(90, "the phone admits ${Bench.PC}; the app says ${model.message}") { model.phase == AppModel.Phase.HOME }
        val out = pairing.finish(60)
        assertTrue("cbb pair on ${Bench.PC} did not join:\n$out", out.contains("Joined the group."))
        until(30, "${Bench.PC} in the phone's devices: ${model.group.devices.map { it.name }}") {
            model.group.devices.any { it.name == Bench.PC }
        }
        val status = Bench.run(Bench.PC, "cbb status")
        assertFalse("cbb status on ${Bench.PC} shows no group:\n$status", status.contains("Not in a group"))
    }

    /** A1: the big button sends the phone's copy to the computer. */
    @Test
    fun a2_sendToComputer() {
        val text = "cbb-bench phone A1 from the phone ${System.currentTimeMillis()}"
        setClip(text)
        runBlocking { model.sync() }
        assertEquals("the button says ${model.message}", R.string.sent, model.message?.text)
        Bench.arrives(Bench.PC, text)
    }

    /** A1: the big button fetches the computer's copy onto the phone's clipboard. */
    @Test
    fun a3_fetchFromComputer() {
        val text = "cbb-bench phone A1 from ${Bench.PC} ${System.currentTimeMillis()}"
        Bench.copy(Bench.PC, text)
        until(30, "the phone fetches ${Bench.PC}'s copy; the button says ${model.message}") {
            runBlocking { model.sync() }
            clip() == text
        }
    }
}
