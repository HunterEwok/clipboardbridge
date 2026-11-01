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
import androidx.compose.ui.test.onNodeWithContentDescription
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

    /** The computer's device ID in the phone's list. */
    private fun idOf(name: String): String = model.group.devices.firstOrNull { it.name == name }?.id
        ?: throw AssertionError("no $name in the phone's devices: ${model.group.devices.map { it.name }}")

    /** M7: in the default mode (shared) a computer's new copy comes onto the phone's clipboard without the button. */
    @Test
    fun a4_receivesByItself() {
        val text = "cbb-bench phone M7 by itself ${System.currentTimeMillis()}"
        Bench.copy(Bench.PC, text)
        until(30, "${Bench.PC}'s copy on the phone's clipboard without the button; it has ${clip()}") { clip() == text }
    }

    /** M7: in the mode send the phone leaves its clipboard alone; shared again, it takes copies. */
    @Test
    fun a5_sendModeKeepsClipboard() {
        val self = model.group.devices.first { it.isSelf }.id
        runBlocking { model.setMode(self, "send") }
        assertEquals("send", model.group.syncMode)
        try {
            val before = clip()
            val text = "cbb-bench phone M7 not taken ${System.currentTimeMillis()}"
            Bench.copy(Bench.PC, text)
            Thread.sleep(10_000)
            assertEquals("in the mode send the phone took ${Bench.PC}'s copy", before, clip())
        } finally {
            runBlocking { model.setMode(self, "shared") }
        }
        assertEquals("shared", model.group.syncMode)
    }

    /** T16: "Paste on it…" types and pastes into the computer's tmux, with Enter and as a secret. */
    @Test
    fun a6_pasteOnComputer() {
        val pc = idOf(Bench.PC)
        // The line of clipboardbridge.conf that starts the helper, and a client attached on a terminal.
        Bench.run(Bench.PC, "tmux new-session -d -s cbb -x 120 -y 30 && tmux run-shell -b 'cbb paste-helper tmux >/tmp/cbb-helper.log 2>&1 || true'")
        Bench.run(Bench.PC, "cbb paste-receive on -console")
        Bench.start(Bench.PC, "TERM=xterm sh -c 'sleep infinity | script -qfc \"tmux attach -t cbb\" /dev/null'")
        until(10, "a tmux client on ${Bench.PC}") { Bench.run(Bench.PC, "tmux list-clients").isNotBlank() }
        val pane = { Bench.run(Bench.PC, "tmux capture-pane -p -J -t cbb") }
        for ((method, secret) in listOf("type" to false, "paste" to false, "paste" to true)) {
            val text = "cbbbench$method${if (secret) "secret" else ""}${System.currentTimeMillis()}"
            // The receiver takes one paste a second from a sender.
            Thread.sleep(1_100)
            val done = runBlocking { model.paste(pc, text, method, enter = true, secret = secret) }
            assertTrue("$method${if (secret) " as a secret" else ""} refused: ${model.message}", done)
            until(20, "the pane on ${Bench.PC} shows $text:\n${pane()}") { pane().contains(text) }
        }
    }

    /** Q8: a quick action the computer allows runs from the phone; turned all off, the next is refused. */
    @Test
    fun a7_quickActions() {
        val pc = idOf(Bench.PC)
        Bench.run(Bench.PC, "cbb action enable restart -any-key -yes")
        val pid = { Bench.run(Bench.PC, "pgrep -o -f 'cbb service'").trim() }
        val before = pid()
        assertTrue("restart refused: ${model.message}", runBlocking { model.runAction(pc, "restart") })
        until(30, "the service on ${Bench.PC} restarted") { runCatching { pid() }.getOrDefault(before).let { it.isNotEmpty() && it != before } }
        until(60, "the phone connected to ${Bench.PC} again") { model.group.devices.any { it.name == Bench.PC && it.online } }
        assertTrue("turning all off refused: ${model.message}", runBlocking { model.actionsOff(pc) })
        assertFalse("restart ran after all were turned off", runBlocking { model.runAction(pc, "restart") })
    }

    /** A1: a second computer admitted, renamed and removed; the removed one says so. */
    @Test
    fun a8_renameAndRemove() {
        val second = Bench.add()
        compose.onNodeWithContentDescription(str(R.string.add_device)).performClick()
        val (code, pairing) = Bench.pairCode(second)
        compose.onNode(hasSetTextAction()).performTextInput(code)
        compose.onNodeWithText(str(R.string.add)).performClick()
        val out = pairing.finish(90)
        assertTrue("cbb pair on $second did not join:\n$out", out.contains("Joined the group."))
        until(30, "$second in the phone's devices") { model.group.devices.any { it.name == second } }
        val id = idOf(second)
        runBlocking { model.rename(id, "bench-second") }
        assertEquals("renaming says ${model.message}", R.string.renamed, model.message?.text)
        until(30, "the new name on ${Bench.PC}") { Bench.run(Bench.PC, "cbb status").contains("bench-second") }
        runBlocking { model.remove(id) }
        assertEquals("removing says ${model.message}", R.string.removed, model.message?.text)
        until(60, "$second says it was removed") { Bench.run(second, "cbb status").contains("removed from the group") }
    }
}

