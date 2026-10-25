// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/**
 * One device: a summary of what it is and where it stands, then what an
 * admin phone may do with it (docs/apps.md, Devices). A page of its own on
 * a phone; on a big screen a pane beside the devices, which close hides.
 */
@Composable
internal fun DeviceDetail(model: AppModel, id: String, close: (() -> Unit)? = null, back: () -> Unit) {
    val d = model.devices.firstOrNull { it.id == id }
    // Removed here or by another admin: back to the devices.
    LaunchedEffect(d == null) { if (d == null) back() }
    if (d == null) return
    val content: @Composable ColumnScope.() -> Unit = {
        Header(d, close)
        Summary(d)
        Actions(model, d)
        model.message?.let { NoteText(it, dim = true) }
    }
    if (close == null) {
        Page(d.name, back, content)
    } else {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge),
            verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge),
            content = content,
        )
    }
}

@Composable
private fun Header(d: LiveGroup.Device, close: (() -> Unit)?) {
    val palette = LocalPalette.current
    Row(verticalAlignment = Alignment.Top) {
        DeviceIcon(d, 64.dp)
        Column(Modifier.weight(1f).padding(horizontal = Tokens.spacingMedium).semantics(mergeDescendants = true) {}) {
            Text(d.name, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, maxLines = 2)
            Row(verticalAlignment = Alignment.CenterVertically) {
                OnlineDot(d.online)
                Text(
                    stringResource(if (d.online) R.string.online else R.string.offline),
                    color = if (d.online) palette.accent else palette.textDim,
                    modifier = Modifier.padding(start = 6.dp),
                )
            }
        }
        if (close != null) IconText("✕", stringResource(R.string.close), onClick = close)
    }
}

/** A row of the summary: what it is, and its value. */
private data class Line(val label: String, val value: String, val mono: Boolean = false, val dim: Boolean = false)

/** What the group knows of it, a row each. */
@Composable
private fun Summary(d: LiveGroup.Device) {
    val palette = LocalPalette.current
    val lines = buildList {
        add(Line(stringResource(R.string.type), stringResource(d.kind.title)))
        d.systemWithVersion?.let { add(Line(stringResource(R.string.operating_system), it)) }
        d.device?.version?.let { add(Line(stringResource(R.string.cbb_name), it, mono = true)) }
        val mac = d.device?.mac
        if (mac != null) {
            add(Line(stringResource(R.string.mac_address), mac, mono = true))
        } else if (d.kind == DeviceKind.PHONE || d.kind == DeviceKind.TABLET) {
            add(Line(stringResource(R.string.mac_address), stringResource(R.string.hidden_by_system), dim = true))
        }
        add(Line(stringResource(R.string.role), stringResource(roleTitle(d.role))))
        d.standing?.let { add(Line(stringResource(R.string.in_the_group), stringResource(it))) }
        d.mode?.let { m -> modeTitle(m)?.let { add(Line(stringResource(R.string.sync_mode), stringResource(it))) } }
    }
    Column(Modifier.fillMaxWidth().card()) {
        lines.forEachIndexed { i, line ->
            if (i > 0) HorizontalDivider(color = palette.line)
            Row(
                Modifier.fillMaxWidth().heightIn(min = 44.dp).padding(horizontal = Tokens.spacingMedium).semantics(mergeDescendants = true) {},
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(line.label, color = palette.textDim, modifier = Modifier.padding(end = Tokens.spacingMedium))
                Text(
                    line.value,
                    fontFamily = if (line.mono) FontFamily.Monospace else null,
                    color = if (line.dim) palette.textDim else Color.Unspecified,
                    textAlign = TextAlign.End,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

private fun roleTitle(role: String) = when (role) {
    "phone" -> R.string.role_phone
    "lite" -> R.string.role_lite
    "shortcut" -> R.string.role_shortcut
    else -> R.string.role_full
}

/** The sync modes, in the order the apps show them (docs/design.md, Sync modes). */
private val modes = listOf("own", "shared", "receive", "send")

private fun modeTitle(mode: String) = when (mode) {
    "own" -> R.string.mode_own
    "shared" -> R.string.mode_shared
    "receive" -> R.string.mode_receive
    "send" -> R.string.mode_send
    else -> null
}

/** The actions an admin phone has for it; none on a phone that is no admin. */
@Composable
private fun Actions(model: AppModel, d: LiveGroup.Device) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var removing by remember { mutableStateOf(false) }
    var promoting by remember { mutableStateOf(false) }
    var thawing by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf(false) }
    var choosingMode by remember { mutableStateOf(false) }
    if (!model.isAdmin) {
        Text(stringResource(R.string.not_admin_note), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
        return
    }
    Column(Modifier.fillMaxWidth().card()) {
        Action("✎", stringResource(R.string.rename)) { renaming = true }
        if (d.frozen) {
            HorizontalDivider(color = palette.line)
            Action("❄", stringResource(R.string.unfreeze)) { thawing = true }
        }
        if (d.canMakeAdmin) {
            HorizontalDivider(color = palette.line)
            Action("★", stringResource(R.string.make_admin)) { promoting = true }
        }
        // The phones and lite members have no modes yet and refuse.
        if (!d.isSelf && d.online && d.role == "full") {
            HorizontalDivider(color = palette.line)
            Action("⇄", stringResource(R.string.sync_mode)) { choosingMode = true }
        }
        if (!d.isSelf) {
            HorizontalDivider(color = palette.line)
            Action("✕", stringResource(R.string.remove), danger = true) { removing = true }
        }
    }
    if (removing) {
        Confirm(
            title = stringResource(R.string.remove_title, d.name),
            body = stringResource(if (d.isRoot) R.string.remove_root_body else R.string.remove_body),
            action = stringResource(R.string.remove),
            dismiss = { removing = false },
        ) { scope.launch { model.remove(d.id) } }
    }
    if (promoting) {
        Confirm(
            title = stringResource(R.string.make_admin_title, d.name),
            body = stringResource(R.string.make_admin_body),
            action = stringResource(R.string.make_admin),
            dismiss = { promoting = false },
        ) { scope.launch { model.makeAdmin(d.id) } }
    }
    if (choosingMode) ModeChoice(d, dismiss = { choosingMode = false }) { mode -> scope.launch { model.setMode(d.id, mode) } }
    if (renaming) Rename(d, dismiss = { renaming = false }) { name -> scope.launch { model.rename(d.id, name) } }
    if (thawing) {
        Confirm(
            title = stringResource(R.string.unfreeze_title, d.name),
            body = stringResource(R.string.unfreeze_body),
            action = stringResource(R.string.unfreeze),
            dismiss = { thawing = false },
        ) { scope.launch { model.unfreeze(d.id) } }
    }
}

/** The sync modes to pick from, the computer's own marked. */
@Composable
private fun ModeChoice(d: LiveGroup.Device, dismiss: () -> Unit, choose: (String) -> Unit) {
    val palette = LocalPalette.current
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.sync_mode)) },
        text = {
            Column {
                for (m in modes) {
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button) {
                            dismiss()
                            choose(m)
                        },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(if (m == d.mode) "✓" else "", color = palette.accent, modifier = Modifier.width(24.dp))
                        Text(stringResource(modeTitle(m)!!), color = palette.text, modifier = Modifier.padding(start = Tokens.spacingMedium))
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}

@Composable
private fun Action(symbol: String, title: String, danger: Boolean = false, perform: () -> Unit) {
    val palette = LocalPalette.current
    val color = if (danger) palette.danger else palette.accent
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button, onClick = perform).padding(horizontal = Tokens.spacingMedium),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(symbol, color = color, modifier = Modifier.width(24.dp))
        Text(title, color = color, modifier = Modifier.padding(start = Tokens.spacingMedium))
    }
}
