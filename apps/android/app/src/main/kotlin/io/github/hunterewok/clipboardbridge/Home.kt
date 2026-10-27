// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Tiles or a list, as the toolbar sets it; on a big screen also the orbit. */
enum class DeviceLayout(val key: String, val symbol: String, @StringRes val title: Int) {
    TILES("tiles", "▦", R.string.layout_tiles),
    LIST("list", "☰", R.string.layout_list),
    ORBIT("orbit", "◎", R.string.layout_orbit),
    ;

    companion object {
        fun of(key: String?, default: DeviceLayout): DeviceLayout = entries.firstOrNull { it.key == key } ?: default
    }
}

private enum class HomePage { MAIN, DEVICE, SETTINGS, ADD }

/**
 * The one page: the big button, the result in one line, and every device
 * of the group as tiles or a list; a device opens its details. On a big
 * screen (a tablet, a foldable's inner screen) the devices may stand on
 * orbits around this phone, and the details open beside them.
 */
@Composable
internal fun HomeScreen(model: AppModel) {
    var page by rememberSaveable { mutableStateOf(HomePage.MAIN) }
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        // The live dots: which devices are connected now.
        while (true) {
            model.refresh()
            delay(2_000)
        }
    }
    LaunchedEffect(Unit) { model.group.renewOwnCertificate() }
    BackgroundSync()
    val wide = LocalConfiguration.current.screenWidthDp >= 720
    when (page) {
        HomePage.DEVICE -> {
            val id = selected
            BackHandler { page = HomePage.MAIN }
            if (id == null || wide) {
                // A big screen shows the details beside the devices.
                LaunchedEffect(Unit) { page = HomePage.MAIN }
            } else {
                DeviceDetail(model, id, back = { page = HomePage.MAIN })
            }
        }
        HomePage.SETTINGS -> SettingsScreen(model) { page = HomePage.MAIN }
        HomePage.ADD -> AddDeviceScreen(model) { page = HomePage.MAIN }
        HomePage.MAIN ->
            if (wide) {
                WideHome(model, selected, select = { selected = it }, open = { page = it })
            } else {
                HomeMain(model, open = { page = it }) {
                    selected = it
                    page = HomePage.DEVICE
                }
            }
    }
}

/** The phone's page. */
@Composable
private fun HomeMain(model: AppModel, open: (HomePage) -> Unit, select: (String) -> Unit) {
    var layout by remember { mutableStateOf(model.settings.layout.takeIf { it != DeviceLayout.ORBIT } ?: DeviceLayout.TILES) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge), verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge)) {
        TopBar(model, layout, listOf(DeviceLayout.TILES, DeviceLayout.LIST), open) {
            layout = it
            model.settings.layout = it
        }
        Summary(model)
        SyncButton(model)
        model.message?.let { NoteText(it, dim = true) }
        DeviceCollection(model.devices, layout, select)
        Hint(model)
    }
}

/** The big screen's page: the devices, and the chosen one's details beside them. */
@Composable
private fun WideHome(model: AppModel, selected: String?, select: (String?) -> Unit, open: (HomePage) -> Unit) {
    var layout by remember { mutableStateOf(model.settings.wideLayout) }
    val scope = rememberCoroutineScope()
    Row(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).fillMaxHeight().padding(Tokens.spacingLarge), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
            TopBar(model, layout, DeviceLayout.entries.sortedBy { it != DeviceLayout.ORBIT }, open) {
                layout = it
                model.settings.wideLayout = it
            }
            Summary(model)
            model.message?.let { NoteText(it, dim = true) }
            if (layout == DeviceLayout.ORBIT) {
                Orbit(
                    model.devices,
                    selected,
                    busy = model.busy,
                    select = { select(it) },
                    sync = { scope.launch { model.sync() } },
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                )
            } else {
                Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
                    SyncButton(model)
                    DeviceCollection(model.devices, layout) { select(it) }
                }
            }
            Hint(model)
        }
        if (selected != null) {
            VerticalDivider(color = LocalPalette.current.line)
            Column(Modifier.width(400.dp).fillMaxHeight()) {
                DeviceDetail(model, selected, close = { select(null) }, back = { select(null) })
            }
        }
    }
}

/** Settings, the view, and Add a device on an admin phone. */
@Composable
private fun TopBar(model: AppModel, layout: DeviceLayout, layouts: List<DeviceLayout>, open: (HomePage) -> Unit, choose: (DeviceLayout) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        IconText("⚙", stringResource(R.string.settings)) { open(HomePage.SETTINGS) }
        Text(
            stringResource(R.string.cbb_name),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.weight(1f).padding(horizontal = Tokens.spacingMedium),
        )
        // The view: each tap shows the next one.
        val next = layouts[(layouts.indexOf(layout) + 1) % layouts.size]
        IconText(layout.symbol, stringResource(R.string.view_now, stringResource(layout.title))) { choose(next) }
        if (model.isAdmin) {
            Spacer(Modifier.width(Tokens.spacingSmall))
            IconText("+", stringResource(R.string.add_device)) { open(HomePage.ADD) }
        }
    }
}

/** How many devices are online, of how many. */
@Composable
private fun Summary(model: AppModel) {
    Text(
        stringResource(R.string.online_count, model.devices.count { it.online }, model.devices.size),
        style = MaterialTheme.typography.bodyMedium,
        color = LocalPalette.current.textDim,
    )
    // The phone as the hub works while the app is open: Home says so, as a fact, not a fault.
    model.hub?.takeIf { it.on }?.let { h ->
        Text(
            stringResource(if (h.background) R.string.hub_home_background else R.string.hub_home_note),
            style = MaterialTheme.typography.bodySmall,
            color = LocalPalette.current.textDim,
        )
    }
}

@Composable
private fun SyncButton(model: AppModel) {
    val scope = rememberCoroutineScope()
    val haptics = LocalHapticFeedback.current
    AccentButton(stringResource(R.string.send_or_fetch), enabled = !model.busy, onClick = {
        scope.launch {
            model.sync()
            haptics.performHapticFeedback(if (model.message?.error == true) HapticFeedbackType.Reject else HapticFeedbackType.Confirm)
        }
    })
}

@Composable
private fun Hint(model: AppModel) {
    val dim = LocalPalette.current.textDim
    if (!model.isAdmin) {
        Text(stringResource(R.string.not_admin_note), style = MaterialTheme.typography.bodySmall, color = dim)
    } else if (model.devices.count { it.admin } == 1) {
        Text(stringResource(R.string.lost_phone_note), style = MaterialTheme.typography.bodySmall, color = dim)
    }
}

/** The devices as tiles or as a list; each one opens its details. */
@Composable
private fun DeviceCollection(devices: List<LiveGroup.Device>, layout: DeviceLayout, select: (String) -> Unit) {
    if (devices.isEmpty()) {
        Text(stringResource(R.string.no_computers), color = LocalPalette.current.textDim)
        return
    }
    if (layout == DeviceLayout.LIST) {
        Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            for (d in devices) DeviceRow(d) { select(d.id) }
        }
        return
    }
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val columns = maxOf(2, (maxWidth / 160.dp).toInt())
        Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
            for (row in devices.chunked(columns)) {
                Row(horizontalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
                    for (d in row) DeviceTile(d, Modifier.weight(1f)) { select(d.id) }
                    repeat(columns - row.size) { Spacer(Modifier.weight(1f)) }
                }
            }
        }
    }
}

/** A device as a tile: its icon and live dot, its name, its system and where it stands. */
@Composable
private fun DeviceTile(d: LiveGroup.Device, modifier: Modifier, open: () -> Unit) {
    Column(
        modifier.glassTile().focusRing().clickable(role = Role.Button, onClick = open).padding(Tokens.spacingMedium).liveState(d),
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall),
    ) {
        Row(verticalAlignment = Alignment.Top) {
            DeviceIcon(d)
            Spacer(Modifier.weight(1f))
            OnlineDot(d.online)
        }
        Text(d.name, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
        DeviceSubtitle(d)
    }
}

/** A device as a row of the list. */
@Composable
private fun DeviceRow(d: LiveGroup.Device, open: () -> Unit) {
    val palette = LocalPalette.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = 60.dp).card().focusRing().clickable(role = Role.Button, onClick = open)
            .padding(horizontal = Tokens.spacingMedium, vertical = Tokens.spacingSmall).liveState(d),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        DeviceIcon(d, 36.dp)
        Column(Modifier.weight(1f).padding(horizontal = Tokens.spacingMedium)) {
            Text(d.name, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            DeviceSubtitle(d)
        }
        OnlineDot(d.online)
        Text("›", color = palette.textDim, modifier = Modifier.padding(start = Tokens.spacingSmall))
    }
}

/** The system (or kind) of a device, then where it stands. */
@Composable
internal fun DeviceSubtitle(d: LiveGroup.Device) {
    val first = d.system ?: stringResource(d.kind.title)
    val text = d.standing?.let { "$first · ${stringResource(it)}" } ?: first
    Text(text, style = MaterialTheme.typography.bodySmall, color = LocalPalette.current.textDim, maxLines = 1, overflow = TextOverflow.Ellipsis)
}

/** One element for TalkBack, which says whether it is online. */
@Composable
private fun Modifier.liveState(d: LiveGroup.Device): Modifier {
    val state = stringResource(if (d.online) R.string.online else R.string.offline)
    return semantics(mergeDescendants = true) { stateDescription = state }
}

/**
 * Keeps syncing in the background: the service, and on Android 13 and later
 * the permission for its notification, asked once.
 */
@Composable
private fun BackgroundSync() {
    val context = LocalContext.current
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { SyncService.start(context) }
    LaunchedEffect(Unit) {
        val permission = Manifest.permission.POST_NOTIFICATIONS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED
        ) {
            launcher.launch(permission)
        } else {
            SyncService.start(context)
        }
    }
}
