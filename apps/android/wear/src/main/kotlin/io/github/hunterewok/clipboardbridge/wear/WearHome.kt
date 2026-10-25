// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.wear

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.wear.compose.foundation.lazy.ScalingLazyColumn
import androidx.wear.compose.foundation.lazy.rememberScalingLazyListState
import androidx.wear.compose.material3.AppScaffold
import androidx.wear.compose.material3.ColorScheme
import androidx.wear.compose.material3.ListHeader
import androidx.wear.compose.material3.MaterialTheme
import androidx.wear.compose.material3.ScreenScaffold
import androidx.wear.compose.material3.SwitchButton
import androidx.wear.compose.material3.Text
import io.github.hunterewok.clipboardbridge.FormGlyph
import io.github.hunterewok.clipboardbridge.Palette
import io.github.hunterewok.clipboardbridge.WatchState
import io.github.hunterewok.clipboardbridge.paletteNamed

/** The one page: how many devices are online, the away switch, the devices and the latest events. */
@Composable
fun WearHome(model: WearModel) {
    // A watch is dark.
    val palette = paletteNamed(model.state.color).dark
    MaterialTheme(colorScheme = scheme(palette)) {
        AppScaffold {
            val list = rememberScalingLazyListState()
            ScreenScaffold(scrollState = list) { padding ->
                ScalingLazyColumn(
                    state = list,
                    contentPadding = padding,
                    modifier = Modifier.fillMaxSize().background(palette.background),
                ) {
                    item { ListHeader { Text("CBB", color = palette.accent) } }
                    val s = model.state
                    if (!s.hasGroup) {
                        item { Text(stringResource(R.string.no_group), color = palette.textDim, textAlign = TextAlign.Center) }
                        return@ScalingLazyColumn
                    }
                    item {
                        Text(
                            stringResource(R.string.online_count, s.devices.count { it.online }, s.devices.size),
                            style = MaterialTheme.typography.titleMedium,
                            color = palette.text,
                        )
                    }
                    s.away?.let { away ->
                        item {
                            SwitchButton(
                                checked = away != WatchState.Away.OFF,
                                onCheckedChange = { model.setAway(it) },
                                enabled = !model.switching,
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text(stringResource(R.string.away)) },
                                secondaryLabel = { Text(stringResource(awayLine(away))) },
                            )
                        }
                    }
                    model.note?.let { n ->
                        item {
                            Text(
                                stringResource(n.text) + (n.detail?.let { "\n\n" + it } ?: ""),
                                color = palette.danger,
                                style = MaterialTheme.typography.bodySmall,
                                textAlign = TextAlign.Center,
                            )
                        }
                    }
                    item { ListHeader { Text(stringResource(R.string.devices), color = palette.textDim) } }
                    items(s.devices.size) { i -> DeviceRow(s.devices[i], palette) }
                    if (s.events.isNotEmpty()) {
                        item { ListHeader { Text(stringResource(R.string.latest), color = palette.textDim) } }
                        items(s.events.size) { i ->
                            Text(s.events[i], color = palette.text, style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth())
                        }
                    }
                    if (!model.reachable) {
                        item { Text(stringResource(R.string.stale), color = palette.textDim, style = MaterialTheme.typography.bodySmall) }
                    }
                }
            }
        }
    }
}

@Composable
private fun DeviceRow(d: WatchState.Device, palette: Palette) {
    val state = stringResource(if (d.online) R.string.online else R.string.offline)
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp).semantics(mergeDescendants = true) { stateDescription = state },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FormGlyph(d.form, if (d.online) palette.accent else palette.textDim, 20.dp)
        Spacer(Modifier.width(8.dp))
        Text(d.name, color = palette.text, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(8.dp))
        Box(Modifier.size(8.dp).clip(CircleShape).background(if (d.online) palette.accent else palette.textDim.copy(alpha = 0.4f)))
    }
}

private fun awayLine(away: WatchState.Away): Int = when (away) {
    WatchState.Away.OFF -> R.string.away_off
    WatchState.Away.AT_HOME -> R.string.away_at_home
    WatchState.Away.CONNECTING -> R.string.away_connecting
    WatchState.Away.CONNECTED -> R.string.away_connected
    WatchState.Away.WAITING -> R.string.away_waiting
}

/** The phone's colour on the watch's dark theme. */
private fun scheme(p: Palette) = ColorScheme(
    primary = p.accent,
    onPrimary = p.onAccent,
    background = p.background,
    onBackground = p.text,
    surfaceContainerLow = p.surface,
    surfaceContainer = p.surface,
    surfaceContainerHigh = p.surface,
    onSurface = p.text,
    onSurfaceVariant = p.textDim,
    error = p.danger,
)
