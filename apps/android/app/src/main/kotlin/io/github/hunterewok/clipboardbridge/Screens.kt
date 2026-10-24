// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Picks the screen, and asks once for the local network, which finding the computers needs on Android 17. */
@Composable
fun Root(model: AppModel) {
    AppTheme(model.theme) {
        GridBackground {
            LocalNetworkPermission(model)
            Box(Modifier.safeDrawingPadding()) {
                when (model.phase) {
                    AppModel.Phase.START -> StartScreen(model)
                    AppModel.Phase.JOINING -> JoinScreen(model)
                    AppModel.Phase.HOME -> HomeScreen(model)
                }
            }
        }
    }
}

/** The permission for devices on the local network: Android 17 asks for it before mDNS and the connections to the computers work. */
@Composable
private fun LocalNetworkPermission(model: AppModel) {
    if (Build.VERSION.SDK_INT < 37) return
    val context = LocalContext.current
    val permission = "android.permission.ACCESS_LOCAL_NETWORK"
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) model.group.reconnect()
    }
    LaunchedEffect(Unit) {
        if (ContextCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED) launcher.launch(permission)
    }
}

// Start

/**
 * No group yet: what clipboardbridge does, the note that this phone is
 * ready (once), connecting a device, and joining the group of a phone that
 * already uses clipboardbridge. Theme and language are a tap away.
 */
@Composable
private fun StartScreen(model: AppModel) {
    val palette = LocalPalette.current
    var adding by rememberSaveable { mutableStateOf(false) }
    var settings by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.prepare() }
    if (adding) {
        AddDeviceScreen(model) { adding = false }
        return
    }
    if (settings) {
        SettingsScreen(model) { settings = false }
        return
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge),
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            // The system's own language, not the one the app shows.
            val system = remember { android.content.res.Resources.getSystem().configuration.locales[0] }
            if (LanguageChoice.offeredOnStart(system)) StartLanguageMenu(model)
            Spacer(Modifier.weight(1f))
            IconText("⚙", stringResource(R.string.settings)) { settings = true }
        }
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        Text(
            stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineLarge,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            color = palette.accent,
        )
        Text(stringResource(R.string.tagline), textAlign = TextAlign.Center, color = palette.textDim)
        if (model.welcome) WelcomeCard(model)
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            AccentButton(stringResource(R.string.connect_device), onClick = {
                model.dismissWelcome()
                adding = true
            })
            Text(
                stringResource(R.string.connect_hint),
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
                color = palette.textDim,
            )
        }
        QuietButton(stringResource(R.string.join_other), onClick = { model.startJoining() })
        model.message?.let { NoteText(it) }
    }
}

/**
 * The language menu next to the gear when the system's language has no
 * translation; the app shows English then, so English is the one chosen.
 */
@Composable
private fun StartLanguageMenu(model: AppModel) {
    val activity = LocalActivity.current
    var open by remember { mutableStateOf(false) }
    val chosen = model.settings.language.takeIf { it != LanguageChoice.SYSTEM } ?: LanguageChoice.EN
    Box {
        TextButton(onClick = { open = true }, modifier = Modifier.card()) {
            Text("${chosen.ownName} ▾", color = LocalPalette.current.text)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for (l in LanguageChoice.translations) {
                DropdownMenuItem(text = { Text(l.ownName ?: "") }, onClick = {
                    open = false
                    model.settings.language = l
                    activity?.recreate()
                })
            }
        }
    }
}

/** Said once, at the first launch: this phone has its own key now, and the next step is to connect a device. */
@Composable
private fun WelcomeCard(model: AppModel) {
    val palette = LocalPalette.current
    Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("✓ ", color = palette.accent, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.welcome_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            IconText("✕", stringResource(R.string.close), small = true) { model.dismissWelcome() }
        }
        Text(stringResource(R.string.welcome_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
    }
}

// Joining

/** Joining another phone's group: this phone's QR code, which the other phone scans in Add a device. */
@Composable
private fun JoinScreen(model: AppModel) {
    val palette = LocalPalette.current
    LaunchedEffect(Unit) { model.join() }
    BackHandler { model.cancelJoin() }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge),
    ) {
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        Text(
            stringResource(R.string.join_title),
            style = MaterialTheme.typography.headlineMedium,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            color = palette.accent,
        )
        val code = model.joinCode
        if (code != null) {
            val label = stringResource(R.string.join_qr_label)
            QrCode(
                code.qrText,
                Modifier.widthIn(max = 280.dp).fillMaxWidth().aspectRatio(1f)
                    .clip(RoundedCornerShape(Tokens.radiusCard)).background(Color.White).padding(Tokens.spacingMedium)
                    .semantics { contentDescription = label },
            )
            Text(stringResource(R.string.join_hint), textAlign = TextAlign.Center, color = palette.textDim)
        } else if (model.message == null) {
            CircularProgressIndicator(color = palette.accent)
        }
        model.message?.let { NoteText(it) }
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        QuietButton(stringResource(R.string.cancel), onClick = { model.cancelJoin() })
    }
}

/** A QR code drawn module by module, black on the white behind it. */
@Composable
private fun QrCode(text: String, modifier: Modifier) {
    val matrix = remember(text) {
        QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 0))
    }
    Canvas(modifier) {
        val n = matrix.width
        val cell = minOf(size.width, size.height) / n
        for (y in 0 until n) for (x in 0 until n) {
            if (matrix[x, y]) drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
        }
    }
}

// Home

private enum class HomePage { MAIN, DEVICES, SETTINGS, ADD }

/** The big button, the result in one line, and the computers; the other pages open from here. */
@Composable
private fun HomeScreen(model: AppModel) {
    var page by rememberSaveable { mutableStateOf(HomePage.MAIN) }
    LaunchedEffect(Unit) {
        // The live dots: which computers are connected now.
        while (true) {
            model.refresh()
            delay(2_000)
        }
    }
    LaunchedEffect(Unit) { model.group.renewOwnCertificate() }
    BackgroundSync()
    when (page) {
        HomePage.DEVICES -> {
            BackHandler { page = HomePage.MAIN }
            DevicesScreen(model) { page = HomePage.MAIN }
        }
        HomePage.SETTINGS -> SettingsScreen(model) { page = HomePage.MAIN }
        HomePage.ADD -> AddDeviceScreen(model) { page = HomePage.MAIN }
        HomePage.MAIN -> HomeMain(model, open = { page = it })
    }
}

@Composable
private fun HomeMain(model: AppModel, open: (HomePage) -> Unit) {
    val scope = rememberCoroutineScope()
    val haptics = LocalHapticFeedback.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge), verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            IconText("⚙", stringResource(R.string.settings)) { open(HomePage.SETTINGS) }
            Spacer(Modifier.weight(1f))
            if (model.isAdmin) IconText("+", stringResource(R.string.add_device)) { open(HomePage.ADD) }
        }
        AccentButton(stringResource(R.string.send_or_fetch), enabled = !model.busy, onClick = {
            scope.launch {
                model.sync()
                haptics.performHapticFeedback(if (model.message?.error == true) HapticFeedbackType.Reject else HapticFeedbackType.Confirm)
            }
        })
        model.message?.let { NoteText(it, dim = true) }
        ComputerList(model.computers, Modifier.clickable(role = Role.Button) { open(HomePage.DEVICES) })
    }
}

/** The computers as a compact list with a live dot each. */
@Composable
private fun ComputerList(computers: List<LiveGroup.Device>, modifier: Modifier) {
    val palette = LocalPalette.current
    val online = stringResource(R.string.online)
    val offline = stringResource(R.string.offline)
    Column(Modifier.fillMaxWidth().card().then(modifier).padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        Text(stringResource(R.string.computers), style = MaterialTheme.typography.titleMedium)
        if (computers.isEmpty()) Text(stringResource(R.string.no_computers), color = palette.textDim)
        for (c in computers) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.semantics(mergeDescendants = true) { stateDescription = if (c.online) online else offline },
            ) {
                Box(Modifier.size(8.dp).clip(CircleShape).background(if (c.online) palette.accent else palette.textDim))
                Text(c.name, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(start = Tokens.spacingSmall))
            }
        }
    }
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

// Devices

/**
 * The whole group: every device with its role, whether it is online, the
 * admins marked; on an admin phone a device can be removed, and on the root
 * phone a computer that offers an admin key made an admin (docs/apps.md,
 * Devices).
 */
@Composable
private fun DevicesScreen(model: AppModel, back: () -> Unit) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var removing by remember { mutableStateOf<LiveGroup.Device?>(null) }
    var promoting by remember { mutableStateOf<LiveGroup.Device?>(null) }
    Page(stringResource(R.string.devices), back) {
        if (model.devices.isEmpty()) Text(stringResource(R.string.no_computers), color = palette.textDim)
        Column(Modifier.fillMaxWidth().card()) {
            model.devices.forEachIndexed { i, d ->
                if (i > 0) HorizontalDivider(color = palette.grid)
                DeviceRow(
                    d,
                    canRemove = model.isAdmin && !d.isSelf,
                    remove = { removing = d },
                    promote = { promoting = d },
                )
            }
        }
        if (!model.isAdmin) {
            Text(stringResource(R.string.not_admin_note), color = palette.textDim)
        } else if (model.devices.count { it.admin } == 1) {
            Text(stringResource(R.string.lost_phone_note), color = palette.textDim)
        }
        model.message?.let { NoteText(it, dim = true) }
    }
    removing?.let { d ->
        Confirm(
            title = stringResource(R.string.remove_title, d.name),
            body = stringResource(if (d.isRoot) R.string.remove_root_body else R.string.remove_body),
            action = stringResource(R.string.remove),
            dismiss = { removing = null },
        ) { scope.launch { model.remove(d.id) } }
    }
    promoting?.let { d ->
        Confirm(
            title = stringResource(R.string.make_admin_title, d.name),
            body = stringResource(R.string.make_admin_body),
            action = stringResource(R.string.make_admin),
            dismiss = { promoting = null },
        ) { scope.launch { model.makeAdmin(d.id) } }
    }
}

@Composable
private fun DeviceRow(d: LiveGroup.Device, canRemove: Boolean, remove: () -> Unit, promote: () -> Unit) {
    val palette = LocalPalette.current
    var menu by remember { mutableStateOf(false) }
    val hasMenu = canRemove || d.canMakeAdmin
    Row(
        Modifier.fillMaxWidth().then(if (hasMenu) Modifier.clickable { menu = true } else Modifier)
            .padding(horizontal = Tokens.spacingMedium, vertical = Tokens.spacingSmall + 4.dp)
            .semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(10.dp).clip(CircleShape).background(if (d.online) palette.accent else palette.textDim))
        Column(Modifier.weight(1f).padding(horizontal = Tokens.spacingMedium)) {
            Text(d.name, fontFamily = FontFamily.Monospace)
            val note = when {
                d.isSelf && d.admin -> stringResource(R.string.this_phone_admin)
                d.isSelf -> stringResource(R.string.this_phone)
                d.admin -> "${roleName(d.role)} · ${stringResource(R.string.admin)}"
                else -> roleName(d.role)
            }
            Text(note, style = MaterialTheme.typography.bodySmall, color = palette.textDim)
        }
        Text(
            stringResource(if (d.online) R.string.online else R.string.offline),
            style = MaterialTheme.typography.bodySmall,
            color = if (d.online) palette.accent else palette.textDim,
        )
        if (hasMenu) {
            Box {
                Text("⋮", modifier = Modifier.padding(start = Tokens.spacingSmall), color = palette.textDim)
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    if (d.canMakeAdmin) {
                        DropdownMenuItem(text = { Text(stringResource(R.string.make_admin)) }, onClick = {
                            menu = false
                            promote()
                        })
                    }
                    if (canRemove) {
                        DropdownMenuItem(text = { Text(stringResource(R.string.remove), color = palette.danger) }, onClick = {
                            menu = false
                            remove()
                        })
                    }
                }
            }
        }
    }
}

/** A device's role in a word: the protocol's names, which are the same in every language. */
private fun roleName(role: String): String = when (role) {
    "mac" -> "macOS"
    "linux" -> "Linux"
    "lite" -> "lite"
    else -> role
}

@Composable
private fun Confirm(title: String, body: String, action: String, dismiss: () -> Unit, confirm: () -> Unit) {
    val palette = LocalPalette.current
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = {
            TextButton(onClick = {
                dismiss()
                confirm()
            }) { Text(action, color = palette.danger) }
        },
        dismissButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}

// Adding

/** The camera with a frame; the text of the QR code by hand when there is no camera or it is not allowed. */
@Composable
private fun AddDeviceScreen(model: AppModel, close: () -> Unit) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val hasCamera = remember { context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) }
    var allowed by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var asked by rememberSaveable { mutableStateOf(false) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        allowed = it
        asked = true
    }
    LaunchedEffect(Unit) {
        model.message = null
        if (hasCamera && !allowed && !asked) launcher.launch(Manifest.permission.CAMERA)
    }
    // The device being admitted: one at a time; leaving the page cancels it.
    var adding by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    val add = { text: String ->
        if (adding == null) {
            adding = scope.launch {
                try {
                    if (model.scanned(text)) close()
                } finally {
                    adding = null
                }
            }
        }
    }
    BackHandler { close() }
    Page(stringResource(R.string.add_device), close) {
        if (hasCamera && allowed) {
            QrScanner(
                onCode = { text -> scope.launch { if (!model.busy) add(text) } },
                modifier = Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(Tokens.radiusCard)),
            )
            Text(stringResource(R.string.scan_hint), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        } else {
            Text(
                stringResource(if (hasCamera) R.string.camera_denied else R.string.paste_hint),
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        var typed by rememberSaveable { mutableStateOf("") }
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it },
            label = { Text(stringResource(R.string.qr_text)) },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth(),
        )
        AccentButton(stringResource(R.string.add), enabled = typed.isNotBlank() && !model.busy, onClick = { add(typed) })
        if (model.busy) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                CircularProgressIndicator(Modifier.size(20.dp), color = palette.accent, strokeWidth = 2.dp)
                Text(stringResource(R.string.connecting))
            }
        } else {
            model.message?.let { NoteText(it) }
        }
    }
}

// Settings

/** Theme, language, sending copies by themselves, sync away from home, about. */
@Composable
private fun SettingsScreen(model: AppModel, back: () -> Unit) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    val activity = LocalActivity.current
    BackHandler { back() }
    Page(stringResource(R.string.settings), back) {
        Section(stringResource(R.string.theme)) {
            for (t in ThemeChoice.offered) {
                Choice(stringResource(t.title), model.theme == t) { model.choose(t) }
            }
        }
        Section(stringResource(R.string.language)) {
            for (l in LanguageChoice.entries) {
                Choice(l.ownName ?: stringResource(R.string.language_system), model.settings.language == l) {
                    if (model.settings.language != l) {
                        model.settings.language = l
                        activity?.recreate()
                    }
                }
            }
        }
        if (model.phase == AppModel.Phase.HOME) AutoSend()
        if (model.phase == AppModel.Phase.HOME) model.away?.let { AwayFromHomeSection(model, it) }
        Section(stringResource(R.string.about)) {
            val version = remember { runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull() ?: "" }
            Row(Modifier.fillMaxWidth().padding(Tokens.spacingMedium)) {
                Text(stringResource(R.string.version), modifier = Modifier.weight(1f))
                Text(version, fontFamily = FontFamily.Monospace, color = palette.textDim)
            }
            HorizontalDivider(color = palette.grid)
            Text(
                stringResource(R.string.source),
                color = palette.accent,
                modifier = Modifier.fillMaxWidth().clickable(role = Role.Button) {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/HunterEwok/clipboardbridge")))
                }.padding(Tokens.spacingMedium),
            )
        }
    }
}

/** The setup of CopyWatcher: what it is for, whether it is on, and the way to the system's settings. */
@Composable
private fun AutoSend() {
    val palette = LocalPalette.current
    val context = LocalContext.current
    var on by remember { mutableStateOf(CopyWatcher.isOn(context)) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { on = CopyWatcher.isOn(context) }
    Section(stringResource(R.string.accessibility_label)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Text(
                stringResource(if (on) R.string.auto_send_on else R.string.auto_send_off),
                color = if (on) palette.accent else palette.textDim,
                fontWeight = FontWeight.SemiBold,
            )
            Text(stringResource(R.string.auto_send_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
            if (!on) {
                TextButton(onClick = {
                    context.startActivity(Intent(android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                }) { Text(stringResource(R.string.open_accessibility), color = palette.accent) }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    Text(stringResource(R.string.restricted_hint), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
                    TextButton(onClick = {
                        context.startActivity(
                            Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    }) { Text(stringResource(R.string.app_info), color = palette.accent) }
                }
            }
        }
    }
}

/** Sync away from home: what it does, the switch, and where it stands. */
@Composable
private fun AwayFromHomeSection(model: AppModel, away: AppModel.Away) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    Section(stringResource(R.string.away_title)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Row(
                Modifier.fillMaxWidth().clickable(role = Role.Switch, enabled = !busy) {
                    busy = true
                    scope.launch {
                        model.setAway(!away.on)
                        busy = false
                    }
                },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(R.string.away_switch), modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                Switch(checked = away.on, onCheckedChange = null, enabled = !busy)
            }
            val status = when {
                !away.on -> R.string.away_off
                away.status == AwayFromHome.Status.AT_HOME -> R.string.away_at_home
                away.status == AwayFromHome.Status.CONNECTING -> R.string.away_connecting
                away.status == AwayFromHome.Status.CONNECTED -> R.string.away_connected
                else -> R.string.away_waiting
            }
            Text(stringResource(status), color = if (away.status == AwayFromHome.Status.CONNECTED) palette.accent else palette.textDim)
            away.error?.let { NoteText(it) }
            model.awayNote?.let { NoteText(it) }
            Text(stringResource(R.string.away_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Text(title, style = MaterialTheme.typography.titleSmall, color = LocalPalette.current.textDim)
    Column(Modifier.fillMaxWidth().card(), content = content)
}

@Composable
private fun Choice(title: String, selected: Boolean, select: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(role = Role.RadioButton, onClick = select).padding(horizontal = Tokens.spacingMedium, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, modifier = Modifier.weight(1f))
        RadioButton(selected = selected, onClick = null)
    }
}

// Parts

/** A page with a title and a way back. */
@Composable
private fun Page(title: String, back: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconText("←", stringResource(R.string.back)) { back() }
            Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(start = Tokens.spacingMedium))
        }
        content()
    }
}

/** A round button with a symbol, and its name for TalkBack. */
@Composable
private fun IconText(symbol: String, label: String, small: Boolean = false, onClick: () -> Unit) {
    val palette = LocalPalette.current
    Box(
        Modifier.size(if (small) 32.dp else 44.dp).clip(CircleShape).background(if (small) Color.Transparent else palette.surface)
            .clickable(role = Role.Button, onClick = onClick).semantics { contentDescription = label },
        contentAlignment = Alignment.Center,
    ) {
        Text(symbol, color = if (small) palette.textDim else palette.text, style = MaterialTheme.typography.titleMedium)
    }
}

/** A note: the line, and the error underneath when details are on. */
@Composable
private fun NoteText(note: AppModel.Note, dim: Boolean = false) {
    val palette = LocalPalette.current
    val color = if (note.error && !dim) palette.danger else palette.textDim
    Column(Modifier.fillMaxWidth()) {
        Text(stringResource(note.text), color = if (note.error) palette.danger else color)
        note.detail?.let { Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = palette.textDim) }
    }
}
