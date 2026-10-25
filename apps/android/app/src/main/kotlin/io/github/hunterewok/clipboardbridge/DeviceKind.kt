// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import androidx.annotation.StringRes
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** What a device is, for its icon and its type; the same kinds as the iPhone app's. */
enum class DeviceKind(val form: String, @StringRes val title: Int) {
    LAPTOP("laptop", R.string.kind_laptop),
    DESKTOP("desktop", R.string.kind_desktop),
    PHONE("phone", R.string.kind_phone),
    TABLET("tablet", R.string.kind_tablet),
    TV("tv", R.string.kind_tv),
    BOARD("board", R.string.kind_board),
    SERVER("server", R.string.kind_server),
    ROUTER("router", R.string.kind_router),
    CONSOLE("console", R.string.kind_console),
    WATCH("watch", R.string.kind_watch),
    RETRO("retro", R.string.kind_retro),
    OTHER("other", R.string.kind_other),
    ;

    companion object {
        fun of(form: String?): DeviceKind? = entries.firstOrNull { it.form == form }
    }
}

/** Its kind as its hello says, or else as its role and system tell: a Mac is taken for a laptop, another computer for a desktop. */
val LiveGroup.Device.kind: DeviceKind
    get() = DeviceKind.of(device?.form) ?: when {
        role == "phone" || role == "shortcut" -> DeviceKind.PHONE
        role == "lite" -> DeviceKind.BOARD
        os == "macos" -> DeviceKind.LAPTOP
        os == "ios" || os == "android" -> DeviceKind.PHONE
        else -> DeviceKind.DESKTOP
    }

/** The name of its operating system, the same in every language; null when the records do not tell. */
val LiveGroup.Device.system: String?
    get() = when (os) {
        "linux" -> "Linux"
        "windows" -> "Windows"
        "macos" -> "macOS"
        "ios" -> "iOS"
        "android" -> "Android"
        else -> null
    }

/** Its system with the version its hello gives, as "macOS 15.1"; Linux names its distribution, which says more. */
val LiveGroup.Device.systemWithVersion: String?
    get() {
        val v = device?.osVersion
        val s = system ?: return v
        return when {
            v == null -> s
            os == "linux" -> v
            else -> "$s $v"
        }
    }

/** Its place in the group, in a word; null for a plain member. */
@get:StringRes
val LiveGroup.Device.standing: Int?
    get() = when {
        isSelf -> if (admin) R.string.this_phone_admin else R.string.this_phone
        frozen -> R.string.frozen
        isRoot -> R.string.root
        admin -> R.string.admin
        else -> null
    }

/** A device's icon on a soft square, bright while it is online. */
@Composable
fun DeviceIcon(d: LiveGroup.Device, size: Dp = 44.dp) {
    val palette = LocalPalette.current
    Box(
        Modifier.size(size).clip(RoundedCornerShape(size * 0.28f)).background(if (d.online) palette.soft else palette.line),
        contentAlignment = Alignment.Center,
    ) {
        DeviceGlyph(d.kind, if (d.online) palette.accent else palette.textDim, size * 0.56f)
    }
}

/** A live dot: the accent while online. */
@Composable
fun OnlineDot(online: Boolean, size: Dp = 8.dp) {
    val palette = LocalPalette.current
    Box(Modifier.size(size).clip(CircleShape).background(if (online) palette.accent else palette.textDim.copy(alpha = 0.4f)))
}

/** A kind's outline, drawn on a grid of 24 by 24, as the system's line icons are. */
@Composable
fun DeviceGlyph(kind: DeviceKind, color: Color, size: Dp) {
    Canvas(Modifier.size(size)) {
        val u = this.size.minDimension / 24f
        val stroke = Stroke(width = 1.8f * u, cap = StrokeCap.Round)
        fun box(x: Float, y: Float, w: Float, h: Float, r: Float = 1.5f) =
            drawRoundRect(color, Offset(x * u, y * u), Size(w * u, h * u), CornerRadius(r * u), style = stroke)
        fun line(x1: Float, y1: Float, x2: Float, y2: Float) = drawLine(color, Offset(x1 * u, y1 * u), Offset(x2 * u, y2 * u), stroke.width, StrokeCap.Round)
        fun dot(x: Float, y: Float, r: Float = 1f) = drawCircle(color, r * u, Offset(x * u, y * u))
        when (kind) {
            DeviceKind.LAPTOP -> { box(4f, 5f, 16f, 11f); line(2f, 19f, 22f, 19f) }
            DeviceKind.DESKTOP -> { box(3f, 4f, 18f, 12f); line(12f, 16f, 12f, 20f); line(8f, 20f, 16f, 20f) }
            DeviceKind.PHONE -> { box(7f, 2.5f, 10f, 19f, 2.5f); line(10.5f, 18.5f, 13.5f, 18.5f) }
            DeviceKind.TABLET -> { box(4.5f, 2.5f, 15f, 19f, 2f); line(10.5f, 18.5f, 13.5f, 18.5f) }
            DeviceKind.TV -> { box(2.5f, 5f, 19f, 12f); line(8f, 20.5f, 16f, 20.5f); line(9f, 2f, 12f, 5f); line(15f, 2f, 12f, 5f) }
            DeviceKind.BOARD -> {
                box(6f, 6f, 12f, 12f)
                box(9.5f, 9.5f, 5f, 5f, 0.8f)
                for (p in listOf(9f, 12f, 15f)) { line(p, 2.5f, p, 6f); line(p, 18f, p, 21.5f); line(2.5f, p, 6f, p); line(18f, p, 21.5f, p) }
            }
            DeviceKind.SERVER -> { box(4f, 3.5f, 16f, 7f); box(4f, 13.5f, 16f, 7f); dot(8f, 7f); dot(8f, 17f) }
            DeviceKind.ROUTER -> { box(3f, 12f, 18f, 8f); line(7f, 12f, 5f, 4f); line(17f, 12f, 19f, 4f); dot(7.5f, 16f); dot(11f, 16f) }
            DeviceKind.CONSOLE -> {
                box(2.5f, 7f, 19f, 11f, 5f)
                line(7f, 10.5f, 7f, 14.5f); line(5f, 12.5f, 9f, 12.5f)
                dot(15.5f, 11f); dot(17.5f, 13.5f)
            }
            DeviceKind.WATCH -> { box(7f, 6f, 10f, 12f, 3f); line(9f, 6f, 9.5f, 2.5f); line(15f, 6f, 14.5f, 2.5f); line(9f, 18f, 9.5f, 21.5f); line(15f, 18f, 14.5f, 21.5f) }
            DeviceKind.RETRO -> {
                box(2f, 7f, 20f, 10f)
                for (x in listOf(6f, 9f, 12f, 15f, 18f)) dot(x, 10.5f, 0.8f)
                line(7f, 14f, 17f, 14f)
            }
            DeviceKind.OTHER -> { box(4f, 7f, 16f, 13f); line(4f, 11f, 20f, 11f); line(9f, 3.5f, 4f, 7f); line(15f, 3.5f, 20f, 7f); line(9f, 3.5f, 15f, 3.5f) }
        }
    }
}
