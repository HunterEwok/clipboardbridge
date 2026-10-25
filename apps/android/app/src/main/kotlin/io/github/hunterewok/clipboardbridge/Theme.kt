// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.os.Build
import androidx.annotation.StringRes
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/** One theme's colours (apps/design/tokens.json; Tokens.kt is generated from it). */
data class Palette(
    val dark: Boolean,
    val background: Color,
    val surface: Color,
    val grid: Color,
    val text: Color,
    val textDim: Color,
    val accent: Color,
    val onAccent: Color,
    val danger: Color,
)

/** One accent colour's palettes for the dark and the light appearance. */
data class PalettePair(val name: String, val dark: Palette, val light: Palette)

/** The colour named [name], or the default, Terminal. */
fun paletteNamed(name: String): PalettePair = Tokens.colors.firstOrNull { it.name == name } ?: Tokens.colors.first()

/**
 * The theme the user picks in Settings; System follows the system's light
 * or dark mode with Terminal and Light, and Material You takes the
 * wallpaper's colours (Android 12 and later; System's before).
 */
enum class ThemeChoice(val key: String, @StringRes val title: Int) {
    SYSTEM("system", R.string.theme_system),
    MATERIAL("material", R.string.theme_material),
    TERMINAL("terminal", R.string.theme_terminal),
    MIDNIGHT("midnight", R.string.theme_midnight),
    AMBER("amber", R.string.theme_amber),
    LIGHT("light", R.string.theme_light),
    ;

    companion object {
        fun of(key: String?): ThemeChoice = entries.firstOrNull { it.key == key } ?: SYSTEM

        /** The choices this phone offers: Material You only where Android has the wallpaper's colours. */
        val offered: List<ThemeChoice> get() = entries.filter { it != MATERIAL || Build.VERSION.SDK_INT >= Build.VERSION_CODES.S }
    }
}

val LocalPalette = staticCompositionLocalOf { Tokens.colors.first().dark }

/** The palette of a Material colour scheme, for Material You. */
private fun ColorScheme.palette(dark: Boolean) = Palette(
    dark = dark,
    background = background,
    surface = surfaceContainer,
    grid = outlineVariant.copy(alpha = 0.35f),
    text = onBackground,
    textDim = onSurfaceVariant,
    accent = primary,
    onAccent = onPrimary,
    danger = error,
)

/** The Material colour scheme of one of the app's palettes, for the platform's controls. */
private fun Palette.scheme(): ColorScheme {
    val base = if (dark) darkColorScheme() else lightColorScheme()
    return base.copy(
        primary = accent,
        onPrimary = onAccent,
        secondary = accent,
        onSecondary = onAccent,
        background = background,
        onBackground = text,
        surface = background,
        onSurface = text,
        surfaceVariant = surface,
        onSurfaceVariant = textDim,
        surfaceContainer = surface,
        surfaceContainerLow = surface,
        surfaceContainerHigh = surface,
        surfaceContainerHighest = surface,
        outline = textDim,
        error = danger,
    )
}

/** Applies the chosen theme to everything inside. */
@Composable
fun AppTheme(choice: ThemeChoice, content: @Composable () -> Unit) {
    val systemDark = isSystemInDarkTheme()
    val context = LocalContext.current
    val (palette, scheme) = when {
        choice == ThemeChoice.MATERIAL && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val s = if (systemDark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
            s.palette(systemDark) to s
        }
        else -> {
            val p = when (choice) {
                ThemeChoice.TERMINAL, ThemeChoice.MIDNIGHT, ThemeChoice.AMBER -> paletteNamed(choice.key).dark
                ThemeChoice.LIGHT -> paletteNamed("terminal").light
                else -> paletteNamed("terminal").let { if (systemDark) it.dark else it.light }
            }
            p to p.scheme()
        }
    }
    CompositionLocalProvider(LocalPalette provides palette) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

/** The deep background with a faint grid, behind content. */
@Composable
fun GridBackground(modifier: Modifier = Modifier, content: @Composable BoxScope.() -> Unit) {
    val palette = LocalPalette.current
    val step = with(LocalDensity.current) { 28.dp.toPx() }
    val line = with(LocalDensity.current) { 0.5.dp.toPx() }
    Box(modifier.fillMaxSize().background(palette.background)) {
        Canvas(Modifier.fillMaxSize()) {
            var x = 0f
            while (x < size.width) {
                drawLine(palette.grid, Offset(x, 0f), Offset(x, size.height), line)
                x += step
            }
            var y = 0f
            while (y < size.height) {
                drawLine(palette.grid, Offset(0f, y), Offset(size.width, y), line)
                y += step
            }
        }
        content()
    }
}

/** The one big button: rounded, generous, the accent colour. */
@Composable
fun AccentButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val palette = LocalPalette.current
    val source = remember { MutableInteractionSource() }
    val pressed by source.collectIsPressedAsState()
    Button(
        onClick = onClick,
        enabled = enabled,
        interactionSource = source,
        shape = RoundedCornerShape(Tokens.radiusButton),
        colors = ButtonDefaults.buttonColors(
            containerColor = palette.accent.copy(alpha = if (pressed) 0.8f else 1f),
            contentColor = palette.onAccent,
            disabledContainerColor = palette.accent.copy(alpha = 0.4f),
            disabledContentColor = palette.onAccent.copy(alpha = 0.5f),
        ),
        modifier = modifier.fillMaxWidth().heightIn(min = 64.dp),
    ) {
        Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
    }
}

/** The quieter button next to the big one: the accent colour on a surface. */
@Composable
fun QuietButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val palette = LocalPalette.current
    OutlinedButton(
        onClick = onClick,
        shape = RoundedCornerShape(Tokens.radiusButton),
        colors = ButtonDefaults.outlinedButtonColors(containerColor = palette.surface.copy(alpha = 0.85f), contentColor = palette.accent),
        border = null,
        contentPadding = PaddingValues(horizontal = Tokens.spacingMedium, vertical = Tokens.spacingSmall),
        modifier = modifier.fillMaxWidth().heightIn(min = 52.dp),
    ) {
        Text(text, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium, textAlign = TextAlign.Center)
    }
}

/** A card on the surface colour. */
@Composable
fun Modifier.card(): Modifier {
    val palette = LocalPalette.current
    return clip(RoundedCornerShape(Tokens.radiusCard)).background(palette.surface.copy(alpha = 0.92f))
}
