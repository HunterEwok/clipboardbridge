// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
import java.util.Locale

/**
 * The language the user picks on the Start screen or in Settings; System
 * follows the system's.
 */
enum class LanguageChoice(val key: String) {
    SYSTEM("system"),
    EN("en"),
    RU("ru"),
    ;

    /** The locale the app shows, null for the system's. */
    val locale: Locale? get() = if (this == SYSTEM) null else Locale.forLanguageTag(key)

    /**
     * The language by its own name ("English", "Russian" in Russian), so
     * that it can be found whichever language the app shows now; null for
     * System, whose title is a string resource.
     */
    val ownName: String?
        get() {
            val l = locale ?: return null
            return l.getDisplayLanguage(l).replaceFirstChar { it.titlecase(l) }
        }

    companion object {
        fun of(key: String?): LanguageChoice = entries.firstOrNull { it.key == key } ?: SYSTEM

        /** The languages the app is translated into, without System. */
        val translations = entries.filter { it != SYSTEM }

        /**
         * Whether the Start screen offers the language: only when the app
         * has no translation for the system's language, so it shows English.
         */
        fun offeredOnStart(system: Locale): Boolean = translations.none { it.key == system.language }
    }
}

/** What the app remembers between runs, besides the group. */
class Settings(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    var theme: ThemeChoice
        get() = ThemeChoice.of(prefs.getString("theme", null))
        set(v) = prefs.edit().putString("theme", v.key).apply()

    var language: LanguageChoice
        get() = LanguageChoice.of(prefs.getString("language", null))
        set(v) = prefs.edit().putString("language", v.key).apply()

    /**
     * Whether Share and the selection menu send without asking first: the
     * user answered "Always allow" once. Android does not tell reliably
     * which app shared, so it holds for every app; Settings turns it off.
     */
    var alwaysAllowShare: Boolean
        get() = prefs.getBoolean("alwaysAllowShare", false)
        set(v) = prefs.edit().putBoolean("alwaysAllowShare", v).apply()

    /** Whether the note that this phone is ready was closed. */
    var welcomed: Boolean
        get() = prefs.getBoolean("welcomed", false)
        set(v) = prefs.edit().putBoolean("welcomed", v).apply()

    /**
     * Whether a message names the error underneath, to find out what
     * failed: on in debug builds, off in release ones, and either way what
     * the launch extra ShowErrorDetails set last
     * (adb shell am start -n io.github.hunterewok.clipboardbridge/.MainActivity --ez ShowErrorDetails true).
     */
    var showsErrorDetails: Boolean
        get() = if (prefs.contains(ERROR_DETAILS)) prefs.getBoolean(ERROR_DETAILS, false) else debuggable
        set(v) = prefs.edit().putBoolean(ERROR_DETAILS, v).apply()

    companion object {
        const val ERROR_DETAILS = "ShowErrorDetails"

        /** context showing the chosen language, for the activity's base context. */
        fun localized(context: Context): Context {
            val locale = Settings(context).language.locale ?: return context
            val config = Configuration(context.resources.configuration)
            config.setLocale(locale)
            return context.createConfigurationContext(config)
        }
    }
}
