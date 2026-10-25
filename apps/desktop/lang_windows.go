// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import "golang.org/x/sys/windows"

// language is the user's display language.
func language() string {
	prefs, _ := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	return pickLanguage(prefs)
}
