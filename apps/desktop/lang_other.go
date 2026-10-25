// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

import (
	"os"
	"strings"
)

// language is the user's language, as the locale's variables give it.
func language() string {
	var prefs []string
	for _, v := range []string{"LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"} {
		// LANGUAGE lists languages in order, separated by colons.
		prefs = append(prefs, strings.Split(os.Getenv(v), ":")...)
	}
	return pickLanguage(prefs)
}
