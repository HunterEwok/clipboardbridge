// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"log"
	"strings"
)

// translations returns the window's and the tray's texts in a language,
// keyed by their English: frontend/l10n/<language>.json, which the window
// reads too. English needs none.
func translations(lang string) map[string]string {
	tr := map[string]string{}
	if lang == "en" {
		return tr
	}
	data, err := assets.ReadFile("frontend/l10n/" + lang + ".json")
	if err != nil {
		return tr
	}
	if err := json.Unmarshal(data, &tr); err != nil {
		log.Printf("l10n %s: %v", lang, err)
	}
	return tr
}

// pickLanguage takes the first of the user's languages that the app
// speaks, as "ru" from "ru_RU.UTF-8" or "ru-RU"; English otherwise.
func pickLanguage(prefs []string) string {
	for _, p := range prefs {
		p = strings.ToLower(p)
		if p == "" || p == "c" || p == "posix" {
			continue
		}
		if strings.HasPrefix(p, "ru") {
			return "ru"
		}
		if strings.HasPrefix(p, "en") {
			return "en"
		}
	}
	return "en"
}
