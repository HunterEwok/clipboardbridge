// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package winpaste is the remote paste target on Windows (design.md,
// "Remote paste"): the clipboard agent in the user's session pastes
// through the clipboard and Ctrl+V, or types with SendInput's Unicode
// keys, which no keyboard layout changes.
//
// It refuses on the secure desktop (UAC, the lock screen), which a
// process in the session cannot reach, and when the window with the focus
// runs at a higher integrity level than the agent, such as an elevated
// program: Windows drops input into it without an error (UIPI).
//
// This file builds the key events, which are the same on every system,
// so that their tests run everywhere.
package winpaste

import "unicode/utf16"

// Virtual keys and flags from WinUser.h.
const (
	vkTab     = 0x09
	vkReturn  = 0x0d
	vkControl = 0x11
	vkV       = 0x56

	keyUp   = 0x0002 // KEYEVENTF_KEYUP
	unicode = 0x0004 // KEYEVENTF_UNICODE
)

// key is one keyboard event of SendInput: a virtual key, or with the
// unicode flag a UTF-16 unit in scan.
type key struct {
	vk    uint16
	scan  uint16
	flags uint32
}

func press(vk uint16) []key { return []key{{vk: vk}, {vk: vk, flags: keyUp}} }

// pasteKeys is Ctrl+V.
func pasteKeys() []key {
	return []key{{vk: vkControl}, {vk: vkV}, {vk: vkV, flags: keyUp}, {vk: vkControl, flags: keyUp}}
}

// enterKeys is Enter.
func enterKeys() []key { return press(vkReturn) }

// typeKeys types text: Enter for a line break, Tab for a tab, and each
// other UTF-16 unit as a Unicode key, a surrogate pair as two.
func typeKeys(text string) []key {
	var ks []key
	for _, r := range text {
		switch r {
		case '\n':
			ks = append(ks, press(vkReturn)...)
			continue
		case '\t':
			ks = append(ks, press(vkTab)...)
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			ks = append(ks, key{scan: u, flags: unicode}, key{scan: u, flags: unicode | keyUp})
		}
	}
	return ks
}
