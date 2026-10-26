// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package winpaste

import (
	"slices"
	"testing"
)

func TestTypeKeys(t *testing.T) {
	got := typeKeys("a\u0416\t\U0001F600\n")
	want := []key{
		{scan: 'a', flags: unicode}, {scan: 'a', flags: unicode | keyUp},
		{scan: 0x416, flags: unicode}, {scan: 0x416, flags: unicode | keyUp},
		{vk: vkTab}, {vk: vkTab, flags: keyUp},
		// U+1F600 is the surrogate pair D83D DE00, each unit pressed alone.
		{scan: 0xd83d, flags: unicode}, {scan: 0xd83d, flags: unicode | keyUp},
		{scan: 0xde00, flags: unicode}, {scan: 0xde00, flags: unicode | keyUp},
		{vk: vkReturn}, {vk: vkReturn, flags: keyUp},
	}
	if !slices.Equal(got, want) {
		t.Errorf("typeKeys = %+v\nwant %+v", got, want)
	}
}

func TestPasteKeys(t *testing.T) {
	want := []key{{vk: vkControl}, {vk: vkV}, {vk: vkV, flags: keyUp}, {vk: vkControl, flags: keyUp}}
	if got := pasteKeys(); !slices.Equal(got, want) {
		t.Errorf("pasteKeys = %+v", got)
	}
	if got := enterKeys(); !slices.Equal(got, []key{{vk: vkReturn}, {vk: vkReturn, flags: keyUp}}) {
		t.Errorf("enterKeys = %+v", got)
	}
}
