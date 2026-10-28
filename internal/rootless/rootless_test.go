// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package rootless

import (
	"path/filepath"
	"testing"
)

func TestDirs(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "relative")
	t.Setenv("XDG_DATA_HOME", "/data")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	for got, want := range map[string]string{
		StateDir():  "/home/u/.local/state/clipboardbridge",
		UpdateDir(): "/home/u/.local/state/clipboardbridge-update",
		ConfigDir(): "/home/u/.config/clipboardbridge",
		ShareDir():  "/data/clipboardbridge",
		UnitDir():   "/home/u/.config/systemd/user",
		Socket():    "/run/user/1000/clipboardbridge/control.sock",
	} {
		if got != filepath.Clean(want) {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}
