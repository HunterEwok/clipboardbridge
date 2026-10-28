// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package rootless tells whether this program is a rootless install on
// Linux (docs/design.md, "Rootless installs", D-79): the service runs as
// the user's own systemd user unit, with its files in the user's home, so
// every program of the user can read its keys. Such a device is never the
// group's root, an admin or a hub.
package rootless

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
)

// Env is set to 1 by the user units of a rootless install.
const Env = "CBB_ROOTLESS"

// Bin is where packaging/linux/install.sh --rootless puts the program,
// under the user's home.
const Bin = ".local/bin/cbb"

var is = sync.OnceValue(func() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if v, ok := os.LookupEnv(Env); ok {
		return v == "1"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return exe == filepath.Join(home, Bin)
})

// Is reports whether this program is a rootless install: CBB_ROOTLESS=1,
// or else the program is the one install.sh --rootless put in
// ~/.local/bin, so that the user's own commands find the user's service.
func Is() bool { return is() }

// dir returns the XDG directory of env, or home/fallback.
func dir(env, fallback string) string {
	if d := os.Getenv(env); filepath.IsAbs(d) {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/"
	}
	return filepath.Join(home, fallback)
}

// StateDir is the service's state: ~/.local/state/clipboardbridge, which
// install.sh --rootless makes.
func StateDir() string {
	return filepath.Join(dir("XDG_STATE_HOME", ".local/state"), "clipboardbridge")
}

// UpdateDir is cbb update's folder: ~/.local/state/clipboardbridge-update.
func UpdateDir() string {
	return filepath.Join(dir("XDG_STATE_HOME", ".local/state"), "clipboardbridge-update")
}

// ConfigDir holds the installer's settings, clipboardbridge.env:
// ~/.config/clipboardbridge.
func ConfigDir() string { return filepath.Join(dir("XDG_CONFIG_HOME", ".config"), "clipboardbridge") }

// ShareDir holds the installer's own files: ~/.local/share/clipboardbridge.
func ShareDir() string { return filepath.Join(dir("XDG_DATA_HOME", ".local/share"), "clipboardbridge") }

// UnitDir is where the user units go: ~/.config/systemd/user.
func UnitDir() string { return filepath.Join(dir("XDG_CONFIG_HOME", ".config"), "systemd", "user") }

// Socket is the control socket, in the user's runtime directory, where the
// user unit's RuntimeDirectory= puts it.
func Socket() string {
	run := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(run) {
		run = filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
	}
	return filepath.Join(run, "clipboardbridge", "control.sock")
}
