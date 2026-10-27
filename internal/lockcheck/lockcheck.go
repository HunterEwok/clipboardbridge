// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

// Package lockcheck tells a remote paste target whether a session is
// locked (design.md, "The lock check"): synthetic keys do not stop at a
// lock screen, so a target asks right before it presses them.
package lockcheck

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// lockers are screen and console lockers that run only while they lock,
// for those that do not tell logind: swaylock and its kin, vlock.
var lockers = []string{"swaylock", "hyprlock", "waylock", "gtklock", "i3lock", "slock", "xsecurelock", "physlock", "vlock",
	// KDE's lock screen tells logind on Linux; on FreeBSD its greeter
	// running is the only sign.
	"kscreenlocker_greet"}

// Reason says why the graphical session of this process takes no keys
// now, or "" if it does: logind marks it locked, as GNOME, KDE and most
// lock screens tell it, or a locker runs as this user.
func Reason() string {
	if Locked(os.Getenv("XDG_SESSION_ID")) {
		return "the session is locked"
	}
	if name := Locker(false); name != "" {
		return "the screen is locked (" + name + " runs)"
	}
	// GNOME's lock screen is part of gnome-shell, so without logind (as on
	// FreeBSD) nothing tells whether it is up.
	if _, err := exec.LookPath("loginctl"); err != nil && strings.Contains(os.Getenv("XDG_CURRENT_DESKTOP"), "GNOME") {
		return "without logind GNOME does not tell whether the screen is locked"
	}
	return ""
}

// Locked reports whether logind marks the session id locked; false
// without logind or an id.
func Locked(id string) bool {
	if id == "" {
		return false
	}
	return Show(id, "LockedHint")["LockedHint"] == "yes"
}

// Show returns logind's properties of the session id, empty when logind
// does not answer.
func Show(id string, props ...string) map[string]string {
	args := []string{"show-session", id}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	out, err := loginctl(args...)
	m := map[string]string{}
	if err != nil {
		return m
	}
	for line := range strings.Lines(out) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// ActiveSession returns the ID of the session active on seat, or "".
func ActiveSession(seat string) string {
	out, err := loginctl("show-seat", seat, "-p", "ActiveSession", "--value")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// Sessions returns the IDs of logind's sessions.
func Sessions() ([]string, error) {
	out, err := loginctl("list-sessions", "--no-legend")
	if err != nil {
		return nil, err
	}
	var ids []string
	for line := range strings.Lines(out) {
		if f := strings.Fields(line); len(f) > 0 {
			ids = append(ids, f[0])
		}
	}
	return ids, nil
}

func loginctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "loginctl", args...).Output()
	return string(out), err
}

// Locker returns the name of a locker that runs, as this user or, with
// anyUser, as anyone, or "".
func Locker(anyUser bool) string {
	uid := uint32(os.Getuid())
	for _, p := range processes() {
		if slices.Contains(lockers, p.name) && (anyUser || p.uid == uid) {
			return p.name
		}
	}
	return ""
}

// A process is the command name and user of a running process.
type process struct {
	name string
	uid  uint32
}
