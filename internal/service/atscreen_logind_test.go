// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package service

import "testing"

// A user signed in over SSH alone, or a user's service manager, is not at
// the screen for the desktop and the actions; it is for tmux.
func TestAtScreenIn(t *testing.T) {
	session := func(state, class, typ string) map[string]string {
		return map[string]string{"User": "1003", "State": state, "Class": class, "Type": typ, "Remote": "no", "Seat": "seat0"}
	}
	remote := func(typ, seat string) map[string]string {
		m := session("active", "user", typ)
		m["Remote"], m["Seat"] = "yes", seat
		return m
	}
	unseated := session("active", "user", "wayland")
	unseated["Seat"] = ""
	for _, c := range []struct {
		name          string
		m             map[string]string
		desktop, tmux bool
	}{
		{"a desktop on X11", session("active", "user", "x11"), true, true},
		{"a desktop on Wayland", session("active", "user", "wayland"), true, true},
		{"a desktop in the background", session("online", "user", "wayland"), false, true},
		{"SSH", remote("tty", ""), false, true},
		{"SSH that names a Wayland session", remote("wayland", ""), false, true},
		{"a remote desktop on a seat", remote("x11", "seat0"), true, true},
		{"a local desktop with no seat", unseated, true, true},
		{"a text console", session("active", "user", "tty"), false, true},
		{"the service manager", session("active", "manager", "unspecified"), false, false},
		{"the login screen", session("active", "greeter", "wayland"), false, false},
		{"a session that is closing", session("closing", "user", "x11"), false, false},
		{"another user's desktop", map[string]string{"User": "1000", "State": "active", "Class": "user", "Type": "x11"}, false, false},
	} {
		if got := atScreenIn(c.m, "1003", targetDesktop); got != c.desktop {
			t.Errorf("%s: at the screen for the desktop: %v, want %v", c.name, got, c.desktop)
		}
		if got := atScreenIn(c.m, "1003", targetAct); got != c.desktop {
			t.Errorf("%s: at the screen for the actions: %v, want %v", c.name, got, c.desktop)
		}
		if got := atScreenIn(c.m, "1003", targetTmux); got != c.tmux {
			t.Errorf("%s: at the screen for tmux: %v, want %v", c.name, got, c.tmux)
		}
	}
}
