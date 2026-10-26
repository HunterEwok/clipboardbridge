// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// sessionLocked reports whether logind marks this graphical session locked,
// as GNOME, KDE and most lock screens tell it. Without logind or a session
// ID it reports false: the board's own checks remain.
func sessionLocked() bool {
	id := os.Getenv("XDG_SESSION_ID")
	if id == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "loginctl", "show-session", id, "-p", "LockedHint", "--value").Output()
	return err == nil && strings.TrimSpace(string(out)) == "yes"
}
