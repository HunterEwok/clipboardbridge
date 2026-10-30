// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package service

import (
	"strconv"

	"github.com/HunterEwok/clipboardbridge/internal/lockcheck"
)

// atScreen asks logind: the desktop and the actions go to the user of an
// active session, tmux to a user with a session, as one over SSH. Without
// logind nothing tells who is at the screen.
func atScreen(p peer, target string) verdict {
	ids, err := lockcheck.Sessions()
	if err != nil {
		return unchecked
	}
	uid := strconv.FormatUint(uint64(p.uid), 10)
	for _, id := range ids {
		m := lockcheck.Show(id, "User", "State")
		if m["User"] != uid {
			continue
		}
		if m["State"] == "active" || target == targetTmux && m["State"] == "online" {
			return allowed
		}
	}
	return refused
}
