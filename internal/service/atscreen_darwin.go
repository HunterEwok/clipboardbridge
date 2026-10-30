// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os"
	"syscall"
)

// atScreen allows the user who owns /dev/console, the one signed in at the
// screen. Another user's tmux, as one over SSH, is unchecked.
func atScreen(p peer, target string) verdict {
	if fi, err := os.Stat("/dev/console"); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid == p.uid {
			return allowed
		}
	}
	if target == targetTmux {
		return unchecked
	}
	return refused
}
