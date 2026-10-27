// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package lockcheck

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// processes lists the running processes from /proc.
func processes() []process {
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	var ps []process
	for _, d := range dirs {
		comm, err := os.ReadFile(filepath.Join(d, "comm"))
		if err != nil {
			continue
		}
		var st syscall.Stat_t
		if syscall.Stat(d, &st) != nil {
			continue
		}
		ps = append(ps, process{name: strings.TrimSpace(string(comm)), uid: st.Uid})
	}
	return ps
}
