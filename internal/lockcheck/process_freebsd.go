// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package lockcheck

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// processes lists the running processes from ps, since FreeBSD mounts no
// /proc by default.
func processes() []process {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// One -o each: FreeBSD's ps takes everything after "=" as the header,
	// commas too, so "uid=,comm=" would print the user alone.
	out, err := exec.CommandContext(ctx, "ps", "-ax", "-o", "uid=", "-o", "comm=").Output()
	if err != nil {
		return nil
	}
	var ps []process
	for _, l := range strings.Split(string(out), "\n") {
		uid, name, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok {
			continue
		}
		u, err := strconv.ParseUint(uid, 10, 32)
		if err != nil {
			continue
		}
		ps = append(ps, process{name: strings.TrimSpace(name), uid: uint32(u)})
	}
	return ps
}
