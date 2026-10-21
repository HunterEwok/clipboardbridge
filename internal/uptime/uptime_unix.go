// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || darwin

package uptime

import (
	"time"

	"golang.org/x/sys/unix"
)

func now() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(clockID, &ts); err != nil {
		panic("uptime: clock_gettime: " + err.Error()) // cannot fail for a valid clock
	}
	return time.Duration(ts.Nano())
}
