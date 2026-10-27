// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package uptime reads a clock for local durations: it keeps counting while
// the machine sleeps and never jumps when the wall clock is set.
//
// Go's monotonic clock does not count sleep, and the wall clock jumps when it
// is corrected. A copy made before a laptop sleeps must look old when the
// laptop wakes, and a correction of the clock must not make events look older
// or younger than they are.
package uptime

import "time"

// Now returns the time since an arbitrary point, counting sleep: Linux's
// CLOCK_BOOTTIME and macOS's CLOCK_MONOTONIC; FreeBSD's CLOCK_UPTIME at
// least never jumps. Elsewhere it falls back to Go's monotonic clock, which
// does not count sleep.
func Now() time.Duration { return now() }
