// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package uptime

import "golang.org/x/sys/unix"

// CLOCK_BOOTTIME is CLOCK_MONOTONIC plus the time spent in suspend.
const clockID = unix.CLOCK_BOOTTIME
