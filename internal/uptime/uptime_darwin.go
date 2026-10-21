// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package uptime

import "golang.org/x/sys/unix"

// On macOS, CLOCK_MONOTONIC keeps counting while the system sleeps
// (CLOCK_UPTIME_RAW is the one that stops).
const clockID = unix.CLOCK_MONOTONIC
