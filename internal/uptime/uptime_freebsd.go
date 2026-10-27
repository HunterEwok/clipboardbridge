// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package uptime

import "golang.org/x/sys/unix"

// CLOCK_UPTIME counts from boot and never jumps when the clock is set;
// FreeBSD's CLOCK_BOOTTIME is another name for it. Whether it counts a
// suspend depends on the machine's timecounter, as with Go's own clock.
const clockID = unix.CLOCK_UPTIME
