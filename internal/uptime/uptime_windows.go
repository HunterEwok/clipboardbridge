// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package uptime

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The interrupt time counts from boot in units of 100 ns, and includes the
// time asleep.
var queryInterruptTimePrecise = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryInterruptTimePrecise")

func now() time.Duration {
	var t uint64
	queryInterruptTimePrecise.Call(uintptr(unsafe.Pointer(&t)))
	return time.Duration(t) * 100
}
