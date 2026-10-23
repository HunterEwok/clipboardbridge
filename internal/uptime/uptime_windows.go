// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package uptime

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The interrupt time counts from boot in units of 100 ns, and includes the
// time asleep. QueryInterruptTimePrecise lives in KernelBase.dll, which
// kernel32.dll does not forward it from; without it, GetTickCount64 counts
// the same time in milliseconds.
var (
	queryInterruptTimePrecise = windows.NewLazySystemDLL("kernelbase.dll").NewProc("QueryInterruptTimePrecise")
	getTickCount64            = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")
)

func now() time.Duration {
	if queryInterruptTimePrecise.Find() != nil {
		ms, _, _ := getTickCount64.Call()
		return time.Duration(ms) * time.Millisecond
	}
	var t uint64
	queryInterruptTimePrecise.Call(uintptr(unsafe.Pointer(&t)))
	return time.Duration(t) * 100
}
