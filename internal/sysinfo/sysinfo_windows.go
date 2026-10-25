// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sysinfo

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getSystemPowerStatus = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemPowerStatus")

// systemPowerStatus is SYSTEM_POWER_STATUS.
type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

// form takes a computer with a battery for a laptop.
func form() string {
	var s systemPowerStatus
	if r, _, _ := getSystemPowerStatus.Call(uintptr(unsafe.Pointer(&s))); r == 0 {
		return ""
	}
	switch {
	case s.BatteryFlag == 255:
		return ""
	case s.BatteryFlag&128 != 0:
		return "desktop"
	}
	return "laptop"
}

// osVersion names Windows 10 or 11 with its build: Windows 11 still says
// 10.0, from build 22000.
func osVersion() string {
	v := windows.RtlGetVersion()
	if v.MajorVersion == 10 && v.BuildNumber >= 22000 {
		return fmt.Sprintf("11 (build %d)", v.BuildNumber)
	}
	return fmt.Sprintf("%d (build %d)", v.MajorVersion, v.BuildNumber)
}
