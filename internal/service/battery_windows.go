// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"syscall"
	"unsafe"
)

var getSystemPowerStatus = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemPowerStatus")

// systemPowerStatus is Win32's SYSTEM_POWER_STATUS.
type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

// hasBattery reports whether the PC has a system battery: BatteryFlag 128
// means none, 255 that Windows does not know.
func hasBattery() bool {
	var st systemPowerStatus
	if r, _, _ := getSystemPowerStatus.Call(uintptr(unsafe.Pointer(&st))); r == 0 {
		return false
	}
	return st.BatteryFlag != 128 && st.BatteryFlag != 255
}
