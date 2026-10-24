// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os"
	"path/filepath"
	"strings"
)

// hasBattery reports whether the machine runs on a battery of its own: a
// power supply of type Battery that is not a device's, such as a mouse's.
func hasBattery() bool {
	dirs, _ := filepath.Glob("/sys/class/power_supply/*")
	for _, d := range dirs {
		typ, _ := os.ReadFile(filepath.Join(d, "type"))
		scope, _ := os.ReadFile(filepath.Join(d, "scope"))
		if strings.TrimSpace(string(typ)) == "Battery" && strings.TrimSpace(string(scope)) != "Device" {
			return true
		}
	}
	return false
}
