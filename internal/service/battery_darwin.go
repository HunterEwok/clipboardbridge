// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os/exec"
	"strings"
)

// hasBattery reports whether the Mac has an internal battery, as pmset
// lists it.
func hasBattery() bool {
	out, err := exec.Command("/usr/bin/pmset", "-g", "batt").Output()
	return err == nil && strings.Contains(string(out), "InternalBattery")
}
