// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sysinfo

import (
	"strings"

	"golang.org/x/sys/unix"
)

func form() string {
	model, err := unix.Sysctl("hw.model")
	if err != nil {
		return ""
	}
	if strings.HasPrefix(model, "MacBook") {
		return "laptop"
	}
	return "desktop"
}

func osVersion() string {
	v, _ := unix.Sysctl("kern.osproductversion")
	return v
}
