// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package openwrt tells whether this system is OpenWrt, whose layout
// differs from other Linux systems: the runtime directory is /var/run (in
// RAM, as /var is), the state lives under /etc, which sysupgrade keeps,
// and packages install to /usr rather than /usr/local.
package openwrt

import (
	"os"
	"runtime"
	"sync"
)

// release is the file every OpenWrt system has.
var release = "/etc/openwrt_release"

var is = sync.OnceValue(func() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := os.Stat(release)
	return err == nil
})

// Is reports whether this system is OpenWrt.
func Is() bool { return is() }
