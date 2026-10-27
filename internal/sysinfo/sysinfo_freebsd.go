// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sysinfo

import (
	"strings"

	"golang.org/x/sys/unix"
)

// form is a FreeBSD machine's form: a firewall distribution says it is a
// router, and FreeBSD itself does not tell a laptop from a server.
func form() string {
	if isFirewall() {
		return "router"
	}
	return ""
}

// isFirewall reports whether this is OPNsense or pfSense.
func isFirewall() bool {
	for _, f := range []string{"/usr/local/opnsense/version/core", "/etc/platform"} {
		if unix.Access(f, unix.R_OK) == nil {
			return true
		}
	}
	return false
}

// osVersion is the system and its release, such as "FreeBSD 15.1-RELEASE".
func osVersion() string {
	typ, _ := unix.Sysctl("kern.ostype")
	rel, _ := unix.Sysctl("kern.osrelease")
	return strings.TrimSpace(typ + " " + rel)
}
