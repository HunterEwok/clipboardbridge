// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"regexp"
	"slices"
)

// Forms of devices, for their icons (docs/protocol.md, section 4, "Device").
var Forms = []string{"laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other"}

// DeviceInfo is what a member's hello says about its device, for the
// others to show: its form, its system's version, its own version and its
// network card's MAC address. Shown, never trusted; any field may be empty.
type DeviceInfo struct {
	Form      string `json:"form,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
	Version   string `json:"version,omitempty"`
	MAC       string `json:"mac,omitempty"`
}

var macPattern = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// Clean drops the fields that are not valid: an unknown form, a version of
// more than 32 bytes or with control characters, a MAC address other than
// six lowercase hex bytes with colons.
func (d DeviceInfo) Clean() DeviceInfo {
	if !slices.Contains(Forms, d.Form) {
		d.Form = ""
	}
	short := func(s string) string {
		if len(s) > 32 || !ValidName(s) {
			return ""
		}
		return s
	}
	d.OSVersion, d.Version = short(d.OSVersion), short(d.Version)
	if !macPattern.MatchString(d.MAC) {
		d.MAC = ""
	}
	return d
}

// IsZero reports whether it says nothing.
func (d DeviceInfo) IsZero() bool { return d == DeviceInfo{} }
