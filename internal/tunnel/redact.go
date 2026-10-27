// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// A run of characters that can make up an IP address, with its port and
// brackets, and a WireGuard peer as wireguard-go prints it.
var (
	addrLike = regexp.MustCompile(`[0-9A-Fa-f:.\[\]%]{3,}`)
	peerLike = regexp.MustCompile(`peer\([^)]*\)`)
)

// Redacted returns a logf that passes each line on to logf without the IP
// addresses and WireGuard peers in it. The servers use it: their own lines
// name no device or address, but an error from the network or from
// wireguard-go can.
func Redacted(logf func(string, ...any)) func(string, ...any) {
	return func(format string, args ...any) {
		logf("%s", Redact(fmt.Sprintf(format, args...)))
	}
}

// Redact replaces the IP addresses, with or without a port, in s by
// "(address)", and the WireGuard peers by "peer".
func Redact(s string) string {
	s = peerLike.ReplaceAllString(s, "peer")
	return addrLike.ReplaceAllStringFunc(s, func(m string) string {
		// A sentence's full stop or colon after an address is kept.
		t := strings.TrimRight(m, ".:")
		if isAddr(t) {
			return "(address)" + m[len(t):]
		}
		return m
	})
}

func isAddr(s string) bool {
	if _, err := netip.ParseAddrPort(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"))
	return err == nil
}
