// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"errors"

	"golang.org/x/sys/windows"
)

// icmpReport tells whether a receive error only reports an ICMP message
// for a packet sent earlier: port unreachable, or time to live exceeded.
func icmpReport(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAENETRESET)
}
