// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package tunnel

// icmpReport tells whether a receive error only reports an ICMP message for
// a packet sent earlier; unconnected UDP sockets report none outside
// Windows.
func icmpReport(error) bool { return false }
