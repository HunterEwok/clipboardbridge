// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build !linux
// +build !linux

package conn

import "net"

func supportsUDPOffload(_ *net.UDPConn) (txOffload, rxOffload bool) {
	return
}
