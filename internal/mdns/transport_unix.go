// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build unix

package mdns

import "golang.org/x/sys/unix"

// controlMessages tells that the system reports the interface of each
// packet, and takes the interface to send on with each packet.
const controlMessages = true

// reuse lets the socket share port 5353 with the other responders.
func reuse(fd uintptr) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
