// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"net"

	"golang.org/x/sys/unix"
)

// connPeer reads the user of the process at the other end from the kernel.
func connPeer(c net.Conn) peer {
	raw, ok := rawConn(c)
	if !ok {
		return peer{}
	}
	var p peer
	raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			p = peer{known: true, uid: cred.Uid}
		}
	})
	return p
}
