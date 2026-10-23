// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build unix

package testnet

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// pair returns a Unix socket pair, which needs no port.
func pair() (net.Conn, net.Conn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	conn := func(fd int) (net.Conn, error) {
		f := os.NewFile(uintptr(fd), "socketpair")
		defer f.Close()
		return net.FileConn(f)
	}
	a, err := conn(fds[0])
	if err != nil {
		unix.Close(fds[1])
		return nil, nil, err
	}
	b, err := conn(fds[1])
	if err != nil {
		a.Close()
		return nil, nil, err
	}
	return a, b, nil
}
