// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux || openbsd || freebsd

package conn

import (
	"encoding/binary"
	"runtime"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

func (s *StdNetBind) SetMark(mark uint32) error {
	var operr error
	if fwmarkIoctl == 0 {
		return nil
	}
	if s.ipv4 != nil {
		fd, err := s.ipv4.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = setsockoptUint32(int(fd), unix.SOL_SOCKET, fwmarkIoctl, mark)
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	if s.ipv6 != nil {
		fd, err := s.ipv6.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = setsockoptUint32(int(fd), unix.SOL_SOCKET, fwmarkIoctl, mark)
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// setsockoptUint32 sets a socket option that the kernel reads as a 32-bit
// value. It passes the mark's four bytes as they are, where SetsockoptInt
// would need a conversion to int that can wrap on 32-bit systems.
func setsockoptUint32(fd, level, opt int, value uint32) error {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], value)
	return unix.SetsockoptString(fd, level, opt, string(b[:]))
}
