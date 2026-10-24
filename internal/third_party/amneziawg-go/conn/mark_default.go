// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build !linux && !openbsd && !freebsd

package conn

func (s *StdNetBind) SetMark(mark uint32) error {
	return nil
}
