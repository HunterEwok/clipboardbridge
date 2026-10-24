// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build !linux

package conn

func errShouldDisableUDPGSO(_ error) bool {
	return false
}
