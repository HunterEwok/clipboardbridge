// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT

package ipc

// Made up sentinel error codes for {js,wasip1}/wasm.
const (
	IpcErrorIO        = 1
	IpcErrorInvalid   = 2
	IpcErrorPortInUse = 3
	IpcErrorUnknown   = 4
	IpcErrorProtocol  = 5
)
