// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build !windows

package conn

func NewDefaultBind() Bind { return NewStdNetBind() }
