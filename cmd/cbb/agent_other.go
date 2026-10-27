// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux && !freebsd

package main

import (
	"context"
	"io"
)

// runDesktop is the agent on a Linux desktop; cmdAgent calls it only there.
func runDesktop(context.Context, func(string, ...any), io.Writer) int { return 2 }
