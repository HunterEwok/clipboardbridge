// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux && !windows

package main

import (
	"context"
	"errors"
	"io"
)

// runConsoleHelper is the helper for the Linux text console.
func runConsoleHelper(_ context.Context, stderr io.Writer) int {
	return fail(stderr, errors.New("the console helper is for the Linux text console"))
}
