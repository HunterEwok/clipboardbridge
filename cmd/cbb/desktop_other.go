// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

func runDesktop(_ context.Context, _ func(string, ...any), stderr io.Writer) int {
	return fail(stderr, errors.New("the desktop connector is for Linux; on a Mac and on Windows the agent links the clipboard"))
}
