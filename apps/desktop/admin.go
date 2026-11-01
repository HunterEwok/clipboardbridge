// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"strings"
)

// What changes the group goes only through the service's admin socket,
// which only the administrator reaches, so the app runs cbb as the
// administrator after the system asks: pkexec on Linux, the UAC prompt on
// Windows (admin_linux.go, admin_windows.go).

// adminRun runs cbb as the administrator; the window's tests put a stand-in
// here.
var adminRun = runAdmin

// errCancelled is a prompt the user closed: nothing changed, and the
// window says nothing.
var errCancelled = errors.New("cancelled")

// An adminError is cbb failing: its last line for the user, all it printed
// underneath.
type adminError struct{ msg, detail string }

func (e *adminError) Error() string { return e.msg }

// cbbFailed makes the error of a cbb run from what it printed.
func cbbFailed(output, fallback string) *adminError {
	out := strings.TrimSpace(strings.ReplaceAll(output, "\r\n", "\n"))
	msg := fallback
	if out != "" {
		lines := strings.Split(out, "\n")
		msg = strings.TrimPrefix(strings.TrimSpace(lines[len(lines)-1]), "cbb: ")
	}
	return &adminError{msg: msg, detail: out}
}
