// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// runService runs the service until a signal stops it; systemd and launchd
// keep its output.
func runService(stderr io.Writer, run func(context.Context, func(string, ...any)) error) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	if err := run(ctx, logf); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// agentLog returns where the agent logs: launchd keeps its output.
func agentLog(stderr io.Writer) (io.Writer, func(), error) { return stderr, func() {}, nil }

// firstAgent reports that no other agent runs; launchd starts only one.
func firstAgent() bool { return true }

func defaultStateDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" { // set by systemd
		return d
	}
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/clipboardbridge/state"
	}
	return "/var/lib/clipboardbridge"
}
