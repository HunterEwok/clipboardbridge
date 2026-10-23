// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/connector"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/desktop"
)

func runDesktop(ctx context.Context, logf func(string, ...any), stderr io.Writer) int {
	backoff := time.Second
	failures := 0
	for ctx.Err() == nil {
		b, how, err := desktop.Open(logf)
		if err != nil {
			// The session is gone, or not there yet: try a few times, then
			// give up, so a connector does not outlive its session.
			if failures++; failures > 10 {
				return fail(stderr, err)
			}
		} else {
			failures, backoff = 0, time.Second
			logf("cbb: linked the clipboard through %s", how)
			err = connector.Run(ctx, connector.Config{Socket: control.SocketPath(), Board: b, Logf: logf})
			b.Close()
			if err == nil || !errors.Is(err, connector.ErrBoardGone) {
				return 0
			}
			logf("cbb: %v; opening the display again", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
	return 0
}
