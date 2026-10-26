// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/HunterEwok/clipboardbridge/internal/connector"
	"github.com/HunterEwok/clipboardbridge/internal/consolepaste"
	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// runConsoleHelper is the helper for the text console, run by the
// clipboardbridge-console unit as root; it logs to the journal.
func runConsoleHelper(ctx context.Context, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		return fail(stderr, errors.New("the console helper runs as root, from the clipboardbridge-console unit"))
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	logf("cbb: pasting into the active text console")
	if err := connector.Run(ctx, connector.Config{Socket: control.SocketPath(), Target: &consolepaste.Console{}, Logf: logf}); err != nil {
		return fail(stderr, err)
	}
	return 0
}
