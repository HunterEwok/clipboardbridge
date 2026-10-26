// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"io"
)

// cmdPasteHelper runs a paste target without a clipboard; Windows has no
// tmux or text console to paste into.
func cmdPasteHelper(_ []string, stderr io.Writer) int {
	return fail(stderr, errors.New("paste-helper is for tmux and the Linux text console, which Windows does not have"))
}
