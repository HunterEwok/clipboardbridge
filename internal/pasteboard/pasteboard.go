// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package pasteboard reads and writes the macOS pasteboard and the Windows
// clipboard for the agent. The Windows side is described in
// pasteboard_windows.go; the rest of this comment is about the Mac.
//
// The agent checks the change counter twice a second and reads an item only
// after it changed. Items that a password manager marked, with the
// nspasteboard.org types, are reported as secret: the agent hands their text
// only to the local service, which keeps a keyed hash of it so a clipboard
// manager that restores it without the mark makes no event, and never sends
// it. Items that came through Universal Clipboard are reported as remote.
// A secret is written for this Mac only, so Universal Clipboard does not
// carry it, and with the concealed marker, so clipboard histories skip it.
package pasteboard

import "errors"

// ErrUnsupported reports a build without the macOS pasteboard or the
// Windows clipboard.
var ErrUnsupported = errors.New("pasteboard: this build has no pasteboard support")

// Item is what the pasteboard holds.
type Item struct {
	Text   string
	Secret bool  // a password manager marked it
	Remote bool  // it came through Universal Clipboard; never on Windows
	Change int64 // the change counter when it was read
}
