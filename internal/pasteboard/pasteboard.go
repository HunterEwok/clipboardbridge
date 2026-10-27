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
//
// Formatted text (public.html) is read and written next to the text, as
// browsers copy it, but never with a secret.
//
// An image is read when the pasteboard holds no text: its PNG, else its
// JPEG, else its TIFF as a PNG; one is written as itself and as a TIFF,
// for the programs that take only that. A copy of files in the Finder is
// read as their paths, before its text (their names) and their icons;
// files are written as file URLs, as the Finder copies them.
package pasteboard

import "errors"

// ErrUnsupported reports a build without the macOS pasteboard or the
// Windows clipboard.
var ErrUnsupported = errors.New("pasteboard: this build has no pasteboard support")

// Item is what the pasteboard holds: files, a text, or an image without
// one.
type Item struct {
	Text   string
	Secret bool  // a password manager marked it
	Remote bool  // it came through Universal Clipboard; never on Windows
	Change int64 // the change counter when it was read
	// ImageType is clip.TypePNG or clip.TypeJPEG for an image, whose
	// bytes are in Image.
	ImageType string
	Image     []byte
	// Files are the paths of copied files, as Finder or Explorer copies
	// them.
	Files []string
	// HTML is the formatted text next to Text, as a browser copies it.
	HTML string
}
