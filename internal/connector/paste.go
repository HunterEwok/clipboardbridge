// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package connector

import "time"

// RestoreAfter is how long the program with the focus has to read a pasted
// text before the clipboard gets its text back.
const RestoreAfter = 500 * time.Millisecond

// A PasteBoard is the clipboard a paste goes through.
type PasteBoard interface {
	Current() (Item, bool, error)
	Write(text string, secret bool) error
	ClearIfUnchanged() error
	// Holds reports whether the clipboard still holds text from the
	// board's own write.
	Holds(text string) bool
}

// PasteThrough puts text into the clipboard, lets press press the paste
// keys, and gives the clipboard back what it held, after RestoreAfter,
// unless the user copied meanwhile. A secret leaves no copy behind.
func PasteThrough(b PasteBoard, text string, secret bool, press func() error) error {
	prev, had, _ := b.Current()
	if err := b.Write(text, secret); err != nil {
		return err
	}
	err := press()
	time.Sleep(RestoreAfter)
	switch {
	case !b.Holds(text): // the user copied meanwhile
	case had:
		if werr := b.Write(prev.Text, prev.Secret); werr != nil && err == nil {
			err = werr
		}
	default:
		if cerr := b.ClearIfUnchanged(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
