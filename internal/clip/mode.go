// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import "fmt"

// Mode is a member's sync mode: what moves between its own clipboard and
// the group (docs/design.md, "Sync modes"). It changes nothing else: the
// member stays connected, keeps the group's current event and forwards
// events in every mode, and deliberate actions (Send) work in every mode.
type Mode uint8

const (
	Shared   Mode = iota // its copies go to the group, and the group's copies reach its clipboard
	Own                  // neither; the group's text is at hand on request (Current)
	Receive              // only the group's copies reach its clipboard
	SendOnly             // only its copies go to the group
)

// Sends reports whether the copies a clipboard watcher reports go to the group.
func (m Mode) Sends() bool { return m == Shared || m == SendOnly }

// Receives reports whether the group's copies are written to the clipboard.
func (m Mode) Receives() bool { return m == Shared || m == Receive }

// String returns the mode's name, as cbb mode takes it.
func (m Mode) String() string {
	switch m {
	case Shared:
		return "shared"
	case Own:
		return "own"
	case Receive:
		return "receive"
	case SendOnly:
		return "send"
	}
	return fmt.Sprintf("mode(%d)", m)
}

// ParseMode reads a mode's name.
func ParseMode(s string) (Mode, error) {
	for m := Shared; m <= SendOnly; m++ {
		if m.String() == s {
			return m, nil
		}
	}
	return Shared, fmt.Errorf("the sync mode is own, shared, receive or send, not %q", s)
}
