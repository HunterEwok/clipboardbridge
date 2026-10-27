// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package desktop

// pasteKeys returns the way to press a paste's keys where the session
// offers no protocol for it. On Linux that is the uinput helper or the
// RemoteDesktop portal (paste_linux.go); FreeBSD has neither, so remote
// paste works where X11's XTEST or Wayland's virtual keyboard does.
func pasteKeys(func(string, ...any)) keyboard { return nil }

func closeKeys(keyboard) {}
