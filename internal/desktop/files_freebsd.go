// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package desktop

// transfers is the FileTransfer portal for Flatpak apps on Linux
// (files_portal.go). FreeBSD has no Flatpak, so a written list of files
// carries no portal key there.
type transfers struct{ logf func(string, ...any) }

func (t *transfers) start([]string) string { return "" }
func (t *transfers) stop()                 {}
func (t *transfers) close()                {}
