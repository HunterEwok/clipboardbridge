// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build (!darwin || !cgo) && !windows

package pasteboard

// Supported reports whether this build reaches the pasteboard: a Mac's
// needs cgo.
const Supported = false

// A Board is a pasteboard; this build has none.
type Board struct{}

// General returns the general pasteboard; this build has none.
func General() *Board { return &Board{} }

// Private returns a private pasteboard; this build has none.
func Private(string) *Board { return &Board{} }

// Release does nothing in this build.
func (b *Board) Release() {}

// ChangeCount returns 0 in this build.
func (b *Board) ChangeCount() int64 { return 0 }

// Read fails in this build.
func (b *Board) Read() (Item, bool, error) { return Item{}, false, ErrUnsupported }

// Write fails in this build.
func (b *Board) Write(string, bool) (int64, error) { return 0, ErrUnsupported }

// Clear does nothing in this build.
func (b *Board) Clear() int64 { return 0 }
