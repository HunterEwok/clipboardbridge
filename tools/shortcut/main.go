// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command shortcut writes the iPhone shortcut, unsigned, to
// internal/phone/shortcut/clipbridge.plist. Sign it on a Mac into
// clipbridge.shortcut next to it:
//
//	go run ./tools/shortcut
//	shortcuts sign --mode anyone --input internal/phone/shortcut/clipbridge.plist \
//		--output internal/phone/shortcut/clipbridge.shortcut
package main

import (
	"fmt"
	"os"

	"github.com/HunterEwok/clipbridge/internal/phone"
)

func main() {
	const path = "internal/phone/shortcut/clipbridge.plist"
	if err := os.WriteFile(path, phone.UnsignedShortcut(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "shortcut:", err)
		os.Exit(1)
	}
	fmt.Println("wrote", path)
}
