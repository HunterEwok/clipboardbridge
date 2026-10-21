// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command shortcut writes the iPhone shortcuts, unsigned, to
// internal/phone/shortcut/<name>.plist. Sign each on a Mac into
// <name>.shortcut next to it:
//
//	go run ./tools/shortcut
//	for n in clipbridge clipbridge-add; do
//		plutil -convert binary1 -o /tmp/$n.shortcut internal/phone/shortcut/$n.plist
//		shortcuts sign --mode anyone --input /tmp/$n.shortcut --output internal/phone/shortcut/$n.shortcut
//	done
//
// shortcuts sign reads only the binary form.
package main

import (
	"fmt"
	"os"

	"github.com/HunterEwok/clipbridge/internal/phone"
)

func main() {
	for name, plist := range phone.UnsignedShortcuts() {
		path := "internal/phone/shortcut/" + name + ".plist"
		if err := os.WriteFile(path, plist, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "shortcut:", err)
			os.Exit(1)
		}
		fmt.Println("wrote", path)
	}
}
