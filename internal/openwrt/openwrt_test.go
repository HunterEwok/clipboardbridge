// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package openwrt

import (
	"os"
	"runtime"
	"testing"
)

func TestIs(t *testing.T) {
	_, err := os.Stat(release)
	if want := runtime.GOOS == "linux" && err == nil; Is() != want {
		t.Errorf("Is() = %v with %s present: %v", Is(), release, err == nil)
	}
}
