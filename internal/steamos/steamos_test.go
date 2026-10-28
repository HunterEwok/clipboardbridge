// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package steamos

import (
	"os"
	"testing"
)

func TestIs(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if want := exe == Bin; Is() != want {
		t.Errorf("Is() = %v for %s", Is(), exe)
	}
}
