// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package actions

import (
	"context"
	"fmt"
	"runtime"
)

// System returns the runner of this system. The Mac and Windows run the
// presets from the app and the agent, which come next; until then they
// refuse every preset but restart.
func System() Runner { return unsupported{} }

type unsupported struct{}

func (unsupported) Run(_ context.Context, name string) error {
	return &Refusal{Reason: fmt.Sprintf("this version of Clipboard Bridge runs %s on Linux only, not on %s", name, runtime.GOOS)}
}

// Rights lists what the presets in on need on this system: nothing here
// yet.
func Rights(on []string) []string { return nil }

// Grant gives the service the rights the presets in on need: nothing here
// yet.
func Grant(on []string) (string, error) { return "", nil }
