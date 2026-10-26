// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package actions

// System returns the runner of this system, or nil where the presets run in
// the signed-in user's session, through the agent (Session): on a Mac and
// on Windows the service's own user has no right to lock, sleep or shut
// down.
func System() Runner { return nil }

// Rights lists what the presets in on need on this system beyond what the
// signed-in user has: nothing here.
func Rights(on []string) []string { return nil }

// Grant gives the service the rights the presets in on need: nothing here.
func Grant(on []string) (string, error) { return "", nil }
