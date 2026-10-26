// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !darwin && !windows

package actions

// Session returns the runner of the presets in the user's session, which
// the agent offers the service, or nil: on Linux the service runs them
// itself, through logind.
func Session() Runner { return nil }
