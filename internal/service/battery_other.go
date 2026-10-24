// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux && !darwin && !windows

package service

// hasBattery guesses no battery where the service cannot tell.
func hasBattery() bool { return false }
