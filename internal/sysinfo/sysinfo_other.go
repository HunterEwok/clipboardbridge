// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux && !darwin && !windows

package sysinfo

func form() string      { return "" }
func osVersion() string { return "" }
