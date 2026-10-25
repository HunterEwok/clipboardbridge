// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux && !darwin && !freebsd && !windows

package netid

// gateways tells nothing here: networks are told apart by their addresses
// only.
func gateways() (map[int]string, error) { return nil, nil }
