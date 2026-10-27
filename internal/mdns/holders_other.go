// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !freebsd

package mdns

// holders names the programs that keep the responder off port 5353 where
// the system does not let it share; elsewhere it shares with any.
func holders() string { return "" }
