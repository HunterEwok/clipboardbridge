// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package update

// VerifySigner is for Windows, whose programs carry Authenticode
// signatures; elsewhere release.json is the check.
var VerifySigner func(installed, unpacked []string) error
