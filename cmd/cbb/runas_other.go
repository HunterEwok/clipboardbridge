// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !unix

package main

import "errors"

// runAs is for Unix's rc scripts; the Windows service has its account.
func runAs(string, func(string, ...any)) error { return errors.New("-user is for Unix") }
