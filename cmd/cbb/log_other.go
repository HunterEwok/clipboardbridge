// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows && !darwin

package main

import "io"

// serviceLog returns where the service logs: systemd's journal, the rc
// script's file or procd keep its standard error.
func serviceLog(stderr io.Writer) (io.Writer, func()) { return stderr, func() {} }

// agentLog returns where the agent logs: its standard error, which the
// user's systemd keeps.
func agentLog(stderr io.Writer) (io.Writer, func(), error) { return stderr, func() {}, nil }
