// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import "golang.org/x/sys/windows"

const needRootText = "on this computer the service may reach only the home network, and only an administrator can change that: run the command again in a terminal opened as administrator"

// awayOnHint is the command that lifts the limit.
const awayOnHint = "cbb global on, in a terminal opened as administrator,"

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
