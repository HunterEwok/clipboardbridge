// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import "golang.org/x/sys/windows"

const needRootText = "on this computer the system limits what the service may reach, and only an administrator can change that: run the command again in a terminal opened as administrator"

// allowHint is the command that lets the service reach the group's servers.
const allowHint = "run cbb global allow in a terminal opened as administrator"

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
