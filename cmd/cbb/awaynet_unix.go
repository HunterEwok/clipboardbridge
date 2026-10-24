// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

import "os"

const needRootText = "on this computer the service may reach only the home network, and only root can change that: run the command again with sudo"

func isElevated() bool { return os.Geteuid() == 0 }

// awayOnHint is the command that lifts the limit.
const awayOnHint = "sudo cbb away on"
