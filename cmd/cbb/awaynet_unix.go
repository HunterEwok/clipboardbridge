// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

import "os"

const needRootText = "on this computer the system limits what the service may reach, and only root can change that: run the command again with sudo"

func isElevated() bool { return os.Geteuid() == 0 }

// allowHint is the command that lets the service reach the group's servers.
const allowHint = "run sudo cbb global allow"

// homeCGNAT reports whether the Windows rule leaves 100.64.0.0/10 to the
// home network; on Linux the installer's drop-in cgnat.conf does it.
var homeCGNAT = func() bool { return false }

// adminName is who may change the firewall.
const adminName = "root (sudo)"

// closeHint closes the hub's port that cbb opened.
const closeHint = "run sudo sh /usr/local/share/clipboardbridge/firewall.sh hub-close"
