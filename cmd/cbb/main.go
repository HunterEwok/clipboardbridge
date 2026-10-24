// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command clipboardbridge shares one clipboard between Apple devices and the Linux
// and Windows computers of a home network. The design is in docs/design.md.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/HunterEwok/clipboardbridge/internal/version"
)

const usage = `Usage: clipboardbridge <command> [arguments]

Commands:
  copy [-secret]          Send standard input to the group.
  paste                   Print this member's clipboard text.
  status                  Show this device, its group and the group's devices.
  revoke <name or ID>     Remove a device from the group.
  admin <name or ID>      Make a computer an admin of the group (on the group's root).
  away [on|off]           Show, or turn on or off, sync away from home on this device.
  away hub address:port   Make this device the group's hub for sync away from home.
  away relay address:port Meet the group's other devices away from home at a relay.
  forward                 Run a forwarder for hubs that clients cannot reach directly.
  relay -group TAG        Run a blind relay for groups without a hub.
  new                     Create a group with this computer as its root.
  pair                    In a group: show a code for a new computer. In none: join one,
                          by the phone's QR code or the code from cbb pair on the group.
  pair -code [address]    Join with the code from cbb pair on the root or an admin.
  pair -phone             Pair an iPhone or iPad with the shortcut.
  pair -invite file       Join from afar with an invitation from cbb invite.
  invite [-for 1h]        Invite a device from afar: run on the group's hub.
  version                 Print the version and the platform.
  help                    Print this help.

Rarely needed:
  holder [auto|first|fallback|never]
                          Show or set whether this computer holds clipboardbridge.local.
  service                 Run the service (started by systemd, launchd or Windows).
  agent                   Link this desktop's clipboard to the service (started at sign-in).

The design is in docs/design.md.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes one command line and returns the exit code: 0 on success,
// 1 on a failure, 2 on a usage error.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "-version", "--version":
		if len(rest) > 0 {
			fmt.Fprintf(stderr, "cbb: %s takes no arguments\n", cmd)
			return 2
		}
		fmt.Fprintln(stdout, version.String())
		return 0
	case "copy":
		return cmdCopy(rest, stdin, stdout, stderr)
	case "paste":
		return cmdPaste(rest, stdout, stderr)
	case "status":
		return cmdStatus(rest, stdout, stderr)
	case "away":
		return cmdAway(rest, stdin, stdout, stderr)
	case "revoke":
		return cmdRevoke(rest, stdout, stderr)
	case "admin":
		return cmdAdmin(rest, stdout, stderr)
	case "new":
		return cmdNew(rest, stdout, stderr)
	case "pair":
		return cmdPair(rest, stdin, stdout, stderr)
	case "invite":
		return cmdInvite(rest, stdin, stdout, stderr)
	case "holder":
		return cmdHolder(rest, stdout, stderr)
	case "forward":
		return cmdForward(rest, stdout, stderr)
	case "relay":
		return cmdRelay(rest, stdout, stderr)
	case "service":
		return cmdService(rest, stderr)
	case "agent":
		return cmdAgent(rest, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "cbb: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}
