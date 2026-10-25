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
  paste [-terminal [-lines] [-secret]]
                          Print this member's clipboard text; -terminal makes it
                          safe to paste into a terminal.
  status                  Show this device, its group and the group's devices.
  revoke <name or ID>     Remove a device from the group.
  rename <name or ID> <new name>
                          Give a device of the group another name (on an admin).
  admin <name or ID>      Make a computer an admin of the group (on the group's root).
  takeover <name or ID>   Take the group over from its lost root computer (on an admin).
  upgrade                 Give a group made before 0.4 a root: this computer (holds its keys).
  freeze <name or ID>     Stop an admin computer, as a stolen one, until the root decides.
  unfreeze <name or ID>   Make a frozen admin computer an admin again (on the group's root).
  global [on|off]         Show, or turn on or off, sync over the internet on this device.
  global hub address:port Make this device the group's hub for sync over the internet.
  global relay address:port
                          Meet the group's other devices over the internet at a relay.
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
  install [options]       Windows, after winget: install the service from this copy
                          (the options of install.ps1, such as -Express).
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
	case "global":
		return cmdGlobal(rest, stdin, stdout, stderr)
	case "revoke":
		return cmdRevoke(rest, stdout, stderr)
	case "rename":
		return cmdRename(rest, stdout, stderr)
	case "install":
		return cmdInstall(rest, stdout, stderr)
	case "upgrade":
		return cmdUpgrade(rest, stdout, stderr)
	case "takeover":
		return cmdTakeover(rest, stdout, stderr)
	case "freeze", "unfreeze":
		return cmdFreeze(rest, cmd == "freeze", stdout, stderr)
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
