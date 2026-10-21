// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command clipbridge shares one clipboard between Apple devices and the Linux
// machines of a home network. The design is in docs/design.md.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/HunterEwok/clipbridge/internal/version"
)

const usage = `Usage: clipbridge <command> [arguments]

Commands:
  copy [-secret]          Send standard input to the group.
  paste                   Print this member's clipboard text.
  status                  Show the group and the connected members.
  pair                    Admit a new computer: show a code for clipbridge join.
  join [address:port]     Join a group with the code from clipbridge pair,
                          typed or read from standard input.
  service                 Run the service (started by systemd or launchd).
  version                 Print the version and the platform.
  help                    Print this help.

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
			fmt.Fprintf(stderr, "clipbridge: %s takes no arguments\n", cmd)
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
	case "pair":
		return cmdPair(rest, stdout, stderr)
	case "join":
		return cmdJoin(rest, stdin, stdout, stderr)
	case "service":
		return cmdService(rest, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "clipbridge: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}
