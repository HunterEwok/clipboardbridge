// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// holders names the other programs that hold port 5353, for the error
// when the responder cannot listen: on FreeBSD a socket shares a port only
// with the sockets of its own user, unless root opened it.
func holders() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sockstat", "-46l", "-P", "udp", "-p", strconv.Itoa(Port)).Output()
	if err != nil {
		return ""
	}
	return describeHolders(string(out), os.Getpid())
}

// describeHolders reads sockstat's lines (USER COMMAND PID FD PROTO LOCAL
// FOREIGN) into a note on the programs other than pid.
func describeHolders(out string, pid int) string {
	var names []string
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "USER" || f[2] == strconv.Itoa(pid) {
			continue
		}
		if n := f[1] + " (user " + f[0] + ")"; !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "; the port is held by " + strings.Join(names, ", ") +
		", and FreeBSD shares a port only among the sockets of one user unless root opened them (cbb service -user)"
}
