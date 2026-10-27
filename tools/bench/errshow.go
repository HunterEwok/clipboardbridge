// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// internalRE finds what only a developer reads in an error: Go's and the
// system's error texts, addresses of sockets, file paths of the code. With
// CBB_DEBUG=0 none of it belongs in a message (R6); the log has it.
var internalRE = regexp.MustCompile(`(?i)(\bdial (unix|tcp|udp)\b|connect: |no such file or directory|connection refused|i/o timeout|broken pipe|\bEOF\b|x509: |tls: |\.go:\d+|errno|0x[0-9a-f]{4,}|context deadline exceeded|syscall|goroutine)`)

// genericRE finds a message that hides its cause.
var genericRE = regexp.MustCompile(`(?i)something went wrong|unknown error|an error occurred`)

// errorCase is one error the bench expects of a command (R6): the words its
// message must have, and whether the error has a cause underneath that
// CBB_DEBUG=1 shows.
type errorCase struct {
	cmd, stdin string
	want       []string // the message has one of these
	detail     bool     // CBB_DEBUG=1 shows a Detail line under it
}

// errorShown runs the command with CBB_DEBUG=0 and then 1 and checks R6:
// it fails both times, its message names the problem (want) and none hides
// it, without details in mode 0 and with them in mode 1.
func errorShown(ctx context.Context, d *Device, ec errorCase) error {
	modes := []string{"0", "1"}
	if d.OS == "darwin" && strings.HasPrefix(ec.cmd, "sudo ") {
		// sudo there keeps no variable (withDebug): one run in the
		// build's own mode, checked for the words only.
		modes = []string{""}
	}
	var short string
	for _, mode := range modes {
		_, err := Run(ctx, d, withDebug(d, ec.cmd, mode), ec.stdin)
		var re *RunError
		switch {
		case err == nil:
			return fmt.Errorf("%s did not fail (CBB_DEBUG=%s)", firstLine(ec.cmd), mode)
		case sudoRefused(err):
			return noSudo(d, err)
		case !errors.As(err, &re):
			return err
		}
		if err := checkMessage(re.Output, ec, mode); err != nil {
			return &RunError{Device: d.Name, Cmd: ec.cmd, Err: err, Output: re.Output}
		}
		if mode != "1" {
			short = re.Output
		} else if len(re.Output) < len(short) {
			return &RunError{Device: d.Name, Cmd: ec.cmd, Err: errors.New("CBB_DEBUG=1 shows less than CBB_DEBUG=0"), Output: short + "\n--- CBB_DEBUG=1:\n" + re.Output}
		}
	}
	return nil
}

// checkMessage checks one run's output for errorShown.
func checkMessage(out string, ec errorCase, mode string) error {
	msg := strings.TrimSpace(out)
	if msg == "" {
		return errors.New("it failed without a message")
	}
	if m := genericRE.FindString(msg); m != "" {
		return fmt.Errorf("the message hides the cause: %q", m)
	}
	found := len(ec.want) == 0
	for _, w := range ec.want {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(w)) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("the message does not say %q: %q", strings.Join(ec.want, `" or "`), firstLine(msg))
	}
	hasDetail := strings.Contains(msg, "Detail:")
	switch mode {
	case "0":
		if hasDetail {
			return errors.New("CBB_DEBUG=0 shows a Detail line")
		}
		if m := internalRE.FindString(msg); m != "" {
			return fmt.Errorf("with CBB_DEBUG=0 the message shows an internal error (%q); put it under Detail", m)
		}
	case "1":
		if ec.detail && !hasDetail {
			return errors.New("CBB_DEBUG=1 shows no Detail line under the message")
		}
	}
	return nil
}

// withDebug runs a command of cbb with CBB_DEBUG set: in its environment,
// past sudo, which drops it, and into a container.
func withDebug(d *Device, cmd, mode string) string {
	switch d.OS {
	case "windows":
		return "$env:CBB_DEBUG='" + mode + "'; " + cmd
	case "docker":
		return strings.Replace(cmd, "docker exec -i ", "docker exec -e CBB_DEBUG="+mode+" -i ", 1)
	}
	if mode == "" {
		return cmd
	}
	if rest, ok := strings.CutPrefix(cmd, "sudo -n "); ok && d.OS != "darwin" {
		return "sudo -n env CBB_DEBUG=" + mode + " " + rest
	}
	// On a Mac sudo runs only cbb itself (the bench's sudoers rule), and
	// keeps no variable: there the case checks the build's own mode.
	return "CBB_DEBUG=" + mode + " " + cmd
}
