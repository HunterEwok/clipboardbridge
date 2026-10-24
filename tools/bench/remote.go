// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
)

// sshArgs are the options of every connection: keys only, no prompts, and
// a dead device fails within seconds instead of hanging the run.
var sshArgs = []string{
	"-o", "BatchMode=yes",
	"-o", "ConnectTimeout=10",
	"-o", "ServerAliveInterval=5",
	"-o", "ServerAliveCountMax=3",
}

// RunError is a remote command that failed, with what it printed.
type RunError struct {
	Device string
	Cmd    string
	Err    error
	Output string
}

func (e *RunError) Error() string {
	return fmt.Sprintf("%s: %s: %v", e.Device, firstLine(e.Cmd), e.Err)
}

// Details is the output of the failed command, for the report and for
// CBB_DEBUG=1.
func (e *RunError) Details() string { return e.Output }

// Run runs a shell command on a device and returns its standard output.
// On Windows the command is PowerShell; elsewhere it is sh.
func Run(ctx context.Context, d *Device, cmd string, stdin string) (string, error) {
	c := command(ctx, d, cmd)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	c.Stdout, c.Stderr = &out, &errOut
	if err := c.Run(); err != nil {
		return out.String(), &RunError{Device: d.Name, Cmd: cmd, Err: err, Output: out.String() + errOut.String()}
	}
	return out.String(), nil
}

// Stream starts a command on a device and hands each line it prints to
// lines, until it exits or ctx ends. It returns once the command exits.
func Stream(ctx context.Context, d *Device, cmd string, lines func(string)) error {
	c := command(ctx, d, cmd)
	pr, pw := io.Pipe()
	c.Stdout, c.Stderr = pw, pw
	var all bytes.Buffer
	done := make(chan struct{})
	go func() {
		s := bufio.NewScanner(pr)
		for s.Scan() {
			all.WriteString(s.Text() + "\n")
			lines(s.Text())
		}
		close(done)
	}()
	err := c.Run()
	pw.Close()
	<-done
	if err != nil {
		return &RunError{Device: d.Name, Cmd: cmd, Err: err, Output: all.String()}
	}
	return nil
}

func command(ctx context.Context, d *Device, cmd string) *exec.Cmd {
	args := append(append([]string{}, sshArgs...), d.SSH, "--")
	if d.OS == "windows" {
		args = append(args, "powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePS("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "+cmd))
	} else {
		args = append(args, "sh", "-c", shellQuote(cmd))
	}
	return exec.CommandContext(ctx, "ssh", args...)
}

// encodePS encodes a PowerShell script for -EncodedCommand, which takes it
// as Base64 of UTF-16LE and so needs no quoting.
func encodePS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, r := range u {
		b[2*i], b[2*i+1] = byte(r), byte(r>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// shellQuote quotes s for the remote shell that ssh hands the command to.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// eventually calls f until it returns nil or the timeout passes, and
// returns the last error.
func eventually(ctx context.Context, timeout time.Duration, f func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := f()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}
