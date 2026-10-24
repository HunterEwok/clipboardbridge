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
	"os"
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

// runTimeout bounds one command of Run, so a command that hangs (a
// clipboard tool waiting for a window, a stuck service) fails its case
// instead of the whole run.
const runTimeout = 30 * time.Second

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
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	c := command(ctx, d, cmd)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	c.Stdout, c.Stderr = &out, &errOut
	if err := c.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("no answer within %s: %w", runTimeout, err)
		}
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
		args = append(args, "powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePS(psScript(cmd)))
	} else {
		args = append(args, "sh", "-c", shellQuote(shPath+cmd))
	}
	c := exec.CommandContext(ctx, "ssh", args...)
	c.Env = noLocale(os.Environ())
	return c
}

// noLocale drops the locale from ssh's environment. The system's ssh_config
// sends LANG and LC_* to the device (SendEnv, which -o cannot take back), and
// a device without that locale warns on every command.
func noLocale(env []string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "LANG=") && !strings.HasPrefix(kv, "LC_") && !strings.HasPrefix(kv, "LANGUAGE=") {
			out = append(out, kv)
		}
	}
	return out
}

// shPath puts the places installers use on the PATH: an SSH command does not
// run a login shell, and macOS then leaves out /usr/local/bin.
const shPath = "PATH=$PATH:/usr/local/bin:/opt/homebrew/bin; export PATH; "

// psScript wraps a PowerShell command for an SSH session. PowerShell writes
// errors to a redirected stream as CLIXML in the console's code page; this
// prints them as plain UTF-8 text instead, and exits with the code of the
// last program the command ran.
func psScript(cmd string) string {
	return "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; " +
		"[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false; $global:LASTEXITCODE = 0; " +
		"try { " + cmd + "\n} catch { [Console]::Error.WriteLine(($_ | Out-String).Trim()); exit 1 }; exit $LASTEXITCODE"
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
