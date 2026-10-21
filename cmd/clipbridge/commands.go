// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/HunterEwok/clipbridge/internal/control"
	"github.com/HunterEwok/clipbridge/internal/node"
	"github.com/HunterEwok/clipbridge/internal/service"
)

const maxText = 1 << 20

// cmdCopy sends standard input to the group as a deliberate copy.
func cmdCopy(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("copy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secret := fs.Bool("secret", false, "send the text as a secret: kept only in memory, gone after 60 seconds")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	text, err := io.ReadAll(io.LimitReader(stdin, maxText+1))
	if err != nil {
		return fail(stderr, err)
	}
	if len(text) > maxText {
		return fail(stderr, errors.New("the text is larger than 1 MiB"))
	}
	kind := "text"
	if *secret {
		kind = "secret"
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpCopy, Kind: kind}, Payload: text}); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// cmdPaste writes the member's own clipboard text to standard output.
func cmdPaste(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "clipbridge: paste takes no arguments")
		return 2
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPaste}})
	if err != nil {
		return fail(stderr, err)
	}
	stdout.Write(m.Payload)
	return 0
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "clipbridge: status takes no arguments")
		return 2
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err != nil {
		return fail(stderr, err)
	}
	st := m.Status
	if st == nil {
		return fail(stderr, errors.New("the service sent no status"))
	}
	fmt.Fprintf(stdout, "%s\n", st.Version)
	if st.Group == "" {
		fmt.Fprintln(stdout, "Not in a group. Run clipbridge pair on a Linux member, then clipbridge join here.")
		return 0
	}
	fmt.Fprintf(stdout, "Device %s (%s), group %s\n", st.Device, st.Role, st.Group)
	if st.Holder {
		fmt.Fprintln(stdout, "This member answers for clipbridge.local.")
	}
	if len(st.Peers) == 0 {
		fmt.Fprintln(stdout, "No members connected.")
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MEMBER\tROLE\tCLOCK")
	for _, p := range st.Peers {
		clock := "ok"
		if d := time.Duration(p.SkewMS) * time.Millisecond; d > 5*time.Second || d < -5*time.Second {
			clock = fmt.Sprintf("off by %v; check its time", d.Round(time.Second))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", p.ID, p.Role, clock)
	}
	tw.Flush()
	return 0
}

// cmdPair opens a pairing window and waits until a device joins, the
// window closes, or the user presses Ctrl+C.
func cmdPair(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "clipbridge: pair takes no arguments")
		return 2
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Pairing code: %s %s\n\n", m.Code[:3], m.Code[3:])
	fmt.Fprintln(stdout, "On the new computer run:  clipbridge join")
	if m.Address != "" {
		fmt.Fprintf(stdout, "If it cannot find this one: clipbridge join %s %s\n", m.Code, m.Address)
	}
	fmt.Fprintf(stdout, "\nWaiting up to %d minutes. Press Ctrl+C to cancel.\n", m.Expires/60)
	m, err = c.Receive()
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s joined the group.\n", m.Name)
	return 0
}

// cmdJoin joins this device to a group with the code shown by pair.
func cmdJoin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 2 {
		fmt.Fprintln(stderr, "usage: clipbridge join [code [address]]")
		return 2
	}
	var code, addr string
	if len(args) > 0 {
		code = args[0]
	}
	if len(args) > 1 {
		addr = args[1]
	}
	if code == "" {
		fmt.Fprint(stdout, "Pairing code: ")
		line, err := readLine(stdin)
		if err != nil {
			return fail(stderr, err)
		}
		code = line
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Code: code, Address: addr}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "Joined the group.")
	return 0
}

func readLine(r io.Reader) (string, error) {
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() < 64 {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			if err == io.EOF && b.Len() > 0 {
				break
			}
			return "", err
		}
	}
	return strings.TrimSpace(b.String()), nil
}

// cmdDesktop links a Linux desktop's clipboard to the service; the session
// starts it. When the display connection drops it opens it again, and it
// exits when the session is gone.
func cmdDesktop(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "clipbridge: desktop takes no arguments")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	return runDesktop(ctx, logf, stderr)
}

// cmdService runs the service; systemd and launchd start it.
func cmdService(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state", defaultStateDir(), "the directory for the identity and the clock mark")
	socket := fs.String("socket", control.SocketPath(), "the control socket")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	role := node.Linux
	if runtime.GOOS == "darwin" {
		role = node.Mac
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	if err := service.Run(ctx, service.Config{StateDir: *stateDir, Socket: *socket, Role: role, Logf: logf}); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func defaultStateDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" { // set by systemd
		return d
	}
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/clipbridge/state"
	}
	return "/var/lib/clipbridge"
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "clipbridge:", err)
	return 1
}
