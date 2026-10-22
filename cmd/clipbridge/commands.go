// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
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

	"github.com/HunterEwok/clipbridge/internal/connector"
	"github.com/HunterEwok/clipbridge/internal/control"
	"github.com/HunterEwok/clipbridge/internal/node"
	"github.com/HunterEwok/clipbridge/internal/pair"
	"github.com/HunterEwok/clipbridge/internal/pasteboard"
	"github.com/HunterEwok/clipbridge/internal/phone"
	"github.com/HunterEwok/clipbridge/internal/service"
)

const maxText = 1 << 20

// cmdCopy sends standard input to the group as a deliberate copy.
func cmdCopy(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("copy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secret := fs.Bool("secret", false, "send the text as a secret: kept only in memory, gone after 60 seconds")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "clipbridge: copy takes no arguments; it reads the text from standard input")
		return 2
	}
	text, err := io.ReadAll(io.LimitReader(stdin, maxText+1))
	if err != nil {
		return fail(stderr, err)
	}
	if len(text) > maxText {
		return fail(stderr, errors.New("the text is larger than 1 MiB"))
	}
	kind := control.KindText
	if *secret {
		kind = control.KindSecret
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
	if _, err := stdout.Write(m.Payload); err != nil {
		return fail(stderr, err)
	}
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
	var out bytes.Buffer
	writeStatus(&out, st)
	if _, err := stdout.Write(out.Bytes()); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func writeStatus(w io.Writer, st *control.Status) {
	fmt.Fprintf(w, "%s\n", st.Version)
	if st.Group == "" {
		if st.Role == string(node.Linux) {
			fmt.Fprintln(w, "Not in a group. Run clipbridge pair here to start one, or clipbridge join to join one.")
		} else {
			fmt.Fprintln(w, "Not in a group. Run clipbridge pair on a Linux member, then clipbridge join here.")
		}
		return
	}
	fmt.Fprintf(w, "Device %s (%s), group %s\n", st.Device, st.Role, st.Group)
	if st.Holder {
		fmt.Fprintln(w, "This member answers for clipbridge.local.")
	}
	if len(st.Peers) == 0 {
		fmt.Fprintln(w, "No members connected.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MEMBER\tROLE\tCLOCK")
	for _, p := range st.Peers {
		clock := "ok"
		if d := time.Duration(p.SkewMS) * time.Millisecond; d > 5*time.Second || d < -5*time.Second {
			clock = fmt.Sprintf("off by %v; check its time", d.Round(time.Second))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", p.ID, p.Role, clock)
	}
	tw.Flush()
}

// cmdPair opens a pairing window and waits until a device joins, the
// window closes, or the user presses Ctrl+C.
func cmdPair(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	phone := fs.Bool("phone", false, "pair an iPhone or iPad instead of a computer")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "clipbridge: pair takes only -phone")
		return 2
	}
	if *phone {
		return cmdPairPhone(stdout, stderr)
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
	fmt.Fprintln(stdout, "On the new computer run:  clipbridge join -code")
	if m.Address != "" {
		fmt.Fprintf(stdout, "If it cannot find this one: clipbridge join -code %s\n", m.Address)
	}
	fmt.Fprintf(stdout, "\nWaiting up to %d minutes. Press Ctrl+C to cancel.\n", m.Expires/60)
	m, err = c.Receive()
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s joined the group.\n", m.Name)
	return 0
}

// cmdPairPhone opens an iPhone pairing window and walks the user through
// it: the profile first, the fingerprint, and only then the code.
func cmdPairPhone(stdout, stderr io.Writer) int {
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPairPhone}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "Scan this with the iPhone's camera and follow the page:")
	fmt.Fprintln(stdout)
	if err := writeQR(stdout, "http://"+m.Address+"/"); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "\n  (or open http://%s/ in Safari)\n\n", m.Address)
	fmt.Fprintf(stdout, "The profile's fingerprint must start with:  %s\n", shortFingerprint(m.Fingerprint))
	fmt.Fprintf(stdout, "The code the shortcut asks for:            %s %s\n", m.Code[:3], m.Code[3:])
	fmt.Fprintf(stdout, "\nWaiting up to %d minutes. Press Ctrl+C to cancel.\n", m.Expires/60)
	if _, err := c.Receive(); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "The iPhone is paired. Press the shortcut to sync.")
	return 0
}

// shortFingerprint returns the first eight groups of a fingerprint, the part
// the user compares.
func shortFingerprint(fp string) string {
	if len(fp) > 23 {
		return fp[:23]
	}
	return fp
}

// cmdJoin joins this device to a group. By default it shows a QR code for
// the phone, the group's main device, to scan with the clipbridge
// shortcut that adds a computer, and waits for the window that the phone
// opens. With -code it asks for the code that clipbridge pair shows on a
// Linux member instead; that code is read from standard input, never taken
// from the command line, where other users of the machine could read it.
func cmdJoin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	fs.SetOutput(stderr)
	typed := fs.Bool("code", false, "type the code that clipbridge pair shows on a Linux member")
	if fs.Parse(args) != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) > 1 || len(rest) == 1 && (!*typed || !strings.Contains(rest[0], ":")) {
		fmt.Fprintln(stderr, "usage: clipbridge join            (scan the QR code with the phone)\n       clipbridge join -code [address:port]\nThe code is asked for, or read from standard input.")
		return 2
	}
	h := control.Header{Op: control.OpJoin}
	if *typed {
		if len(rest) == 1 {
			h.Address = rest[0]
		}
		fmt.Fprint(stdout, "Pairing code: ")
		line, err := readLine(stdin)
		if err != nil {
			return fail(stderr, err)
		}
		if h.Code, err = pair.NormalizeCode(line); err != nil {
			return fail(stderr, err)
		}
	} else {
		h.Code = pair.NewCode()
		h.Expires = int(pair.Lifetime / time.Second)
		h.Listen = true
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h})
	if err != nil {
		return fail(stderr, err)
	}
	if !*typed {
		// The service listens and answers first with where, for the QR
		// code, then once more when the join ends.
		if len(m.Addrs) == 0 {
			return fail(stderr, errors.New("this device has no address on the home network; connect it to the network, or use clipbridge join -code"))
		}
		fmt.Fprintln(stdout, "In the clipbridge app, tap \"Connect a new device\" (or run the shortcut")
		fmt.Fprintln(stdout, "\"clipbridge: add a computer\") and scan this:")
		fmt.Fprintln(stdout)
		jc := phone.JoinCode{Code: h.Code, Addrs: m.Addrs, Fingerprint: m.Fingerprint}
		text := phone.JoinQR(jc)
		if err := writeQR(stdout, text); err != nil {
			return fail(stderr, err)
		}
		// The same code as text, for a phone without a camera, such as the
		// app in the iOS simulator.
		fmt.Fprintf(stdout, "\nOr paste this into the app: %s\n", text)
		fmt.Fprintf(stdout, "\nWaiting up to %d minutes. Press Ctrl+C to cancel.\n", h.Expires/60)
		fmt.Fprintln(stdout, "Without a phone: run clipbridge pair on a Linux member and clipbridge join -code here.")
		fmt.Fprintln(stdout, "If the phone cannot connect, a firewall may be in the way: TCP 8764-8767 must be open")
		fmt.Fprintln(stdout, "to the home network; the installer opens them in ufw or firewalld (docs/quickstart.md).")
		if _, err := c.Receive(); err != nil {
			return fail(stderr, err)
		}
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

// cmdAgent links the Mac's pasteboard to the service; launchd starts it in
// the user's session.
func cmdAgent(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "clipbridge: agent takes no arguments")
		return 2
	}
	if runtime.GOOS != "darwin" {
		return fail(stderr, errors.New("the pasteboard agent is for macOS; on Linux the desktop connector links the clipboard"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	b := pasteboard.General()
	if _, _, err := b.Read(); errors.Is(err, pasteboard.ErrUnsupported) {
		return fail(stderr, err)
	}
	if err := connector.Run(ctx, connector.Config{Socket: control.SocketPath(), Board: pasteboard.NewWatch(b), Logf: logf}); err != nil {
		return fail(stderr, err)
	}
	return 0
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
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "clipbridge: service takes only flags")
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
