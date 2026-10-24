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
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/connector"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/pasteboard"
	"github.com/HunterEwok/clipboardbridge/internal/phone"
	"github.com/HunterEwok/clipboardbridge/internal/service"
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
		fmt.Fprintln(stderr, "cbb: copy takes no arguments; it reads the text from standard input")
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
		fmt.Fprintln(stderr, "cbb: paste takes no arguments")
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
		fmt.Fprintln(stderr, "cbb: status takes no arguments")
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
	var devs []control.Device
	if st.Group != "" {
		d, err := control.Dial(control.SocketPath())
		if err != nil {
			return fail(stderr, err)
		}
		defer d.Close()
		m, err := d.Do(&control.Message{Header: control.Header{Op: control.OpDevices}})
		if err != nil {
			return fail(stderr, err)
		}
		devs = m.Devices
	}
	var out bytes.Buffer
	writeStatus(&out, st, devs, time.Now())
	if _, err := stdout.Write(out.Bytes()); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// writeStatus prints this device, its group and the group's devices.
func writeStatus(w io.Writer, st *control.Status, devs []control.Device, now time.Time) {
	fmt.Fprintf(w, "%s\n", st.Version)
	if st.Group == "" {
		fmt.Fprintln(w, "Not in a group. Run cbb new here to start one, or cbb pair to join one.")
		return
	}
	fmt.Fprintf(w, "Device %s (%s, %s), group %s\n", st.Device, group.OSName(st.OS), st.Role, st.Group)
	if st.Removed {
		fmt.Fprintln(w, "This device was removed from the group: its members refuse it. To join again, remove clipboardbridge with its keys (uninstall --purge), install it again and join.")
	}
	fmt.Fprintln(w, holderLine(st))
	writeAway(w, st.Away)
	if len(st.Peers) == 0 {
		fmt.Fprintln(w, "No members connected.")
	}
	writeDevices(w, devs, st.Peers, now)
}

// cmdNew creates a group with this computer as its root.
func cmdNew(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "cbb: new takes no arguments")
		return 2
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpNew}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Created the group %s; this computer is its root.\n", m.Status.Group)
	fmt.Fprintln(stdout, "Add a computer: cbb pair here, then cbb pair on the new computer.")
	fmt.Fprintln(stdout, "Add an iPhone with the shortcut: cbb pair -phone.")
	return 0
}

// cmdPair adds a device, on whichever side this computer is: in a group it
// opens a pairing window for a new computer; in no group it joins one, by
// the phone's QR code or by the code that cbb pair shows on the group's
// root or an admin.
func cmdPair(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	phone := fs.Bool("phone", false, "pair an iPhone or iPad with the shortcut")
	typed := fs.Bool("code", false, "join with the code that cbb pair shows on the group's root or an admin, read from standard input")
	invitation := fs.String("invite", "", "join from afar with the invitation file that cbb invite made on the group's hub")
	if fs.Parse(args) != nil {
		return 2
	}
	rest := fs.Args()
	switch {
	case *phone && (*typed || *invitation != "" || len(rest) != 0),
		*invitation != "" && (*typed || len(rest) != 0),
		len(rest) > 1 || len(rest) == 1 && (!*typed || !strings.Contains(rest[0], ":")):
		fmt.Fprintln(stderr, pairUsage)
		return 2
	case *phone:
		return cmdPairPhone(stdout, stderr)
	case *invitation != "":
		return cmdJoinInvite(*invitation, stdin, stdout, stderr)
	case *typed:
		address := ""
		if len(rest) == 1 {
			address = rest[0]
		}
		fmt.Fprint(stdout, "Pairing code: ")
		line, err := readLine(stdin)
		if err != nil {
			return fail(stderr, err)
		}
		return joinWithCode(line, address, stdout, stderr)
	}
	st, err := serviceStatus()
	if err != nil {
		return fail(stderr, err)
	}
	if st.Group == "" {
		return joinByQR(stdin, stdout, stderr)
	}
	return admit(stdout, stderr)
}

const pairUsage = `usage: cbb pair                  in a group: show a code for a new computer;
                                in no group: join by the phone's QR code or a typed code
       cbb pair -code [address:port]   join with the code, read from standard input
       cbb pair -phone          pair an iPhone with the shortcut
       cbb pair -invite file    join from afar with an invitation`

// serviceStatus asks the service for its status.
func serviceStatus() (*control.Status, error) {
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err != nil {
		return nil, err
	}
	return m.Status, nil
}

// admit opens a pairing window and waits until a device joins, the window
// closes, or the user presses Ctrl+C.
func admit(stdout, stderr io.Writer) int {
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
	fmt.Fprintln(stdout, "On the new computer run cbb pair and type the code.")
	if m.Address != "" {
		fmt.Fprintf(stdout, "If it cannot find this one: cbb pair -code %s\n", m.Address)
	}
	fmt.Fprintf(stdout, "\nWaiting up to %d minutes. Press Ctrl+C to cancel.\n", m.Expires/60)
	m, err = c.Receive()
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s joined the group.\n", m.Name)
	adminHint(stdout)
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

// joinWithCode joins the group with the code that cbb pair shows on the
// group's root or an admin, at address or at the member that announces an
// open window. The code comes from standard input, never from the command
// line, where other users of the machine could read it.
func joinWithCode(line, address string, stdout, stderr io.Writer) int {
	code, err := pair.NormalizeCode(line)
	if err != nil {
		return fail(stderr, err)
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Code: code, Address: address}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "Joined the group.")
	return 0
}

// joinByQR joins a group by the QR code the phone scans, the group's main
// device: it shows the QR code and waits for the window the phone opens.
// Meanwhile the user may type the code that cbb pair shows on a computer
// of the group instead.
func joinByQR(stdin io.Reader, stdout, stderr io.Writer) int {
	h := control.Header{Op: control.OpJoin, Code: pair.NewCode(), Expires: int(pair.Lifetime / time.Second), Listen: true}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h})
	if err != nil {
		return fail(stderr, err)
	}
	// The service listens and answers first with where, for the QR code,
	// then once more when the join ends.
	if len(m.Addrs) == 0 {
		return fail(stderr, errors.New("this device has no address on the home network; connect it to the network, or use cbb pair -code"))
	}
	fmt.Fprintln(stdout, "In the clipboardbridge app, tap \"Connect a new device\" (or run the shortcut")
	fmt.Fprintln(stdout, "\"clipboardbridge: add a computer\") and scan this:")
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
	port, err := service.Port()
	if err != nil {
		port = service.MemberPort
	}
	fmt.Fprintf(stdout, "If the phone cannot connect, a firewall may be in the way: TCP %d must be open to\n", port)
	fmt.Fprintln(stdout, "the home network; the installer opens it in ufw or firewalld (docs/quickstart.md).")
	fmt.Fprint(stdout, "\nWithout a phone: run cbb pair on the group's root or an admin and type its code here: ")

	ended := make(chan error, 1)
	go func() {
		_, err := c.Receive()
		ended <- err
	}()
	lines := make(chan string)
	go func() {
		for {
			line, err := readLine(stdin)
			if err != nil {
				return // no terminal, or it closed: the phone may still come
			}
			lines <- line
		}
	}()
	for {
		select {
		case err := <-ended:
			if err != nil {
				return fail(stderr, err)
			}
			fmt.Fprintln(stdout, "\nJoined the group.")
			return 0
		case line := <-lines:
			if line == "" {
				continue
			}
			if _, err := pair.NormalizeCode(line); err != nil {
				fmt.Fprintf(stderr, "cbb: %v; type the six digits again: ", err)
				continue
			}
			// Any message ends the wait for the phone; the join with the
			// code starts once the service has said so.
			c.Send(&control.Message{Header: control.Header{Op: control.OpAnswer}})
			<-ended
			return joinWithCode(line, "", stdout, stderr)
		}
	}
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

// cmdAgent links the desktop's clipboard to the service: the Mac's
// pasteboard, where launchd starts it in the user's session; the Windows
// clipboard, started at sign-in; a Linux desktop's clipboard, started with
// the desktop session.
func cmdAgent(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "cbb: agent takes no arguments")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if runtime.GOOS == "linux" {
		logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
		return runDesktop(ctx, logf, stderr)
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return fail(stderr, fmt.Errorf("the agent has no clipboard to link on %s", runtime.GOOS))
	}
	stderr, closeLog, err := agentLog(stderr)
	if err != nil {
		return fail(stderr, err)
	}
	defer closeLog()
	if !firstAgent() {
		return 0 // another agent links this session's clipboard already
	}
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
		fmt.Fprintln(stderr, "cbb: service takes only flags")
		return 2
	}
	return runService(stderr, func(ctx context.Context, logf func(string, ...any)) error {
		return service.Run(ctx, service.Config{StateDir: *stateDir, Socket: *socket, Role: node.Full, OS: hostOS(), Logf: logf})
	})
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "clipboardbridge:", err)
	return 1
}

// hostOS names this computer's operating system as device records do.
func hostOS() string {
	switch runtime.GOOS {
	case "darwin":
		return group.OSMacOS
	case "windows":
		return group.OSWindows
	}
	return group.OSLinux
}

// adminHint suggests a second admin on a root computer that has none: a
// group whose root is lost is taken over by an admin (cbb takeover), or
// made anew.
func adminHint(w io.Writer) {
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpDevices}})
	if err != nil {
		return
	}
	root := false
	for _, d := range m.Devices {
		switch {
		case d.Self && d.Root:
			root = true
		case d.Admin && !d.Root:
			return
		}
	}
	if root {
		fmt.Fprintln(w, "This computer is the group's only admin. Make another computer one with cbb admin NAME,")
		fmt.Fprintln(w, "so that it can take the group over if this one is lost (cbb takeover).")
	}
}
