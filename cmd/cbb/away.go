// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/version"
)

// keysWarning is what a user agrees to before a device whose keys sit in
// files syncs away from home (docs/design.md, "Turning it on, step by
// step").
const keysWarning = `Sync away from home lets this device reach the group's hub from the internet,
through the group's own WireGuard tunnel, with the clipboard encrypted end to end.

This device keeps its keys in files, not in a security chip. Whoever copies those
files (with root on this device, from its disk or memory card, or from an
unencrypted backup) can act as this device from anywhere until you remove it from
the group. To keep that from happening:

  - encrypt the disk (LUKS, BitLocker, FileVault);
  - keep the service's state directory out of unencrypted backups;
  - remove the device at once (cbb revoke, or Remove on the phone) when it is lost
    or someone else may have had root on it.

`

// cmdAway shows or changes sync away from home on this device.
func cmdAway(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := "usage: cbb away                       show sync away from home\n" +
		"       cbb away on                    turn it on here\n" +
		"       cbb away off                   turn it off here and forget its keys\n" +
		"       cbb away hub [-port N] address:port...\n" +
		"                                      make this device the group's hub, reached at these addresses"
	if len(args) == 0 {
		return cmdAwayStatus(stdout, stderr)
	}
	h := control.Header{Op: control.OpAway, Name: args[0]}
	switch args[0] {
	case "on":
		if len(args) != 1 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		fmt.Fprint(stdout, keysWarning)
		fmt.Fprint(stdout, "Type yes to turn sync away from home on: ")
		line, err := readLine(stdin)
		if err != nil {
			return fail(stderr, err)
		}
		if !strings.EqualFold(strings.TrimSpace(line), "yes") {
			fmt.Fprintln(stdout, "Nothing changed.")
			return 1
		}
		h.Consent = true
	case "off":
		if len(args) != 1 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
	case "hub":
		fs := flag.NewFlagSet("away hub", flag.ContinueOnError)
		fs.SetOutput(stderr)
		port := fs.Int("port", 0, "the UDP port the hub listens on (default 8764)")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		if fs.NArg() == 0 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		h.Port, h.Addrs = *port, fs.Args()
	default:
		fmt.Fprintln(stderr, usage)
		return 2
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
	if m.Status != nil {
		writeAway(stdout, m.Status.Away)
	}
	return 0
}

func cmdAwayStatus(stdout, stderr io.Writer) int {
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err != nil {
		return fail(stderr, err)
	}
	if m.Status == nil || m.Status.Group == "" {
		return fail(stderr, fmt.Errorf("this device is in no group"))
	}
	writeAway(stdout, m.Status.Away)
	return 0
}

// writeAway describes sync away from home: with the underlying error in a
// debug build or with CBB_DEBUG=1, and only the short message otherwise.
func writeAway(w io.Writer, a *control.Away) {
	if a == nil {
		fmt.Fprintln(w, "Sync away from home: off (cbb away on turns it on).")
		return
	}
	switch {
	case a.Hub:
		fmt.Fprintf(w, "Sync away from home: on; this device is the hub, on UDP port %d, for %d devices.\n", a.Port, a.Clients)
		if len(a.Endpoints) == 0 {
			fmt.Fprintln(w, "  The hub has no address away from home: cbb away hub address:port...")
		} else {
			fmt.Fprintf(w, "  Reached at %s.\n", strings.Join(a.Endpoints, ", "))
		}
		fmt.Fprintf(w, "  The router must forward UDP port %d to this device, and its firewall must allow it.\n", a.Port)
	case a.HubDevice == "":
		fmt.Fprintln(w, "Sync away from home: on; waiting to meet the group's hub on the home network.")
	case a.Through:
		fmt.Fprintf(w, "Sync away from home: on; connected to the hub %s through the tunnel.\n", a.HubDevice)
	default:
		fmt.Fprintf(w, "Sync away from home: on; the hub is %s, at %s; not connected through the tunnel.\n", a.HubDevice, strings.Join(a.Endpoints, ", "))
	}
	if a.KeysInFile {
		fmt.Fprintln(w, "  This device keeps its keys in files, not in a security chip.")
	}
	if a.Error != "" {
		fmt.Fprintf(w, "  Problem: %s.\n", a.Error)
		if a.Detail != "" && debugErrors() {
			fmt.Fprintf(w, "  Detail: %s\n", a.Detail)
		}
	}
}

// debugErrors tells whether to show the underlying errors: in a build
// without a release version, unless CBB_DEBUG=0; in a release, only with
// CBB_DEBUG=1. The service's log always has them.
func debugErrors() bool {
	switch os.Getenv("CBB_DEBUG") {
	case "1":
		return true
	case "0":
		return false
	}
	return version.Version == "dev"
}
