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
		"       cbb away hub [-port N] [-obfuscate] [-forwarder address:port -forwarder-key KEY] [address:port...]\n" +
		"                                      make this device the group's hub, reached at these addresses\n" +
		"                                      or through the forwarder; -obfuscate for networks that block WireGuard\n" +
		"       cbb away relay address:port -key KEY\n" +
		"                                      meet the group's other devices at a blind relay, for a group\n" +
		"                                      without a hub"
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
		fwd := fs.String("forwarder", "", "the forwarder's address, for clients that cannot reach the hub directly")
		fwdKey := fs.String("forwarder-key", "", "the forwarder's key, which cbb forward prints")
		obfuscate := fs.Bool("obfuscate", false, "speak AmneziaWG, which hides that the packets are WireGuard, for networks that block it")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		if fs.NArg() == 0 && *fwd == "" {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		h.Port, h.Addrs, h.Forwarder, h.ForwarderKey, h.Obfuscate = *port, fs.Args(), *fwd, *fwdKey, *obfuscate
	case "relay":
		fs := flag.NewFlagSet("away relay", flag.ContinueOnError)
		fs.SetOutput(stderr)
		key := fs.String("key", "", "the relay's key, which cbb relay prints")
		// The address may come before the flag or after it.
		rest := args[1:]
		var addr string
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			addr, rest = rest[0], rest[1:]
		}
		if fs.Parse(rest) != nil {
			return 2
		}
		if addr == "" && fs.NArg() == 1 {
			addr = fs.Arg(0)
		} else if fs.NArg() != 0 {
			addr = ""
		}
		if addr == "" || *key == "" {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		h.Relay, h.RelayKey = addr, *key
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
	if args[0] == "hub" {
		fmt.Fprint(stdout, hubNote)
	}
	return 0
}

// hubNote tells the user what depends on the hub being on.
const hubNote = `
The hub does not have to stay on. While it is off, nothing syncs away from home;
at home the devices sync with each other without it. Keep it on all the time, turn
it on when you need it, or sync only at home.
`

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
		if a.Obfuscated {
			fmt.Fprintln(w, "  Obfuscated: the tunnel speaks AmneziaWG, so it does not look like WireGuard.")
		}
		switch {
		case len(a.Endpoints) > 0:
			fmt.Fprintf(w, "  Reached at %s.\n", strings.Join(a.Endpoints, ", "))
			fmt.Fprintf(w, "  The router must forward UDP port %d to this device, and its firewall must allow it.\n", a.Port)
		case a.Forwarder == nil:
			fmt.Fprintln(w, "  The hub has no address away from home: cbb away hub address:port...")
		}
		if f := a.Forwarder; f != nil {
			switch {
			case f.Registered && f.Seen != "":
				fmt.Fprintf(w, "  Registered with the forwarder at %s, which reaches this hub at %s.\n", f.Endpoint, f.Seen)
			case f.Registered:
				fmt.Fprintf(w, "  Registered with the forwarder at %s; it has not heard the hub's UDP port yet.\n", f.Endpoint)
			case f.Error == "":
				fmt.Fprintf(w, "  Registering with the forwarder at %s.\n", f.Endpoint)
			default:
				fmt.Fprintf(w, "  Not registered with the forwarder at %s: %s.\n", f.Endpoint, f.Error)
				if f.Detail != "" && debugErrors() {
					fmt.Fprintf(w, "  Detail: %s\n", f.Detail)
				}
			}
		}
	case a.Relay != nil:
		r := a.Relay
		switch {
		case r.Connected && a.Through:
			fmt.Fprintf(w, "Sync away from home: on; connected to the relay at %s and through it to other devices.\n", r.Endpoint)
		case r.Connected && len(r.Online) == 0:
			fmt.Fprintf(w, "Sync away from home: on; connected to the relay at %s; no other device of the group is there now.\n", r.Endpoint)
		case r.Connected:
			fmt.Fprintf(w, "Sync away from home: on; connected to the relay at %s, with %d other devices of the group there.\n", r.Endpoint, len(r.Online))
		case r.Error == "":
			fmt.Fprintf(w, "Sync away from home: on; connecting to the relay at %s.\n", r.Endpoint)
		default:
			fmt.Fprintf(w, "Sync away from home: on; not connected to the relay at %s: %s.\n", r.Endpoint, r.Error)
			if r.Detail != "" && debugErrors() {
				fmt.Fprintf(w, "  Detail: %s\n", r.Detail)
			}
		}
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
