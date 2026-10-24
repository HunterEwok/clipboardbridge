// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// writeDevices prints the devices list, with the clock of each connected
// peer from peers.
func writeDevices(w io.Writer, devs, peers []control.Device, now time.Time) {
	if len(devs) == 0 {
		return
	}
	skew := map[string]int64{}
	for _, p := range peers {
		skew[p.ID] = p.SkewMS
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSYSTEM\tROLE\tADMIN\tSEEN\tCLOCK\tID")
	unlisted := false
	for _, d := range devs {
		name := d.Name
		if d.Self {
			name += " (this device)"
		}
		if !d.Listed {
			name += " *"
			unlisted = true
		}
		admin := ""
		switch {
		case d.Root:
			admin = "root"
		case d.Admin:
			admin = "admin"
		}
		clock := ""
		if ms, ok := skew[d.ID]; ok {
			clock = "ok"
			if d := time.Duration(ms) * time.Millisecond; d > 5*time.Second || d < -5*time.Second {
				clock = fmt.Sprintf("off by %v; check its time", d.Round(time.Second))
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, group.OSName(d.OS), d.Role, admin, seen(d, now), clock, d.ID)
	}
	tw.Flush()
	if unlisted {
		fmt.Fprintln(w, "* not in the devices list yet; the group's root adds it when they meet.")
	}
}

// seen says when a device was last seen, in words.
func seen(d control.Device, now time.Time) string {
	switch {
	case d.Online:
		return "online"
	case d.LastSeenMS == 0:
		return "not seen here"
	}
	ago := now.Sub(time.UnixMilli(d.LastSeenMS))
	switch {
	case ago < time.Minute:
		return "just now"
	case ago < time.Hour:
		return fmt.Sprintf("%d min ago", int(ago/time.Minute))
	case ago < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(ago/time.Hour))
	}
	return fmt.Sprintf("%d days ago", int(ago/(24*time.Hour)))
}

// cmdRevoke removes a device from the group.
func cmdRevoke(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "cbb: usage: cbb revoke <name or device ID>; cbb status lists them")
		return 2
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpRevoke, Name: args[0]}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Removed %s from the group. The other members refuse it as soon as they hear of it.\n", m.Name)
	return 0
}

// cmdAdmin makes a device an admin of the group, on the group's root.
func cmdAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "cbb: usage: cbb admin <name or device ID>; cbb status lists them")
		return 2
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpAdmin, Name: args[0]}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s is an admin now: it can admit and remove devices and pair iPhones for the shortcut.\n", m.Name)
	return 0
}

// cmdTakeover takes the group over from its lost root computer, on an
// admin.
func cmdTakeover(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "cbb: usage: cbb takeover <name or device ID of the lost root>; cbb status shows it")
		return 2
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpTakeover, Name: args[0]}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "This device is the group's root now, and %s is removed from it. The group has a new iPhone CA: iPhones that use the shortcut pair again with cbb pair -phone.\n", m.Name)
	return 0
}
