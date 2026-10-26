// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
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
	fmt.Fprintln(tw, "NAME\tSYSTEM\tROLE\tADMIN\tKEYS\tMODE\tSEEN\tCLOCK\tID")
	unlisted, oldKeys := false, false
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
		case d.Frozen:
			admin = "frozen"
		case d.Admin:
			admin = "admin"
		case d.OldKeys:
			admin = "old keys"
			oldKeys = true
		}
		clock := ""
		if ms, ok := skew[d.ID]; ok {
			clock = "ok"
			if d := time.Duration(ms) * time.Millisecond; d > 5*time.Second || d < -5*time.Second {
				clock = fmt.Sprintf("off by %v; check its time", d.Round(time.Second))
			}
		}
		// The sync mode, as each connected device's hello says it.
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, group.OSName(d.OS), d.Role, admin, keys(d), d.Mode, seen(d, now), clock, d.ID)
	}
	tw.Flush()
	if unlisted {
		fmt.Fprintln(w, "* not in the devices list yet; the group's root adds it when they meet.")
	}
	if oldKeys {
		fmt.Fprintln(w, "old keys: it may still hold the group's CA keys from before cbb upgrade; it deletes them when it next connects.")
	}
}

// keys says where a device's keys live: "in a file" warns that whoever
// copies the file holds them.
func keys(d control.Device) string {
	switch d.Store {
	case group.StoreHardware:
		return "hardware"
	case group.StoreFile:
		return "in a file"
	}
	return ""
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
	c, err := control.DialFor(control.OpRevoke)
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

// cmdRename gives a device of the group a new name, on an admin.
func cmdRename(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "cbb: usage: cbb rename <name or device ID> <new name>; cbb status lists them")
		return 2
	}
	c, err := control.DialFor(control.OpRename)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpRename, Name: args[0], NewName: args[1]}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Renamed %s to %s. The other devices show the new name as soon as they hear of it.\n", m.Name, strings.TrimSpace(args[1]))
	return 0
}

// cmdFreeze freezes (on true) or unfreezes an admin computer.
func cmdFreeze(args []string, on bool, stdout, stderr io.Writer) int {
	op, cmd := control.OpFreeze, "freeze"
	if !on {
		op, cmd = control.OpThaw, "unfreeze"
	}
	if len(args) != 1 {
		fmt.Fprintf(stderr, "cbb: usage: cbb %s <name or device ID>; cbb status lists them\n", cmd)
		return 2
	}
	c, err := control.DialFor(op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: op, Name: args[0]}})
	if err != nil {
		return fail(stderr, err)
	}
	if on {
		fmt.Fprintf(stdout, "Froze %s: it is no admin and the members refuse it as soon as they hear of it.\n"+
			"The group's root or an admin phone unfreezes it (cbb unfreeze) or removes it (cbb revoke).\n", m.Name)
	} else {
		fmt.Fprintf(stdout, "Unfroze %s: it is an admin again.\n", m.Name)
	}
	return 0
}

// cmdAdmin makes a device an admin of the group, on the group's root.
func cmdAdmin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	allow := fs.Bool("allow-file-key", false, "make it an admin although its keys sit in a file")
	if fs.Parse(args) != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "cbb: usage: cbb admin [-allow-file-key] <name or device ID>; cbb status lists them")
		return 2
	}
	args = fs.Args()
	c, err := control.DialFor(control.OpAdmin)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpAdmin, Name: args[0], Consent: *allow}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s is an admin now: it can admit and remove devices and pair iPhones for the shortcut.\n", m.Name)
	if *allow {
		fmt.Fprintf(stdout, "If it keeps its keys in a file, guard it: whoever copies that file acts as an admin until another admin removes %s.\n", m.Name)
	}
	return 0
}

// cmdTakeover takes the group over from its lost root computer, on an
// admin.
func cmdTakeover(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "cbb: usage: cbb takeover <name or device ID of the lost root>; cbb status shows it")
		return 2
	}
	c, err := control.DialFor(control.OpTakeover)
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

// cmdUpgrade gives a group made before roots and admins a root: this
// computer, which holds the group's keys.
func cmdUpgrade(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "cbb: usage: cbb upgrade, on a Linux or Windows member, after every member runs this version")
		return 2
	}
	c, err := control.DialFor(control.OpUpgrade)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpUpgrade}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "Upgraded the group: this computer is its root now, and only it and the admins it makes (cbb admin) hold keys.")
	fmt.Fprintln(stdout, "The other computers delete their copies of the old keys when they hear of it; cbb status marks those that have not yet.")
	fmt.Fprintln(stdout, "The group has a new iPhone CA: iPhones that use the shortcut pair again with cbb pair -phone.")
	return 0
}
