// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// cmdDevices lists the devices of the group.
func cmdDevices(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "cbb: devices takes no arguments")
		return 2
	}
	c, err := control.Dial(control.SocketPath())
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpDevices}})
	if err != nil {
		return fail(stderr, err)
	}
	var out bytes.Buffer
	writeDevices(&out, m.Devices, time.Now())
	if _, err := stdout.Write(out.Bytes()); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func writeDevices(w io.Writer, devs []control.Device, now time.Time) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tROLE\tADMIN\tSEEN\tID")
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
		if d.Admin {
			admin = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, d.Role, admin, seen(d, now), d.ID)
	}
	tw.Flush()
	if unlisted {
		fmt.Fprintln(w, "* not in the devices list yet; a member that holds the group's keys adds it when they meet.")
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
		fmt.Fprintln(stderr, "cbb: usage: cbb revoke <name or device ID>; cbb devices lists them")
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
