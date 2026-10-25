// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// cmdMode shows or changes this device's sync mode: what moves between its
// clipboard and the group.
func cmdMode(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: cbb mode [own|shared|receive|send]")
		return 2
	}
	h := control.Header{Op: control.OpStatus}
	if len(args) == 1 {
		h = control.Header{Op: control.OpMode, Name: args[0]}
	}
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h})
	if err != nil {
		return fail(stderr, err)
	}
	if m.Status == nil {
		return fail(stderr, errors.New("the service sent no status"))
	}
	if m.Status.Group == "" {
		return fail(stderr, errors.New("this device is in no group; run cbb new here to start one, or cbb pair to join one"))
	}
	fmt.Fprintln(stdout, modeLine(m.Status.Mode))
	return 0
}

// modeLine says what the sync mode mode does.
func modeLine(mode string) string {
	switch mode {
	case "own":
		return "Sync mode own: this device keeps its clipboard to itself; cbb paste prints the group's text, and cbb copy sends to the group."
	case "shared":
		return "Sync mode shared: copies here go to the group, and the group's copies come here."
	case "receive":
		return "Sync mode receive: the group's copies come here, and copies here stay here."
	case "send":
		return "Sync mode send: copies here go to the group, and the group's copies do not come here."
	}
	return "Sync mode " + mode + "."
}
