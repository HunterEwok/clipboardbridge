// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// cmdHolder shows or changes whether this computer holds
// clipboardbridge.local first, only as a fallback, or never.
func cmdHolder(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: cbb holder [auto|first|fallback|never]")
		return 2
	}
	h := control.Header{Op: control.OpStatus}
	if len(args) == 1 {
		h = control.Header{Op: control.OpHolder, Name: args[0]}
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
	if m.Status == nil {
		return fail(stderr, errors.New("the service sent no status"))
	}
	fmt.Fprintln(stdout, holderLine(m.Status))
	return 0
}

// holderLine says how this computer takes part in holding
// clipboardbridge.local, the name the shortcut on an iPhone reaches.
func holderLine(st *control.Status) string {
	setting := st.HoldSetting
	if setting == "auto" {
		if st.Battery {
			setting += ", a laptop"
		} else {
			setting += ", no battery"
		}
	}
	var turn string
	switch st.HoldPriority {
	case 1:
		turn = "first"
	case 2:
		turn = "as a fallback"
	}
	switch {
	case st.Group == "":
		return fmt.Sprintf("Holder of clipboardbridge.local: setting %s.", setting)
	case turn == "" && st.HoldSetting == "never":
		return fmt.Sprintf("Never holds clipboardbridge.local (setting %s).", setting)
	case turn == "":
		return "Never holds clipboardbridge.local: it does not hold the group's iPhone key."
	case st.Holder:
		return fmt.Sprintf("Answers for clipboardbridge.local (%s; setting %s).", turn, setting)
	}
	return fmt.Sprintf("Answers for clipboardbridge.local %s when elected; another member does now (setting %s).", turn, setting)
}
