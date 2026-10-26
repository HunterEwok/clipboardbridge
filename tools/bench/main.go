// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command bench runs the hardware test bench of docs/testbench.md: it drives
// real devices over SSH from the bench's controller and reports what passed.
//
//	go run ./tools/bench [-inventory FILE] [-report DIR] [-only a,b] check|smoke|full|away|relay
//	go run ./tools/bench [-only a,b] -build DIR reset
//	go run ./tools/bench [-only a,b] -quick reset
//
// check only reaches every device and prints what it finds; reset (R1)
// installs the build under test on every device at once, in no group, or
// with -quick only wipes the devices' state; smoke makes a
// group of the devices and sends one text from each device to all the
// others; full runs the sync matrix and the failure, mode and security
// cases on top; away adds the devices away from home by invitation through
// the hub and its forwarder (with -stop-forwarder also F7, which stops the
// forwarder); relay meets the group at the blind relay. The inventory lives on the controller, never in the repository
// (docs/testbench.md, section 13). Devices must be in no group before smoke;
// the bench never removes a group it did not make.
//
// CBB_DEBUG=1 adds each command's output to the messages of failed steps;
// the report always has it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	home, _ := os.UserHomeDir()
	invPath := fs.String("inventory", filepath.Join(home, ".config", "cbb-bench", "inventory.toml"), "the bench's inventory")
	reportDir := fs.String("report", "", "write report.xml (JUnit) and report.txt here")
	only := fs.String("only", "", "comma-separated devices to use instead of all of them")
	timeout := fs.Duration("timeout", 20*time.Second, "how long a text may take to arrive")
	stopForwarder := fs.Bool("stop-forwarder", false, "away: also stop and start the forwarder (F7), which other groups may use")
	buildDir := fs.String("build", "", "reset: the directory with the release archives (and SHA256SUMS) to install")
	quick := fs.Bool("quick", false, "reset: keep each device's install and only remove its state")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: bench [flags] check|reset|smoke|full|away|relay")
		return 2
	}
	inv, err := LoadInventory(*invPath)
	if err != nil {
		fmt.Fprintf(stderr, "bench: %v\n", err)
		return 1
	}
	devices, err := inv.Select(*only)
	if err != nil {
		fmt.Fprintf(stderr, "bench: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	r := NewReport(fs.Arg(0), stdout, debugMode())
	switch fs.Arg(0) {
	case "check":
		Check(ctx, r, devices)
	case "smoke":
		Smoke(ctx, r, inv, devices, *timeout)
	case "full":
		Full(ctx, r, devices, *timeout)
	case "away":
		Away(ctx, r, inv, devices, *timeout, *stopForwarder)
	case "relay":
		Relay(ctx, r, inv, devices, *timeout)
	case "reset":
		var b *Build
		if *buildDir != "" {
			if b, err = LoadBuild(*buildDir); err != nil {
				fmt.Fprintf(stderr, "bench: %v\n", err)
				return 1
			}
		}
		Reset(ctx, r, devices, b, *quick)
	default:
		fmt.Fprintf(stderr, "bench: unknown suite %q\n", fs.Arg(0))
		return 2
	}
	if *reportDir != "" {
		if err := r.Write(*reportDir); err != nil {
			fmt.Fprintf(stderr, "bench: %v\n", err)
			return 1
		}
	}
	if r.Failed() > 0 {
		return 1
	}
	return 0
}

// debugMode follows CBB_DEBUG like cbb itself: details under each failure
// with 1, none with 0; a development run shows them by default.
func debugMode() bool {
	v := strings.TrimSpace(os.Getenv("CBB_DEBUG"))
	return v != "0"
}
