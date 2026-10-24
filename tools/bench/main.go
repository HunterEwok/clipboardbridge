// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command bench runs the hardware test bench of docs/testbench.md: it drives
// real devices over SSH from the bench's controller and reports what passed.
//
//	go run ./tools/bench [-inventory FILE] [-report DIR] [-only a,b] check
//	go run ./tools/bench [-inventory FILE] [-report DIR] [-only a,b] smoke
//
// check only reaches every device and prints what it finds; smoke makes a
// group of the devices and sends one text from each device to all the
// others. The inventory lives on the controller, never in the repository
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
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: bench [flags] check|smoke|full")
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
