// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build benchtime

package benchtime

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// enabled: this is the time-scaled build.
const enabled = true

// Scale is how many times faster long times run in the time-scaled build:
// 100000, or CBB_TEST_SCALE, such as 1 for cases that move only the clock.
var Scale = func() time.Duration {
	s := os.Getenv("CBB_TEST_SCALE")
	if s == "" {
		return 100000
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		fmt.Fprintf(os.Stderr, "benchtime: CBB_TEST_SCALE %q is not a whole number of 1 or more\n", s)
		os.Exit(2)
	}
	return time.Duration(n)
}()

// offset is what CBB_TEST_CLOCK adds to the wall clock. Without it, the
// file CBB_TEST_CLOCK_FILE names holds the value, if it exists, so the
// bench moves a member's clock with a restart of the service.
var offset = func() time.Duration {
	s := os.Getenv("CBB_TEST_CLOCK")
	if name := os.Getenv("CBB_TEST_CLOCK_FILE"); s == "" && name != "" {
		b, err := os.ReadFile(name)
		if err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "benchtime:", err)
			os.Exit(2)
		}
		s = string(b)
	}
	d, err := parseClock(s, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return d
}()
