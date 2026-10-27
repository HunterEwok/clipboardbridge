// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build benchtime

package benchtime

import (
	"fmt"
	"os"
	"time"
)

// Scale is how many times faster long times run in the time-scaled build.
const Scale = 100000

// offset is what CBB_TEST_CLOCK adds to the wall clock.
var offset = func() time.Duration {
	d, err := parseClock(os.Getenv("CBB_TEST_CLOCK"), time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return d
}()
