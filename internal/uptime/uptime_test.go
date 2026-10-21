// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package uptime

import (
	"testing"
	"time"
)

func TestNowAdvances(t *testing.T) {
	a := Now()
	time.Sleep(20 * time.Millisecond)
	b := Now()
	if d := b - a; d < 15*time.Millisecond || d > 5*time.Second {
		t.Errorf("Now advanced by %v over a 20 ms sleep", d)
	}
	if a <= 0 {
		t.Errorf("Now() = %v, want a positive duration", a)
	}
}

func TestNowCountsLikeGoAwake(t *testing.T) {
	// While the machine is awake, the clock runs at the speed of Go's
	// monotonic clock.
	u0, m0 := Now(), time.Now()
	time.Sleep(100 * time.Millisecond)
	du, dm := Now()-u0, time.Since(m0)
	if diff := du - dm; diff < -50*time.Millisecond || diff > 50*time.Millisecond {
		t.Errorf("uptime moved %v while Go's clock moved %v", du, dm)
	}
}
