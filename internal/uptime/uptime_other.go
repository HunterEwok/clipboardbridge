// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux && !darwin && !windows

package uptime

import "time"

var start = time.Now()

func now() time.Duration { return time.Since(start) }
