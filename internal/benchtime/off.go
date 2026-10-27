// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !benchtime

package benchtime

// Scale is how many times faster long times run: 1, as in every release.
const Scale = 1

// offset is what CBB_TEST_CLOCK adds to the wall clock: nothing outside
// the time-scaled build.
const offset = 0
