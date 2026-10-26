// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package actions

import (
	"context"
	"time"
)

// A Runner carries out the presets on this system; the service restarts
// itself. An error that is a *Refusal is a reason not to run it, for the
// sender; any other is a failure.
type Runner interface {
	Run(ctx context.Context, name string) error
}

// ScheduleDelay is how long a reboot or shutdown waits, so that a mistaken
// tap can be cancelled (cancel-shutdown) and the users logged in are told.
const ScheduleDelay = time.Minute
