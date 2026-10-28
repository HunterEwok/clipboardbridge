// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// signalService sends sig to d's cbb service, not to the container's loop
// that starts it again.
func signalService(ctx context.Context, d *Device, sig string) error {
	_, err := Run(ctx, d, strings.ReplaceAll(fleetKill, "-KILL", "-"+sig), "")
	return err
}

// slowPeer (D14): a member whose peer stops reading fills the peer's queue
// of 256 messages and closes the connection, rather than holding every
// copy it makes; the peer, back, catches up from its next hello with the
// latest copy.
func slowPeer(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D14-queue/"
	g := fleetGroup(ctx, r, f, "fleet/D14-queue", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	a, b := g.members[0], g.members[1]
	if r.Do(p+"connected", func() error {
		return syncs(ctx, g, a, b, "before", timeout)
	}) != nil {
		return
	}
	r.Do("fleet/D14-slow-peer-closed", func() error {
		if err := signalService(ctx, b, "STOP"); err != nil {
			return err
		}
		defer signalService(context.WithoutCancel(ctx), b, "CONT")
		// Copies of 60 KB each fill the socket's buffers first and then
		// the queue; a frozen peer answers no heartbeat either, so the
		// copies come faster than its timeout.
		copies := `for i in $(seq 1 600); do head -c 45000 /dev/urandom | base64 -w0 | cbb copy || exit 1; done`
		if _, err := RunFor(ctx, a, copies, "", 3*time.Minute); err != nil {
			return err
		}
		return eventually(ctx, 30*time.Second, func() error {
			logs, err := docker(ctx, "logs", a.Container)
			if err != nil {
				return err
			}
			if !strings.Contains(logs, "is too slow; closing the connection") {
				return fmt.Errorf("%s did not close the connection to %s, which stopped reading", a.Name, b.Name)
			}
			return nil
		})
	})
	r.Do("fleet/D14-catches-up", func() error {
		if err := signalService(ctx, b, "CONT"); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " after the queue was full"
		if err := Copy(ctx, a, text); err != nil {
			return err
		}
		return arrives(ctx, b, text, 2*timeout)
	})
}
