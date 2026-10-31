// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// forwarderRules (W30): the hub registers with the forwarder under its
// period's credential; a member that is no hub and no admin cannot take
// the hub's place, and the hub's registration stays.
func forwarderRules(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W30-forwarder/"
	a := newAwayGroup(ctx, r, f, "fleet/W30-forwarder", 2)
	if a == nil {
		return
	}
	m := a.members[1]
	r.Do(p+"member-not-hub-setup", func() error {
		if err := a.in.publish(ctx, hubPublic2, m); err != nil {
			return err
		}
		_, err := Run(ctx, m, "cbb global on", "yes\n")
		return err
	})
	// The member's own command refuses, and says what to do.
	fails(ctx, r, p+"member-not-hub", m, errorCase{cmd: a.hubCmd(hubPublic2, a.fwdKey), want: []string{"only the group's root or an admin can be its hub"}})
	r.Do(p+"hub-kept", func() error {
		// Whatever the member tried, the forwarder keeps the hub, and the
		// member never registers.
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if out, _ := Run(ctx, m, "cbb global", ""); strings.Contains(out, "Registered with the forwarder") {
				return fmt.Errorf("the member %s registered with the forwarder: %s", m.Name, strings.Join(strings.Fields(out), " "))
			}
			if err := globalShows(ctx, a.hub, "Registered with the forwarder at "+fwdPublic, 5*time.Second); err != nil {
				return err
			}
			time.Sleep(2 * time.Second)
		}
		return nil
	})
}
