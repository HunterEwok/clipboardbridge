// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// isSecret tells whether d's clipboard for the group holds a secret: cbb
// paste -terminal refuses one without -secret.
func isSecret(ctx context.Context, d *Device, text string) (bool, error) {
	out, err := runOut(ctx, d, "cbb paste -terminal", time.Minute)
	switch {
	case err != nil && strings.Contains(out, "the clipboard holds a secret"):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
	case strings.TrimSpace(out) == text:
		return false, nil
	}
	return false, fmt.Errorf("%s pastes %q, not %q", d.Name, out, text)
}

// secretMemory (Y34, the fleet's part): a text sent as a secret stays a
// secret, on the sender and the receiver, when it is sent again without
// the mark; the sender remembers 4096 secrets, so after 4096 more the
// first is a plain text again while the next, and the last, are still
// secrets. The 12
// hours the memory lasts are internal/clip's TestSecrets.
func secretMemory(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/Y34-secret-memory/"
	g := fleetGroup(ctx, r, f, "fleet/Y34-secret-memory", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	a, b := g.members[0], g.members[1]
	first := "cbb-bench " + g.run + " secret 0"
	// copy sends text from a, as a secret with -secret, and waits until
	// cbb paste on each of on gives secret.
	copyAs := func(text, flags string, secret bool, on ...*Device) error {
		if _, err := Run(ctx, a, "cbb copy "+flags, text); err != nil {
			return err
		}
		for _, d := range on {
			if err := eventually(ctx, timeout, func() error {
				got, err := isSecret(ctx, d, text)
				if err == nil && got != secret {
					err = fmt.Errorf("on %s, %q is a secret: %v, want %v", d.Name, text, got, secret)
				}
				return err
			}); err != nil {
				return err
			}
		}
		return nil
	}
	r.Do(p+"stays-secret", func() error {
		// A secret reaches only members connected when it is copied (a
		// hello carries it as a mark alone), so the two connect first.
		if err := syncs(ctx, g, a, b, "before the secrets", timeout); err != nil {
			return err
		}
		if err := copyAs(first, "-secret", true, a, b); err != nil {
			return fmt.Errorf("sent as a secret: %w", err)
		}
		if err := copyAs("cbb-bench "+g.run+" plain", "", false, a, b); err != nil {
			return fmt.Errorf("a plain text after it: %w", err)
		}
		if err := copyAs(first, "", true, a, b); err != nil {
			return fmt.Errorf("sent again without the mark: %w", err)
		}
		return nil
	})
	r.Do(p+"holds-4096", func() error {
		// 4096 more secrets, all different, in one go on a.
		loop := fmt.Sprintf("for i in $(seq 1 4096); do printf 'cbb-bench %s secret %%s' $i | cbb copy -secret || exit 1; done", g.run)
		if _, err := RunFor(ctx, a, loop, "", 15*time.Minute); err != nil {
			return err
		}
		if err := copyAs(first, "", false, a); err != nil {
			return fmt.Errorf("the oldest of 4097 secrets: %w", err)
		}
		// The oldest kept, and so every later one, is still a secret.
		for _, i := range []int{1, 4096} {
			if err := copyAs(fmt.Sprintf("cbb-bench %s secret %d", g.run, i), "", true, a); err != nil {
				return err
			}
		}
		return nil
	})
}
