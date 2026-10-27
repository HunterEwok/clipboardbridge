// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The time-scaled build (`go build -tags benchtime`, internal/benchtime)
// runs every long time of the product benchScale times faster: a member
// certificate lasts about ten minutes and is renewed in its last three and
// a half, a credential period lasts half a minute. The time suite runs that
// build in the fleet (docs/testbench-catalogue.md, section 0.1, "time").
const benchScale = 100000

// scaled is d as the time-scaled build runs it.
func scaled(d time.Duration) time.Duration { return d / benchScale }

// TimeSuite runs the cases that wait for certificates and credential
// periods to end, on fleet members of the time-scaled build cbb.
func TimeSuite(ctx context.Context, r *Report, cbb string, timeout time.Duration) {
	cleanFleet(ctx)
	var f *Fleet
	if r.Do("time/setup", func() error {
		var err error
		if f, err = NewFleet(ctx, cbb); err != nil {
			return err
		}
		out, err := exec1(ctx, f.cbb, "version")
		if err == nil && !strings.Contains(out, "time-scaled") {
			err = fmt.Errorf("%s is not the time-scaled build (go build -tags benchtime): %s", cbb, firstLine(out))
		}
		return err
	}) != nil {
		if f != nil {
			f.Close(ctx)
		}
		return
	}
	defer f.Close(ctx)

	// Both groups start now, so that their certificates age together: in
	// the second the root is away through the member's renewal window.
	renewed := fleetGroup(ctx, r, f, "time/K1-renewal", 3)
	lapsed := fleetGroup(ctx, r, f, "time/K4-lapse", 2)
	if lapsed != nil {
		r.Do("time/K4-lapse/root-away", func() error { return f.stop(ctx, lapsed.hub) })
	}
	if renewed != nil {
		renewal(ctx, r, renewed, timeout)
		periods(ctx, r, renewed)
	}
	if lapsed != nil {
		lapse(ctx, r, f, lapsed, timeout)
	}
}

// exec1 runs a program on the controller.
func exec1(ctx context.Context, name string, args ...string) (string, error) {
	return docker(ctx, append([]string{"run", "--rm", "-v", name + ":/cbb:ro", fleetImage, "/cbb"}, args...)...)
}

// memberCert reads a fleet member's member certificate from its state.
func memberCert(ctx context.Context, d *Device) (*x509.Certificate, error) {
	out, err := Run(ctx, d, "cat /var/lib/clipboardbridge/identity.json", "")
	if err != nil {
		return nil, err
	}
	var f struct {
		Cert []byte `json:"cert"`
	}
	if err := json.Unmarshal([]byte(out), &f); err != nil {
		return nil, fmt.Errorf("%s: identity.json: %w", d.Name, err)
	}
	return x509.ParseCertificate(f.Cert)
}

// renewal (K1, K7): the root renews the members' certificates in their
// renewal window over connections that stay up, and its own; the group
// keeps syncing across it.
func renewal(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	const p = "time/K1-renewal/"
	first := map[string]time.Time{}
	if r.Do(p+"certificates", func() error {
		for _, m := range g.members {
			c, err := memberCert(ctx, m)
			if err != nil {
				return err
			}
			first[m.Name] = c.NotAfter
		}
		return nil
	}) != nil {
		return
	}
	// A member certificate lasts two scaled years and is renewed when less
	// than 240 scaled days remain.
	life := scaled(2 * 365 * 24 * time.Hour)
	for _, m := range g.members {
		r.Do(p+"renewed/"+m.Name, func() error {
			return eventually(ctx, life, func() error {
				c, err := memberCert(ctx, m)
				if err != nil {
					return err
				}
				if !c.NotAfter.After(first[m.Name]) {
					return fmt.Errorf("%s still has its certificate until %s", m.Name, c.NotAfter.Format(time.TimeOnly))
				}
				return nil
			})
		})
	}
	r.Do(p+"K7-still-syncing", func() error {
		text := "cbb-bench " + g.run + " after the renewal"
		if err := Copy(ctx, g.members[1], text); err != nil {
			return err
		}
		for _, m := range []*Device{g.members[0], g.members[2]} {
			if err := arrives(ctx, m, text, timeout); err != nil {
				return err
			}
		}
		return nil
	})
}

// periods (W39): the root starts a new credential period when the last is
// 30 scaled days old, and every member takes it.
func periods(ctx context.Context, r *Report, g *benchGroup) {
	const p = "time/W39-periods/"
	sum := func(d *Device) (string, error) {
		out, err := Run(ctx, d, "cat /var/lib/clipboardbridge/credentials.json", "")
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(out) == "" {
			return "", fmt.Errorf("%s keeps no credentials", d.Name)
		}
		return fmt.Sprintf("%x", sha256.Sum256([]byte(out))), nil
	}
	before := map[string]string{}
	if r.Do(p+"credentials", func() error {
		for _, m := range g.members {
			s, err := sum(m)
			if err != nil {
				return err
			}
			before[m.Name] = s
		}
		return nil
	}) != nil {
		return
	}
	for _, m := range g.members {
		r.Do(p+"new-period/"+m.Name, func() error {
			return eventually(ctx, 3*scaled(35*24*time.Hour), func() error {
				s, err := sum(m)
				if err == nil && s == before[m.Name] {
					err = fmt.Errorf("%s keeps the same credentials", m.Name)
				}
				return err
			})
		})
	}
}

// lapse (K4): the member's certificate ends while no admin is on; it can
// no longer connect, says so, and pairs again.
func lapse(ctx context.Context, r *Report, f *Fleet, g *benchGroup, timeout time.Duration) {
	const p = "time/K4-lapse/"
	m := g.members[1]
	var end time.Time
	if r.Do(p+"certificate", func() error {
		c, err := memberCert(ctx, m)
		end = c.NotAfter
		return err
	}) != nil {
		return
	}
	if wait := time.Until(end) + 5*time.Second; wait > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
	r.Do(p+"root-back", func() error { return f.start(ctx, g.hub) })
	r.Do(p+"refused", func() error {
		time.Sleep(timeout)
		out, err := Run(ctx, m, "cbb status", "")
		if err == nil && !strings.Contains(out, "certificate ended on") {
			err = fmt.Errorf("%s does not say that its certificate ended: %q", m.Name, out)
		}
		return err
	})
	r.Do(p+"pairs-again", func() error {
		id, err := deviceOf(ctx, m)
		if err != nil {
			return err
		}
		if _, err := Run(ctx, g.hub, "cbb revoke "+id, ""); err != nil {
			return err
		}
		if _, err := Run(ctx, m, "rm -rf /var/lib/clipboardbridge/*", ""); err != nil {
			return err
		}
		if _, err := docker(ctx, "restart", "-t", "1", m.Container); err != nil {
			return err
		}
		if err := eventually(ctx, 20*time.Second, func() error {
			_, err := Run(ctx, m, "cbb status", "")
			return err
		}); err != nil {
			return err
		}
		if _, err := pairOne(ctx, g.hub, m); err != nil {
			return err
		}
		if err := setMode(ctx, m, "shared"); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " after pairing again"
		if err := Copy(ctx, g.hub, text); err != nil {
			return err
		}
		return arrives(ctx, m, text, timeout)
	})
}
