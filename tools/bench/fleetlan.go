// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// dialBack (D11): a member whose firewall drops connections to its member
// port still syncs, because the others connect to it no longer but it
// connects to them; cbb status on it names who could not connect and what
// to allow.
func dialBack(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D11-dial-back/"
	g := fleetGroup(ctx, r, f, "fleet/D11-dial-back", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	walled := g.members[2]
	defer heal(ctx, walled)
	if r.Do(p+"firewall", func() error {
		// New connections to the member port are dropped; the service is
		// started again so that no connection from before is left.
		if _, err := Run(ctx, walled, "iptables -A INPUT -p tcp --dport 8764 --syn -j DROP", ""); err != nil {
			return err
		}
		_, err := Run(ctx, walled, fleetKill, "")
		return err
	}) != nil {
		return
	}
	for i, from := range []*Device{walled, g.hub, walled, g.members[1]} {
		to := g.hub
		if from != walled {
			to = walled
		}
		r.Do(fmt.Sprintf("%ssyncs-%d-%s-to-%s", p, i, from.Name, to.Name), func() error {
			return eventually(ctx, time.Minute, func() error {
				return syncs(ctx, g, from, to, fmt.Sprintf("dial-back %d", i), timeout)
			})
		})
	}
	r.Do(p+"status-warns", func() error {
		return eventually(ctx, 2*time.Minute, func() error {
			out, err := Run(ctx, walled, "cbb status", "")
			if err != nil {
				return err
			}
			for _, want := range []string{"could not connect to this device; they sync only because this device connects to them", "Allow TCP 8764 and UDP 5353"} {
				if !strings.Contains(out, want) {
					return fmt.Errorf("cbb status on %s does not warn %q:\n%s", walled.Name, want, out)
				}
			}
			for _, d := range g.members[:2] {
				if !strings.Contains(out, d.Name) {
					return fmt.Errorf("cbb status on %s does not name %s", walled.Name, d.Name)
				}
			}
			return nil
		})
	})
	r.Do(p+"others-quiet", func() error {
		// Only the member behind the firewall is told.
		out, err := Run(ctx, g.hub, "cbb status", "")
		if err == nil && strings.Contains(out, "could not connect to this device") {
			err = fmt.Errorf("cbb status on %s warns too:\n%s", g.hub.Name, out)
		}
		return err
	})
}

var (
	hexIDRE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	txtItemRE = regexp.MustCompile(`^(v=1|g=[0-9a-f]{16}|h=[12]|p=1)$`)
)

// stranger (S21): a device on the LAN that is in no group learns from the
// members' mDNS records only random device IDs, the port and the TXT
// strings of the protocol (the group's tag in g= among them), and from
// their member port, which it may connect to, no name of a device and no
// tag.
func stranger(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/S21-stranger/"
	g := fleetGroup(ctx, r, f, "fleet/S21-stranger", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	var browser *Device
	if r.Do(p+"browser", func() error {
		var err error
		browser, err = forgeServer(ctx, f, f.net, "-addr /tmp/mdns mdns-browse")
		return err
	}) != nil {
		return
	}
	// secrets is what a stranger must not see: the devices' names and,
	// outside the TXT g=, the group's tag.
	var names []string
	for _, d := range g.members {
		names = append(names, d.Name)
	}
	r.Do(p+"mdns", func() error {
		return eventually(ctx, 30*time.Second, func() error {
			out, err := Run(ctx, browser, "cat /tmp/mdns/peers 2>/dev/null; true", "")
			if err != nil {
				return err
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if len(lines) < len(g.members) {
				return fmt.Errorf("the browser finds %d members, not %d: %q", len(lines), len(g.members), out)
			}
			for _, l := range lines {
				f := strings.Fields(l)
				if len(f) < 3 || !hexIDRE.MatchString(f[0]) || f[1] != "8764" {
					return fmt.Errorf("a record that is not a random ID and the port: %q", l)
				}
				for _, item := range f[2:] {
					if !txtItemRE.MatchString(item) {
						return fmt.Errorf("a TXT string beyond the protocol's: %q in %q", item, l)
					}
				}
				for _, n := range names {
					if strings.Contains(l, n) {
						return fmt.Errorf("the record %q names %s", l, n)
					}
				}
			}
			return nil
		})
	})
	r.Do(p+"member-port", func() error {
		for _, d := range g.members {
			ip, err := fleetIP(ctx, d)
			if err != nil {
				return err
			}
			out, err := Run(ctx, browser, "cbbbench-forge tls-peek:"+ip+":8764", "")
			if err != nil {
				return err
			}
			for _, secret := range append([]string{g.tag}, names...) {
				if strings.Contains(out, secret) {
					return fmt.Errorf("the member port of %s shows a stranger %q:\n%s", d.Name, secret, out)
				}
			}
			fmt.Fprintf(r.out, "%s's member port shows a stranger: %s\n", d.Name, strings.ReplaceAll(strings.TrimSpace(out), "\n", "; "))
		}
		return nil
	})
	r.Do(p+"still-syncs", func() error {
		return syncs(ctx, g, g.members[1], g.members[2], "after a stranger looked", timeout)
	})
}
