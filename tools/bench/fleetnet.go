// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// syncs copies a text on from and waits for it on to.
func syncs(ctx context.Context, g *benchGroup, from, to *Device, what string, timeout time.Duration) error {
	text := "cbb-bench " + g.run + " " + what
	if err := Copy(ctx, from, text); err != nil {
		return err
	}
	return arrives(ctx, to, text, timeout)
}

// joinPaths (G4, D7, D8): joining by address; a network of carrier-grade
// NAT only with CBB_HOME_CGNAT=1; a public network never; only IPv6.
func joinPaths(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G4-paths/"
	g := fleetGroup(ctx, r, f, "fleet/G4-address", 2)
	if g != nil && len(g.members) == 2 {
		r.Do(p+"by-address", func() error {
			d, err := f.Add(ctx)
			if err != nil {
				return err
			}
			ip, err := fleetIP(ctx, g.hub)
			if err != nil {
				return err
			}
			hub := *g.hub
			hub.Address = net.JoinHostPort(ip, "8764")
			if _, err := pairOne(ctx, &hub, d); err != nil {
				return err
			}
			if err := setMode(ctx, d, "shared"); err != nil {
				return err
			}
			return syncs(ctx, g, d, g.members[1], "joined by address", timeout)
		})
	}

	// refusedOn makes a group on a new network of the subnet and checks
	// that a second member cannot join it.
	refusedOn := func(name string, args ...string) {
		var n string
		if r.Do(p+name+"/network", func() error {
			var err error
			n, err = f.Network(ctx, args...)
			return err
		}) != nil {
			return
		}
		r.Do(p+name+"/refused", func() error {
			ds := make([]*Device, 2)
			for i := range ds {
				var err error
				if ds[i], err = f.AddOn(ctx, n); err != nil {
					return err
				}
			}
			if _, err := Run(ctx, ds[0], "cbb new", ""); err != nil {
				return err
			}
			ip, err := fleetIP(ctx, ds[0])
			if err != nil {
				return err
			}
			hub := *ds[0]
			hub.Address = net.JoinHostPort(ip, "8764")
			_, err = pairOne(ctx, &hub, ds[1])
			var re *RunError
			switch {
			case err == nil:
				return errors.New("a member joined on a network that is not a home network")
			case !errors.As(err, &re):
				return err
			case !strings.Contains(re.Output, "outside the home network"):
				return fmt.Errorf("refused with %q, not outside the home network", strings.TrimSpace(re.Output))
			}
			if tag, _ := groupOf(ctx, ds[1]); tag != "" {
				return fmt.Errorf("%s is in group %s", ds[1].Name, tag)
			}
			return nil
		})
	}
	// D7: public addresses (a documentation range stands for one).
	refusedOn("D7-public", "--subnet", "203.0.113.0/24")
	// G4: carrier-grade NAT is not home unless the setting says so.
	refusedOn("cgnat-off", "--subnet", "100.64.77.0/24")
	r.Do(p+"cgnat-on", func() error {
		n, err := f.Network(ctx, "--subnet", "100.64.78.0/24")
		if err != nil {
			return err
		}
		cg := fleetGroupOn(ctx, r, f, n, "fleet/G4-cgnat", 2, "CBB_HOME_CGNAT=1")
		if cg == nil || len(cg.members) < 2 {
			return errors.New("no group on 100.64.0.0/10 with CBB_HOME_CGNAT=1")
		}
		return syncs(ctx, cg, cg.members[1], cg.members[0], "over carrier-grade NAT", timeout)
	})
	// D8: only IPv6 between the members.
	if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
		r.Skip("fleet/D8-ipv6-only", "the controller's kernel has no IPv6")
		return
	}
	r.Do("fleet/D8-ipv6-only", func() error {
		n, err := f.Network(ctx, "--ipv6", "--ipv4=false", "--subnet", "fd00:cbb:77::/64")
		if err != nil {
			return err
		}
		v6 := fleetGroupOn(ctx, r, f, n, "fleet/D8-ipv6", 3)
		if v6 == nil || len(v6.members) < 3 {
			return errors.New("no group on a network with only IPv6")
		}
		if err := syncs(ctx, v6, v6.members[1], v6.members[2], "over IPv6 only", timeout); err != nil {
			return err
		}
		out, err := Run(ctx, v6.members[1], "ip -4 addr show scope global", "")
		if err == nil && strings.Contains(out, "inet ") {
			err = fmt.Errorf("the member has an IPv4 address: %s", out)
		}
		return err
	})
}
