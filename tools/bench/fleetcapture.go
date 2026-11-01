// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// countStrings adds a chain named chain to d's table and hooks it into
// hooks, counting the packets that match filter and carry one of words in
// the clear (iptables' string match, as a capture searched for them).
func countStrings(ctx context.Context, d *Device, chain, filter string, hooks []string, words []string) error {
	cmds := []string{"iptables -N " + chain}
	for _, w := range words {
		cmds = append(cmds, fmt.Sprintf("iptables -A %s %s -m string --algo bm --string %q", chain, filter, w))
	}
	for _, h := range hooks {
		cmds = append(cmds, "iptables -I "+h+" -j "+chain)
	}
	_, err := Run(ctx, d, strings.Join(cmds, " && "), "")
	return err
}

// stringsSeen returns, for each word countStrings counts in chain, the
// packets that carried it.
func stringsSeen(ctx context.Context, d *Device, chain string, words []string) (map[string]int, error) {
	out, err := Run(ctx, d, "iptables -L "+chain+" -v -x -n", "")
	if err != nil {
		return nil, err
	}
	seen := map[string]int{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		for _, w := range words {
			if strings.Contains(l, fmt.Sprintf("STRING match  %q", w)) || strings.Contains(l, "\""+w+"\"") {
				seen[w] += n
			}
		}
	}
	return seen, nil
}

// leaks is an error naming each word seen in packets, or nil.
func leaks(where string, seen map[string]int) error {
	var hits []string
	for w, n := range seen {
		if n > 0 {
			hits = append(hits, fmt.Sprintf("%q in %d packets", w, n))
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return fmt.Errorf("%s carried in the clear: %s", where, strings.Join(hits, ", "))
}

// canary is sent in the clear past each counter, so that a count of none
// shows that nothing else carried a word, not that the counter saw nothing.
const canary = "cbb-bench-canary"

// captures (S1, S2): what someone watching the wire learns. On the
// internet's router between an away client and the group's servers, no
// packet carries the copied text, the run's marker, the group's tag or a
// device ID in the clear, and the client sends nothing to anyone but the
// hub and the forwarder. At home, member connections speak only TLS 1.3
// and carry no copied text in the clear; the device IDs and the group's
// tag are public there by design (mDNS names them, and the TLS server
// name is cb-<ID>.local), so only the run's marker is looked for.
func captures(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/S1-internet-path/"
	a := newAwayGroup(ctx, r, f, "fleet/S1-internet-path", 2)
	if a == nil {
		return
	}
	hub, home := a.hub, a.members[1]
	var words []string
	if r.Do(p+"setup", func() error {
		_, tag, err := statusIDs(ctx, hub)
		if err != nil {
			return err
		}
		words = append(words, a.run, tag)
		for _, d := range []*Device{hub, home} {
			id, _, err := statusIDs(ctx, d)
			if err != nil {
				return err
			}
			words = append(words, id)
		}
		if err := countStrings(ctx, a.in.router, "cbbleak", "", []string{"FORWARD"}, append(words, canary)); err != nil {
			return err
		}
		return countStrings(ctx, home, "cbbleak", "-p tcp -m multiport --ports 8764", []string{"INPUT", "OUTPUT"}, []string{a.run, canary})
	}) != nil {
		return
	}
	c := a.join(ctx, r, p+"invited")
	if c == nil {
		return
	}
	if r.Do(p+"syncs", func() error {
		id, _, err := statusIDs(ctx, c)
		if err != nil {
			return err
		}
		if err := countStrings(ctx, a.in.router, "cbbleak2", "", []string{"FORWARD"}, []string{id}); err != nil {
			return err
		}
		if err := watchOut(ctx, c); err != nil {
			return err
		}
		if err := connected(ctx, c, 3*time.Minute); err != nil {
			return err
		}
		for i, pair := range [][2]*Device{{hub, c}, {c, hub}, {home, c}, {c, home}, {hub, home}} {
			if err := syncs(ctx, a.benchGroup, pair[0], pair[1], fmt.Sprintf("watched %d", i), 2*timeout); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	r.Do(p+"nothing-in-clear", func() error {
		// The canary to the hub's WireGuard port, which drops it.
		if _, err := Run(ctx, c, "bash -c 'echo "+canary+" > /dev/udp/"+hubPublic+"/51820'", ""); err != nil {
			return err
		}
		seen, err := stringsSeen(ctx, a.in.router, "cbbleak", append(words, canary))
		if err != nil {
			return err
		}
		if seen[canary] == 0 {
			return fmt.Errorf("the internet's router did not count the canary sent in the clear; the counters see nothing")
		}
		delete(seen, canary)
		if err := leaks("the internet's router saw packets that", seen); err != nil {
			return err
		}
		id, _, _ := statusIDs(ctx, c)
		seen, err = stringsSeen(ctx, a.in.router, "cbbleak2", []string{id})
		if err != nil {
			return err
		}
		if err := leaks("the internet's router saw packets that", seen); err != nil {
			return err
		}
		n, err := outElsewhere(ctx, c)
		if err == nil && n > 0 {
			err = fmt.Errorf("the away client sent %d packets to neither the hub nor the forwarder", n)
		}
		return err
	})
	r.Do("fleet/S2-lan", func() error {
		ip, err := fleetIP(ctx, home)
		if err != nil {
			return err
		}
		id, _, err := statusIDs(ctx, home)
		if err != nil {
			return err
		}
		addr := ip + ":8764 -servername cb-" + id + ".local -alpn clipboardbridge/1"
		if out, _ := runOut(ctx, hub, "openssl s_client -tls1_2 -connect "+addr+" </dev/null 2>&1", time.Minute); !strings.Contains(out, "alert protocol version") {
			return fmt.Errorf("the member port at home did not refuse TLS 1.2 by its version: %q", out)
		}
		if out, _ := runOut(ctx, hub, "openssl s_client -tls1_3 -connect "+addr+" </dev/null 2>&1", time.Minute); !strings.Contains(out, "New, TLSv1.3,") {
			return fmt.Errorf("the member port at home does not speak TLS 1.3: %q", out)
		}
		// The canary in the clear to the member port, which drops it.
		if _, err := Run(ctx, hub, "bash -c 'exec 3<>/dev/tcp/"+ip+"/8764; echo "+canary+" >&3; sleep 1'", ""); err != nil {
			return err
		}
		seen, err := stringsSeen(ctx, home, "cbbleak", []string{a.run, canary})
		if err != nil {
			return err
		}
		if seen[canary] == 0 {
			return fmt.Errorf("the member at home did not count the canary sent in the clear; the counters see nothing")
		}
		delete(seen, canary)
		return leaks("member connections at home", seen)
	})
}
