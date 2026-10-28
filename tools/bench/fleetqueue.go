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

// servicePID is the process ID of d's cbb service.
func servicePID(ctx context.Context, d *Device) (string, error) {
	out, err := Run(ctx, d, `for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = cbb ] && tr '\0' ' ' <$p/cmdline | grep -q 'cbb service' && echo ${p#/proc/}; done; true`, "")
	if err != nil {
		return "", err
	}
	if f := strings.Fields(out); len(f) == 1 {
		return f[0], nil
	}
	return "", fmt.Errorf("%s runs %d cbb services", d.Name, len(strings.Fields(out)))
}

// floodScript opens n TCP connections to addr that send nothing, waits a
// second, and prints how many the far side closed and how many are still
// open; it then holds the open ones for hold seconds.
func floodScript(addr string, n, hold int) string {
	host, port, _ := strings.Cut(addr, ":")
	return fmt.Sprintf(`fds=""
for i in $(seq 1 %d); do exec {fd}<>/dev/tcp/%s/%s || exit 1; fds="$fds $fd"; done
sleep 1
closed=0; open=0
for fd in $fds; do if read -t 0.2 -u $fd x; then closed=$((closed+1)); else rc=$?; if [ $rc -gt 128 ]; then open=$((open+1)); else closed=$((closed+1)); fi; fi; done
echo "closed $closed open $open"
sleep %d`, n, host, port, hold)
}

// handshakeSlots (D13): at most 32 connections to the member port wait for
// their handshake at once; the 33rd is closed, the members already
// connected keep syncing, and once the idle ones time out a member
// connects again. A service out of file descriptors pauses accepting and
// recovers once some are free.
func handshakeSlots(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D13-handshakes/"
	g := fleetGroup(ctx, r, f, "fleet/D13-handshakes", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	a, b := g.members[0], g.members[1]
	var addr string
	if r.Do(p+"connected", func() error {
		ip, err := fleetIP(ctx, a)
		addr = ip + ":8764"
		if err != nil {
			return err
		}
		return syncs(ctx, g, a, b, "before", timeout)
	}) != nil {
		return
	}
	r.Do("fleet/D13-33rd-closed", func() error {
		out, err := RunFor(ctx, b, "bash", floodScript(addr, 40, 0), time.Minute)
		if err != nil {
			return err
		}
		var closed, open int
		if _, err := fmt.Sscanf(strings.TrimSpace(out), "closed %d open %d", &closed, &open); err != nil {
			return fmt.Errorf("the flood printed %q", out)
		}
		if open != 32 || closed != 8 {
			return fmt.Errorf("of 40 idle connections %s kept %d and closed %d, not 32 and 8", a.Name, open, closed)
		}
		return nil
	})
	r.Do("fleet/D13-members-sync-during-flood", func() error {
		done := make(chan error, 1)
		go func() {
			_, err := RunFor(ctx, b, "bash", floodScript(addr, 40, 8), time.Minute)
			done <- err
		}()
		time.Sleep(2 * time.Second)
		err := syncs(ctx, g, a, b, "while the member port is full", timeout)
		if ferr := <-done; err == nil {
			err = ferr
		}
		return err
	})
	r.Do("fleet/D13-member-connects-after", func() error {
		// The idle connections time out after 10 seconds; a restarted
		// member then connects again.
		if err := signalService(ctx, b, "KILL"); err != nil {
			return err
		}
		return syncs(ctx, g, a, b, "after the flood", 2*timeout)
	})
	r.Do("fleet/D13-out-of-descriptors", func() error {
		pid, err := servicePID(ctx, a)
		if err != nil {
			return err
		}
		out, err := Run(ctx, a, "ls /proc/"+pid+"/fd | wc -l; prlimit --nofile --output SOFT,HARD --noheadings --pid "+pid, "")
		if err != nil {
			return err
		}
		f := strings.Fields(out)
		if len(f) != 3 {
			return fmt.Errorf("prlimit printed %q", out)
		}
		var used int
		fmt.Sscan(f[0], &used)
		// Below what it holds, so that no descriptor it closes meanwhile
		// leaves room for another: accepting fails.
		if _, err := Run(ctx, a, fmt.Sprintf("prlimit --pid %s --nofile=%d:%s", pid, used-2, f[2]), ""); err != nil {
			return err
		}
		restore := func() {
			Run(context.WithoutCancel(ctx), a, fmt.Sprintf("prlimit --pid %s --nofile=%s:%s", pid, f[1], f[2]), "")
		}
		defer restore()
		flood, err := RunFor(ctx, b, "bash", floodScript(addr, 20, 2), time.Minute)
		if err != nil {
			return err
		}
		logs, err := docker(ctx, "logs", "--tail", "200", a.Container)
		if err != nil {
			return err
		}
		if !strings.Contains(logs, "too many open files") {
			return fmt.Errorf("%s did not log running out of file descriptors (flood: %s)", a.Name, strings.TrimSpace(flood))
		}
		restore()
		if err := signalService(ctx, b, "KILL"); err != nil {
			return err
		}
		return syncs(ctx, g, a, b, "after running out of file descriptors", 2*timeout)
	})
}
