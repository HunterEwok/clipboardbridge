// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// routerMemory is the memory of the fleet's router: the container's cap,
// and the soft limit the OpenWrt package gives the service.
const (
	routerCap      = "160m"
	routerMemLimit = "GOMEMLIMIT=64MiB"
)

// cgroupOOM is the number of processes the container's memory cap killed,
// and its memory's peak in bytes (0 where the kernel does not keep it),
// from its cgroup.
func cgroupOOM(ctx context.Context, d *Device) (kills int, peak int64, err error) {
	// cgroup v2, or v1's memory controller.
	out, err := Run(ctx, d, `c=/sys/fs/cgroup; if [ -f $c/memory.events ]; then sed -n 's/^oom_kill //p' $c/memory.events; cat $c/memory.peak 2>/dev/null || echo 0; else sed -n 's/^oom_kill //p' $c/memory/memory.oom_control; cat $c/memory/memory.max_usage_in_bytes; fi`, "")
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		return 0, 0, fmt.Errorf("the cgroup of %s gave %q, not its OOM kills and peak", d.Name, out)
	}
	kills, err = strconv.Atoi(f[0])
	if err == nil {
		peak, err = strconv.ParseInt(f[1], 10, 64)
	}
	return kills, peak, err
}

// routerMedia (O14, the fleet's part): a member with a router's memory (the
// container capped at 160 MiB, GOMEMLIMIT as the OpenWrt package sets it)
// takes a 90 MiB file and passes it on to a member that reaches only it,
// without running out of memory: the parts go through its cache on disk.
func routerMedia(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/O14-router/"
	ds := make([]*Device, 3)
	if r.Do(p+"start", func() error {
		errs := make([]error, 3)
		var wg sync.WaitGroup
		for i := range ds {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if i == 1 {
					ds[i], errs[i] = f.AddWith(ctx, f.net, []string{"--memory", routerCap, "--memory-swap", routerCap}, routerMemLimit)
				} else {
					ds[i], errs[i] = f.Add(ctx)
				}
			}()
		}
		wg.Wait()
		return errors.Join(errs...)
	}) != nil {
		return
	}
	ds[0].Roles = []string{"member", "hub"}
	g := formGroup(ctx, r, "fleet/O14-router", ds)
	if g == nil || len(g.members) != 3 {
		return
	}
	src, rt, dst := ds[0], ds[1], ds[2]
	var pid, sum string
	r.Do(p+"passes-on", func() error {
		var err error
		if pid, err = Run(ctx, rt, "pgrep -o -f 'cbb service'", ""); err != nil {
			return err
		}
		// dst reaches only the router.
		if err := cut(ctx, dst, src); err != nil {
			return err
		}
		defer heal(context.WithoutCancel(ctx), dst, src)
		if _, err := RunFor(ctx, src, "mkdir -p /tmp/o14 && head -c 94371840 /dev/urandom >/tmp/o14/big", "", time.Minute); err != nil {
			return err
		}
		if sum, err = Run(ctx, src, "sha256sum </tmp/o14/big", ""); err != nil {
			return err
		}
		if _, err := RunFor(ctx, src, "cbb copy /tmp/o14/big", "", time.Minute); err != nil {
			return err
		}
		return eventually(ctx, 5*time.Minute, func() error {
			if err := pasteInto(ctx, dst, "/tmp/o14", 2*time.Minute); err != nil {
				return err
			}
			got, err := Run(ctx, dst, "sha256sum </tmp/o14/big", "")
			if err == nil && got != sum {
				err = fmt.Errorf("%s saved another file than %s copied", dst.Name, src.Name)
			}
			return err
		})
	})
	r.Do(p+"memory", func() error {
		kills, peak, err := cgroupOOM(ctx, rt)
		if err != nil {
			return err
		}
		r.Note(p+"memory", fmt.Sprintf("the router's memory peaked at %d MiB of its %s", peak>>20, routerCap))
		if kills > 0 {
			return fmt.Errorf("the memory cap killed %d processes on the router", kills)
		}
		now, err := Run(ctx, rt, "pgrep -o -f 'cbb service'", "")
		if err != nil {
			return err
		}
		if pid != "" && now != pid {
			return fmt.Errorf("the router's service restarted (pid %s, then %s)", strings.TrimSpace(pid), strings.TrimSpace(now))
		}
		return nil
	})
}
