// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// disruptive (-disruptive) lets the desktop suite lock, put to sleep and
// restart the real computers (Q3, I18, H7, H8): only on the owner's word,
// since it leaves screens locked and takes the computers away for minutes.
var disruptive bool

// bootID names the device's current boot: it changes when it restarts.
func bootID(ctx context.Context, d *Device) (string, error) {
	var cmd string
	switch d.OS {
	case "windows":
		cmd = "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')"
	case "darwin":
		cmd = "sysctl -n kern.boottime"
	default:
		cmd = "cat /proc/sys/kernel/random/boot_id"
	}
	out, err := Run(ctx, d, cmd, "")
	return strings.TrimSpace(out), err
}

// armWake makes the device wake by itself after a while, for a sleep the
// bench starts; it returns false where the bench has no way to.
func armWake(ctx context.Context, d *Device, after time.Duration) (bool, error) {
	s := int(after.Seconds())
	switch d.OS {
	case "darwin":
		_, err := Run(ctx, d, fmt.Sprintf(`sudo -n pmset schedule wake "$(date -v+%dS '+%%m/%%d/%%Y %%H:%%M:%%S')"`, s), "")
		return err == nil, err
	case "linux":
		_, err := Run(ctx, d, fmt.Sprintf("sudo -n rtcwake -m no -s %d", s), "")
		return err == nil, err
	}
	return false, nil
}

// disruptiveCases runs on each computer, from the hub: the quick actions
// restart, lock, a reboot cancelled within its minute and a real one (Q3,
// H7's lock on Windows), a sleep that the bench wakes (I18), and on a Mac
// the application firewall on and blocking all (H8).
func disruptiveCases(ctx context.Context, r *Report, g *benchGroup, devices []*Device, timeout time.Duration) {
	if !disruptive {
		for _, id := range []string{"Q3-actions", "I18-sleep", "H7-windows", "H8-macos"} {
			r.Skip("desktop/"+id, "locks, sleeps and restarts the computers: only with -disruptive, on the owner's word")
		}
		return
	}
	hub := g.hub
	for _, d := range devices {
		p := "desktop/Q3-actions/" + d.Name
		action := func(name string) error {
			_, err := RunFor(ctx, hub, adminCmd(hub)+" action -on "+d.Name+" "+name, "", time.Minute)
			return err
		}
		if r.Do(p+"/enable", func() error {
			for _, a := range []string{"lock", "sleep", "reboot", "cancel-shutdown", "restart"} {
				if _, err := Run(ctx, d, adminCmd(d)+" action enable "+a+" -any-key -yes", ""); err != nil {
					return err
				}
			}
			return nil
		}) != nil {
			continue
		}
		defer Run(context.WithoutCancel(ctx), d, adminCmd(d)+" action off", "")
		r.Do(p+"/restart", func() error {
			if err := action("restart"); err != nil {
				return err
			}
			time.Sleep(10 * time.Second)
			return syncs(ctx, g, hub, d, "Q3 after a restart of the service", timeout+30*time.Second)
		})
		r.Do(p+"/lock", func() error {
			if err := action("lock"); err != nil {
				return err
			}
			if d.OS == "linux" {
				defer Run(context.WithoutCancel(ctx), d, "loginctl unlock-sessions 2>/dev/null || sudo -n loginctl unlock-sessions", "")
			}
			// Locked, the computer still takes the group's text.
			if err := syncs(ctx, g, hub, d, "Q3 on a locked screen", timeout); err != nil {
				return err
			}
			if d.OS == "windows" {
				r.Note(p+"/lock", "H7: Windows locked by the action and still syncing")
			}
			return nil
		})
		r.Do(p+"/reboot-cancelled", func() error {
			boot, err := bootID(ctx, d)
			if err != nil {
				return err
			}
			if err := action("reboot"); err != nil {
				return err
			}
			time.Sleep(10 * time.Second)
			if err := action("cancel-shutdown"); err != nil {
				return err
			}
			time.Sleep(90 * time.Second)
			now, err := bootID(ctx, d)
			if err != nil {
				return err
			}
			if now != boot {
				return fmt.Errorf("%s restarted although the reboot was cancelled", d.Name)
			}
			return nil
		})
		r.Do("desktop/I18-sleep/"+d.Name, func() error {
			ok, err := armWake(ctx, d, 2*time.Minute)
			if err != nil {
				return err
			}
			if !ok {
				return Skipped("no wake timer the bench sets on " + d.Name)
			}
			if err := action("sleep"); err != nil {
				return err
			}
			time.Sleep(3 * time.Minute)
			start := time.Now()
			if err := syncs(ctx, g, hub, d, "I18 after sleep and wake", 30*time.Second); err != nil {
				return err
			}
			r.Note("desktop/I18-sleep/"+d.Name, fmt.Sprintf("in sync %v after waking", time.Since(start).Round(time.Second)))
			return nil
		})
		if d == hub {
			continue
		}
		r.Do(p+"/reboot", func() error {
			boot, err := bootID(ctx, d)
			if err != nil {
				return err
			}
			if err := action("reboot"); err != nil {
				return err
			}
			if err := eventually(ctx, 6*time.Minute, func() error {
				now, err := bootID(ctx, d)
				if err == nil && now == boot {
					err = fmt.Errorf("%s has not restarted", d.Name)
				}
				return err
			}); err != nil {
				return err
			}
			return syncs(ctx, g, hub, d, "Q3 after a reboot", 2*time.Minute)
		})
	}
	for _, d := range devices {
		if d.OS != "darwin" {
			continue
		}
		p := "desktop/H8-macos/" + d.Name
		const fw = "sudo -n /usr/libexec/ApplicationFirewall/socketfilterfw "
		before, _ := Run(ctx, d, fw+"--getglobalstate; "+fw+"--getblockall", "")
		defer Run(context.WithoutCancel(ctx), d, fw+"--setblockall off; "+fw+"--setglobalstate "+map[bool]string{true: "on", false: "off"}[strings.Contains(before, "enabled")], "")
		r.Do(p+"/firewall", func() error {
			if _, err := Run(ctx, d, fw+"--setglobalstate on", ""); err != nil {
				return err
			}
			if err := syncs(ctx, g, hub, d, "H8 with the application firewall on", timeout); err != nil {
				return err
			}
			return syncs(ctx, g, d, hub, "H8 from behind the application firewall", timeout)
		})
		r.Do(p+"/block-all", func() error {
			if _, err := Run(ctx, d, fw+"--setblockall on", ""); err != nil {
				return err
			}
			// The Mac still dials out; the group's text reaches it over
			// its own connections.
			err := syncs(ctx, g, hub, d, "H8 with the firewall blocking all", timeout+30*time.Second)
			r.Note(p+"/block-all", fmt.Sprintf("with all incoming blocked: %v", err))
			return err
		})
	}
}
