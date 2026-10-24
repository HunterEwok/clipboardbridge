// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxSkew is how far a device's clock may be from the controller's
// (docs/testbench.md, section 12), with room for the SSH round trip.
const maxSkew = 2 * time.Second

var (
	groupRE  = regexp.MustCompile(`group\s+([0-9a-f]{8,})`)
	deviceRE = regexp.MustCompile(`(?i)device\s+([0-9a-f]{8,})`)
	codeRE   = regexp.MustCompile(`Pairing code:\s*(\d{3})\s*(\d{3})`)
	addrRE   = regexp.MustCompile(`cbb pair -code (\S+:\d+)`)
)

// Check reaches every device: SSH, the clock, the installed version and its
// group.
func Check(ctx context.Context, r *Report, devices []*Device) {
	for _, d := range devices {
		r.Do("check/"+d.Name+"/reach", func() error {
			_, err := Run(ctx, d, "exit 0", "")
			return err
		})
		r.Do("check/"+d.Name+"/clock", func() error { return checkClock(ctx, d) })
		r.Do("check/"+d.Name+"/version", func() error {
			out, err := Run(ctx, d, cbbCmd(d)+" version", "")
			if err != nil {
				return fmt.Errorf("%s is not installed or does not run: %w", cbbCmd(d), err)
			}
			fmt.Fprintf(r.out, "     %s: %s\n", d.Name, strings.TrimSpace(out))
			return nil
		})
		r.Do("check/"+d.Name+"/group", func() error {
			g, err := groupOf(ctx, d)
			if err != nil {
				return err
			}
			if g == "" {
				g = "none"
			}
			fmt.Fprintf(r.out, "     %s: group %s\n", d.Name, g)
			return nil
		})
	}
}

func checkClock(ctx context.Context, d *Device) error {
	cmd := "date +%s.%N"
	if d.OS == "windows" {
		cmd = "[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0"
	} else if d.OS == "darwin" {
		cmd = "date +%s" // BSD date has no %N
	}
	before := time.Now()
	out, err := Run(ctx, d, cmd, "")
	if err != nil {
		return err
	}
	sec, err := strconv.ParseFloat(strings.TrimSpace(strings.ReplaceAll(out, ",", ".")), 64)
	if err != nil {
		return fmt.Errorf("cannot read the clock of %s from %q", d.Name, strings.TrimSpace(out))
	}
	mid := before.Add(time.Since(before) / 2)
	skew := time.Duration(sec*float64(time.Second)) - time.Duration(mid.UnixNano())
	if d.OS == "darwin" {
		skew = skew.Truncate(time.Second)
	}
	if skew > maxSkew || skew < -maxSkew {
		return fmt.Errorf("the clock of %s is off by %v; turn on NTP there", d.Name, skew.Round(time.Millisecond))
	}
	return nil
}

// groupOf returns the device's group ID, or "" when it is in no group.
func groupOf(ctx context.Context, d *Device) (string, error) {
	out, err := Run(ctx, d, cbbCmd(d)+" status", "")
	if err != nil {
		var re *RunError
		// cbb says "Not in a group.", cbb-lite "in no group"; both exit 1.
		if errors.As(err, &re) && (strings.Contains(re.Output, "Not in a group") || strings.Contains(re.Output, "in no group")) {
			return "", nil
		}
		return "", err
	}
	if m := groupRE.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", nil
}

// Smoke makes a group of the devices around the hub and sends one text from
// each device to every other one.
func Smoke(ctx context.Context, r *Report, inv *Inventory, devices []*Device, timeout time.Duration) {
	var hub *Device
	for _, d := range devices {
		if d.Has("hub") {
			hub = d
		}
	}
	if hub == nil || hub.OS != "linux" {
		r.Do("smoke/setup", func() error {
			return errors.New("smoke needs a Linux device with the role hub in the inventory: it makes the group with cbb new")
		})
		return
	}
	run := runID()
	fmt.Fprintf(r.out, "run %s, hub %s\n", run, hub.Name)

	// Every device must start in no group: the bench never touches a
	// group it did not make.
	ok := true
	for _, d := range devices {
		err := r.Do("smoke/"+d.Name+"/no-group", func() error {
			if err := checkClock(ctx, d); err != nil {
				return err
			}
			g, err := groupOf(ctx, d)
			if err != nil {
				return err
			}
			if g != "" {
				return fmt.Errorf("%s is in group %s; reset it before the run (uninstall with --purge, -Purge on Windows)", d.Name, g)
			}
			return nil
		})
		ok = ok && err == nil
	}
	if !ok {
		return
	}

	// mDNS does not cross subnets: a lite member is told where the hub is
	// for the run, and the service goes back to its own settings after it.
	if hub.Address != "" {
		for _, d := range devices {
			if d.OS != "linux-lite" {
				continue
			}
			if r.Do("smoke/"+d.Name+"/peer", func() error { return litePeer(ctx, d, hub.Address) }) == nil {
				defer r.Do("smoke/"+d.Name+"/unpeer", func() error { return litePeer(context.WithoutCancel(ctx), d, "") })
			}
		}
	}

	var group string
	if r.Do("smoke/"+hub.Name+"/new", func() error {
		_, err := Run(ctx, hub, "cbb new", "")
		return err
	}) != nil {
		return
	}
	members := []*Device{hub}
	for _, d := range devices {
		if d == hub {
			continue
		}
		if r.Do("smoke/"+d.Name+"/join", func() error { return pairOne(ctx, hub, d) }) == nil {
			members = append(members, d)
		}
	}
	r.Do("smoke/group", func() error {
		var err error
		group, err = groupOf(ctx, hub)
		if err == nil && group == "" {
			err = fmt.Errorf("%s made no group", hub.Name)
		}
		if err != nil {
			return err
		}
		for _, d := range members[1:] {
			g, err := groupOf(ctx, d)
			if err != nil {
				return err
			}
			if g != group {
				return fmt.Errorf("%s is in group %q, not %s", d.Name, g, group)
			}
		}
		return nil
	})

	// One text from each member; every other member must show it.
	for _, from := range members {
		text := fmt.Sprintf("cbb-bench %s from %s café ✓", run, from.Name)
		if r.Do("smoke/"+from.Name+"/copy", func() error { return Copy(ctx, from, text) }) != nil {
			continue
		}
		var wg sync.WaitGroup
		for _, to := range members {
			if to == from {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.Do(fmt.Sprintf("smoke/sync/%s->%s", from.Name, to.Name), func() error {
					var got string
					err := eventually(ctx, timeout, func() error {
						var err error
						if got, err = Paste(ctx, to); err != nil {
							return err
						}
						if strings.TrimRight(got, "\r\n") != text {
							return fmt.Errorf("%s did not get the text within %v; it has %q", to.Name, timeout, firstLine(got))
						}
						return nil
					})
					return err
				})
			}()
		}
		wg.Wait()
	}

	// The hub revokes the others, so nothing copied on them after the run
	// (the Mac is also someone's own computer) reaches the bench's group.
	// Linux and Windows members of a computer's group hold its CA keys and
	// cannot be revoked without a new group (docs/design.md): they are test
	// devices, reset before the next run.
	for _, d := range members[1:] {
		if d.OS == "linux" || d.OS == "windows" {
			r.Skip("smoke/"+d.Name+"/revoke", "it holds the group's CA keys; reset it before the next run")
			continue
		}
		r.Do("smoke/"+d.Name+"/revoke", func() error {
			id, err := deviceOf(ctx, d)
			if err != nil {
				return err
			}
			_, err = Run(ctx, hub, cbbCmd(hub)+" revoke "+id, "")
			return err
		})
	}
}

// liteDropIn is the bench's systemd drop-in for the lite member's service.
const liteDropIn = "/etc/systemd/system/cbb-lite.service.d/cbbbench.conf"

// litePeer restarts the lite member's service with -peer addr, or without
// the bench's drop-in when addr is "".
func litePeer(ctx context.Context, d *Device, addr string) error {
	cmd := "sudo -n rm -f " + liteDropIn + " && sudo -n rmdir --ignore-fail-on-non-empty " + path.Dir(liteDropIn)
	if addr != "" {
		conf := "[Service]\nExecStart=\nExecStart=/usr/local/bin/cbb-lite run -peer " + addr + "\n"
		cmd = "sudo -n mkdir -p " + path.Dir(liteDropIn) + " && printf '" + conf + "' | sudo -n tee " + liteDropIn + " >/dev/null"
	}
	_, err := Run(ctx, d, cmd+" && sudo -n systemctl daemon-reload && sudo -n systemctl restart cbb-lite", "")
	return err
}

// deviceOf returns the device's ID from its status.
func deviceOf(ctx context.Context, d *Device) (string, error) {
	out, err := Run(ctx, d, cbbCmd(d)+" status", "")
	if err != nil {
		return "", err
	}
	if m := deviceRE.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("%s shows no device ID in its status: %q", d.Name, firstLine(out))
}

// pairOne admits a device into the hub's group: cbb pair on the hub, and
// cbb pair -code (cbb-lite join -code) with its code on the device.
func pairOne(ctx context.Context, hub, d *Device) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	type window struct{ code, addr string }
	got := make(chan window, 1)
	done := make(chan error, 1)
	go func() {
		var w window
		done <- Stream(ctx, hub, "cbb pair", func(line string) {
			if m := addrRE.FindStringSubmatch(line); m != nil {
				w.addr = m[1]
			}
			if m := codeRE.FindStringSubmatch(line); m != nil {
				w.code = m[1] + m[2]
			}
			if strings.HasPrefix(line, "Waiting up to") && w.code != "" {
				select {
				case got <- w:
				default:
				}
			}
		})
	}()
	var w window
	select {
	case w = <-got:
	case err := <-done:
		if err == nil {
			err = errors.New("cbb pair ended without a code")
		}
		return err
	case <-ctx.Done():
		return fmt.Errorf("cbb pair on %s showed no code", hub.Name)
	}
	addr := d.addrFor(hub, w.addr)
	join := cbbCmd(d) + " pair -code"
	if d.OS == "linux-lite" {
		join = cbbCmd(d) + " join -code"
	}
	if d.OS == "linux-lite" {
		// The lite member joins as its service's user, which alone may
		// write its keys (lite/README.md); the bench user has sudo.
		join = "sudo -n -u cbb-lite " + join
	}
	if d.OS == "linux-lite" || addr != "" {
		if addr == "" {
			cancel()
			return fmt.Errorf("cbb-lite joins at an address; set address for %s in the inventory", hub.Name)
		}
		join += " " + addr
	}
	if _, err := Run(ctx, d, join, w.code+"\n"); err != nil {
		cancel()
		return err
	}
	if err := <-done; err != nil {
		return fmt.Errorf("cbb pair on %s did not see %s join: %w", hub.Name, d.Name, err)
	}
	return nil
}

// addrFor returns the address d dials to pair with hub: the hub's address in
// the inventory, the one cbb pair printed for a lite member (which cannot
// search), or "" to find it on the network.
func (d *Device) addrFor(hub *Device, printed string) string {
	if hub.Address != "" {
		return hub.Address
	}
	if d.OS == "linux-lite" {
		return printed
	}
	return ""
}

func runID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b)
}
