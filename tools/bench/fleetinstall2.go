// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// hardeningMax is the highest overall exposure systemd-analyze security may
// give clipboardbridge.service (I20): the score recorded when the unit was
// last made stricter. A change to the unit that raises it fails the case.
const hardeningMax = 2.6

var exposure = regexp.MustCompile(`Overall exposure level for clipboardbridge\.service: ([0-9.]+)`)

// settingsOf is what an install again must keep on d (I5): the group, the
// mode, the limits, the quick actions, remote paste and the keys.
func settingsOf(ctx context.Context, d *Device) (string, error) {
	var b strings.Builder
	for _, c := range []string{"cbb mode", "cbb config", "cbb action", "cbb paste-receive", "sha256sum /var/lib/clipboardbridge/identity.json"} {
		out, err := Run(ctx, d, c, "")
		if err != nil {
			return "", fmt.Errorf("%s: %w", c, err)
		}
		fmt.Fprintf(&b, "%s:\n%s\n", c, strings.TrimSpace(out))
	}
	tag, err := groupOf(ctx, d)
	if err != nil {
		return "", err
	}
	return b.String() + "group: " + tag, nil
}

// installedCases (I5, I20) run on an installed member in a group: install.sh
// run again over the install keeps every setting; the unit's sandbox
// scores no worse than recorded, and the TPM is reached through
// /dev/tpmrm0 alone.
func installedCases(ctx context.Context, r *Report, d *Device, archive string) {
	r.Do("fleet/I5-install-again", func() error {
		for _, c := range []string{"cbb mode receive", "cbb config max-copy 20MiB", "cbb action enable restart -yes", "cbb paste-receive on -enter"} {
			if _, err := Run(ctx, d, c, ""); err != nil {
				return fmt.Errorf("%s: %w", c, err)
			}
		}
		before, err := settingsOf(ctx, d)
		if err != nil {
			return err
		}
		if _, err := installArchive(ctx, d, archive, "--express --auto-update off"); err != nil {
			return err
		}
		if err := runsVersion(ctx, d, "0.6.0"); err != nil {
			return err
		}
		after, err := settingsOf(ctx, d)
		if err != nil {
			return err
		}
		if after != before {
			return fmt.Errorf("install.sh again changed the settings:\n%s", footprintDiff(before, after))
		}
		// Back to the defaults for the cases after.
		for _, c := range []string{"cbb mode own", "cbb config max-copy 100MiB", "cbb action off", "cbb paste-receive off"} {
			if _, err := Run(ctx, d, c, ""); err != nil {
				return fmt.Errorf("%s: %w", c, err)
			}
		}
		return nil
	})
	const p = "fleet/I20-hardening/"
	r.Do(p+"score", func() error {
		out, err := Run(ctx, d, "systemd-analyze security --no-pager clipboardbridge.service", "")
		if err != nil {
			return err
		}
		m := exposure.FindStringSubmatch(out)
		if m == nil {
			return fmt.Errorf("systemd-analyze security printed no overall exposure: %q", lastLines(out, 3))
		}
		score, _ := strconv.ParseFloat(m[1], 64)
		fmt.Fprintf(r.out, "     I20: exposure %.1f (at most %.1f)\n", score, hardeningMax)
		if score > hardeningMax {
			return fmt.Errorf("the unit's exposure is %.1f, above the recorded %.1f", score, hardeningMax)
		}
		return nil
	})
	r.Do(p+"tpm-only", func() error {
		// Without a TPM the sandbox gives the service no devices.
		show := func() (string, error) {
			return Run(ctx, d, "systemctl show -p PrivateDevices -p DevicePolicy -p DeviceAllow clipboardbridge", "")
		}
		out, err := show()
		if err != nil {
			return err
		}
		if !strings.Contains(out, "PrivateDevices=yes") || !strings.Contains(out, "DevicePolicy=closed") {
			return fmt.Errorf("without a TPM the unit has %q", out)
		}
		// With one (a stand-in node and the group tss), install.sh's
		// drop-in opens /dev/tpmrm0 and nothing else.
		if _, err := Run(ctx, d, "mknod /dev/tpmrm0 c 10 224 && groupadd -f -r tss", ""); err != nil {
			return err
		}
		defer Run(ctx, d, "rm -f /dev/tpmrm0", "")
		if _, err := installArchive(ctx, d, archive, "--express --auto-update off"); err != nil {
			return err
		}
		if out, err = show(); err != nil {
			return err
		}
		allow := ""
		for _, l := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(l, "DeviceAllow="); ok {
				allow = strings.TrimSpace(v)
			}
		}
		if !strings.Contains(out, "DevicePolicy=closed") || allow != "/dev/tpmrm0 rw" {
			return fmt.Errorf("with a TPM the unit has %q, not DevicePolicy=closed and DeviceAllow=/dev/tpmrm0 rw alone", out)
		}
		// Back without the TPM for the cases after.
		if _, err := Run(ctx, d, "rm -f /dev/tpmrm0", ""); err != nil {
			return err
		}
		_, err = installArchive(ctx, d, archive, "--express --auto-update off")
		return err
	})
}

// ufwRules (S12): on a computer whose ufw is on, install.sh --express adds
// exactly the rules docs/guide/install.md lists: TCP to the member port
// and UDP 5353 from the home networks only, each with the comment
// clipboardbridge; uninstall.sh takes away those and no other.
func ufwRules(ctx context.Context, r *Report, f *Fleet, archive string) {
	const p = "fleet/S12-firewall/"
	var d *Device
	noIPv6 := false
	if r.Do(p+"setup", func() error {
		var err error
		if d, err = f.AddSystemd(ctx, f.net); err != nil {
			return err
		}
		// Docker turns IPv6 off in a container on a network without it;
		// a computer at home has it, and install.sh's rules name fe80::/10.
		// A kernel without IPv6 at all (ipv6.disable=1) gets IPv4 rules
		// only, and install.sh must not fail on it.
		if out, _ := Run(ctx, d, "test -d /proc/sys/net/ipv6 && echo yes; true", ""); strings.TrimSpace(out) != "yes" {
			noIPv6 = true
		}
		if noIPv6 {
			fmt.Fprintln(r.out, "     S12: the kernel has no IPv6")
		} else if _, err := Run(ctx, d, "sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0", ""); err != nil {
			return err
		}
		out, err := Run(ctx, d, "command -v ufw && ufw allow 22/tcp >/dev/null && ufw --force enable && ufw status", "")
		if err != nil || !strings.Contains(out, "Status: active") {
			return fmt.Errorf("cannot turn ufw on in the image: %q %v", out, err)
		}
		return nil
	}) != nil {
		return
	}
	numbered := func() ([]string, error) {
		out, err := Run(ctx, d, "ufw status", "")
		if err != nil {
			return nil, err
		}
		var rules []string
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "ALLOW") {
				rules = append(rules, strings.Join(strings.Fields(l), " "))
			}
		}
		return rules, nil
	}
	var before []string
	r.Do(p+"exactly", func() error {
		var err error
		if before, err = numbered(); err != nil {
			return err
		}
		out, err := installArchive(ctx, d, archive, "--express --auto-update off")
		if err != nil {
			return err
		}
		if !strings.Contains(out, "ufw") {
			return fmt.Errorf("install.sh did not name ufw: %q", lastLines(out, 5))
		}
		after, err := numbered()
		if err != nil {
			return err
		}
		nets, err := Run(ctx, d, `ip -o -f inet addr show scope global | awk '{print $4}'`, "")
		if err != nil {
			return err
		}
		var added []string
		in := map[string]bool{}
		for _, l := range before {
			in[l] = true
		}
		for _, l := range after {
			if !in[l] {
				added = append(added, l)
			}
		}
		if len(added) == 0 {
			return fmt.Errorf("install.sh added no ufw rule: %q", after)
		}
		for _, l := range added {
			ok := strings.HasSuffix(l, "# clipboardbridge") || strings.HasSuffix(l, "# clipboardbridge mDNS")
			ok = ok && (strings.HasPrefix(l, "8764/tcp ") || strings.HasPrefix(l, "5353/udp "))
			if ok {
				// From a home network: the container's own or another
				// private range, never Anywhere.
				ok = !strings.Contains(l, "Anywhere")
			}
			if !ok {
				return fmt.Errorf("install.sh added a rule it does not list: %q (networks here: %s)", l, strings.Fields(nets))
			}
		}
		return nil
	})
	r.Do(p+"uninstall", func() error {
		if _, err := RunFor(ctx, d, "sh /usr/local/share/clipboardbridge/uninstall.sh --purge", "", 2*time.Minute); err != nil {
			return err
		}
		after, err := numbered()
		if err != nil {
			return err
		}
		if strings.Join(after, "\n") != strings.Join(before, "\n") {
			return fmt.Errorf("uninstall left the ufw rules %q, not %q", after, before)
		}
		return nil
	})
}

// lastLines is the last n lines of s.
func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

// inviteGrant (G15): a join by invitation on a computer whose unit lets
// the service reach only the home network: while it joins, the service may
// reach the hub's addresses (the drop-in away.conf allows them), and once
// the join fails, as with a hub that is not there, they are taken back.
func inviteGrant(ctx context.Context, r *Report, f *Fleet, archive string) {
	const p = "fleet/G15-invite-addresses/"
	const hub = "203.0.113.7"
	var d *Device
	if r.Do(p+"setup", func() error {
		var err error
		if d, err = f.AddSystemd(ctx, f.net); err != nil {
			return err
		}
		if _, err := installArchive(ctx, d, archive, "--no-firewall --auto-update off"); err != nil {
			return err
		}
		bin, err := forgeOn(ctx, d)
		if err != nil {
			return err
		}
		_, err = Run(ctx, d, bin+" invite:"+hub+":443 >/tmp/invitation", "")
		return err
	}) != nil {
		return
	}
	dropIn := func() string {
		out, _ := Run(ctx, d, "cat /etc/systemd/system/clipboardbridge.service.d/away.conf 2>/dev/null; true", "")
		return out
	}
	r.Do(p+"allowed-while-joining", func() error {
		if _, err := Run(ctx, d, `rm -f /tmp/join.rc; nohup sh -c 'printf "yes\n" | cbb pair -invite /tmp/invitation >/tmp/join.out 2>&1; echo $? >/tmp/join.rc' >/dev/null 2>&1 &`, ""); err != nil {
			return err
		}
		return eventually(ctx, 30*time.Second, func() error {
			if got := dropIn(); !strings.Contains(got, "IPAddressAllow="+hub) {
				return fmt.Errorf("while joining, away.conf is %q, without the hub's address", got)
			}
			return nil
		})
	})
	r.Do(p+"taken-back", func() error {
		var rc string
		if err := eventually(ctx, 2*time.Minute, func() error {
			out, err := Run(ctx, d, "cat /tmp/join.rc", "")
			rc = strings.TrimSpace(out)
			return err
		}); err != nil {
			return fmt.Errorf("the join did not end: %w", err)
		}
		out, _ := Run(ctx, d, "cat /tmp/join.out", "")
		if rc == "0" {
			return fmt.Errorf("the join with no hub there succeeded: %q", out)
		}
		if !strings.Contains(out, "the hub did not answer") {
			return fmt.Errorf("the failed join said %q", lastLines(out, 3))
		}
		if got := dropIn(); strings.Contains(got, hub) {
			return fmt.Errorf("after the failed join away.conf still allows the hub: %q", got)
		}
		return nil
	})
}
