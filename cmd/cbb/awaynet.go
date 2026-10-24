// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// On every computer the installer lets the service reach only the home
// network: on Linux its systemd unit (packaging/linux/clipboardbridge.service),
// on Windows an outbound rule of Windows Firewall (packaging/windows/install.ps1),
// on a Mac a pf anchor (packaging/macos/pf.sh). Sync away from home reaches
// the group's hub, forwarder or relay on the internet, so turning it on lifts
// that limit, and turning it off puts it back. Both need root or an
// administrator.

// A netLimit is one system's way of keeping the service on the home network.
type netLimit struct {
	present  func() bool         // the installer set the limit up
	lifted   func() bool         // the service may reach the internet
	lift     func(on bool) error // lifts the limit (on) or puts it back
	restarts bool                // changing it restarts the service
}

var (
	limit = map[string]*netLimit{"linux": &linuxLimit, "darwin": &macLimit, "windows": &windowsLimit}[runtime.GOOS]
	// elevated reports whether this process may change the limit: root,
	// or an administrator's elevated process on Windows.
	elevated = isElevated
)

// errNeedRoot is what a user sees who changes sync away from home without
// root or an administrator on a computer whose service is confined to the
// home network.
var errNeedRoot = errors.New(needRootText)

// confined reports whether this computer's service is confined to the home
// network by its installer.
func confined() bool {
	return limit != nil && limit.present()
}

// awayNetOpen reports whether the service may reach the internet.
func awayNetOpen() bool {
	return limit != nil && limit.lifted()
}

// checkAwayNet fails before anything changes when opening (on) or closing
// the service's network needs privileges that this command does not have.
func checkAwayNet(on bool) error {
	if !confined() || on == awayNetOpen() || elevated() {
		return nil
	}
	return errNeedRoot
}

// setAwayNet lets the service reach the internet (on) or only the home
// network. It reports whether that changed and whether the service
// restarted for it; the caller waits for its socket with waitService.
func setAwayNet(on bool) (changed, restarted bool, err error) {
	if !confined() || on == awayNetOpen() {
		return false, false, nil
	}
	if !elevated() {
		return false, false, errNeedRoot
	}
	return true, limit.restarts, limit.lift(on)
}

// Linux: a systemd drop-in that allows any address, and a restart, since
// systemd applies IPAddressAllow when the service starts.
var (
	serviceUnit = "/etc/systemd/system/clipboardbridge.service"
	awayDropIn  = "/etc/systemd/system/clipboardbridge.service.d/away.conf"
	systemctl   = func(args ...string) error { return runCmd("systemctl", args...) }
)

const awayDropInText = `# Written by cbb away on or cbb pair -invite; cbb away off removes it.
# The unit lets the service reach only the home network; sync away from
# home reaches the group's hub, forwarder or relay on the internet.
[Service]
IPAddressAllow=any
`

var linuxLimit = netLimit{
	present:  func() bool { return exists(serviceUnit) },
	lifted:   func() bool { return exists(awayDropIn) },
	restarts: true,
	lift: func(on bool) error {
		if on {
			if err := os.MkdirAll(filepath.Dir(awayDropIn), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(awayDropIn, []byte(awayDropInText), 0o644); err != nil {
				return err
			}
		} else if err := os.Remove(awayDropIn); err != nil {
			return err
		}
		if err := systemctl("daemon-reload"); err != nil {
			return err
		}
		return systemctl("restart", "clipboardbridge.service")
	},
}

// macOS: pf.sh loads the rules of the anchor com.apple/clipboardbridge for
// the service's user, without those for the home network while the file
// awayMark exists; pf applies them at once, so nothing restarts. awayMark
// sits where only root writes, so the service cannot lift its own limit.
var (
	pfScript = "/usr/local/share/clipboardbridge/pf.sh"
	awayMark = "/etc/clipboardbridge/away"
	sh       = func(args ...string) error { return runCmd("/bin/sh", args...) }
)

var macLimit = netLimit{
	present: func() bool { return exists(pfScript) },
	lifted:  func() bool { return exists(awayMark) },
	lift: func(on bool) error {
		if on {
			if err := os.MkdirAll(filepath.Dir(awayMark), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(awayMark, []byte("# Written by cbb away on; cbb away off removes it.\n"), 0o644); err != nil {
				return err
			}
		} else if err := os.Remove(awayMark); err != nil {
			return err
		}
		return sh(pfScript, "load")
	},
}

// Windows: an outbound rule of Windows Firewall blocks the service from
// every address outside the home network; turning it off lifts the limit at
// once, so nothing restarts. The rule's state is the truth, so a reinstall
// keeps it.
const firewallRule = "clipboardbridge-home-only"

var powershell = func(script string) (string, error) {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// windowsRule returns the rule's state: "True" while it blocks, "False"
// while it is lifted, "none" without the rule. A failed lookup counts as
// blocking, so that a change asks for an administrator rather than doing
// nothing.
func windowsRule() string {
	out, err := powershell(`$r = Get-NetFirewallRule -Name '` + firewallRule + `' -ErrorAction SilentlyContinue; if ($r) { [string]$r.Enabled } else { 'none' }`)
	if err != nil {
		return "True"
	}
	return out
}

var windowsLimit = netLimit{
	present: func() bool { return windowsRule() != "none" },
	lifted:  func() bool { return windowsRule() == "False" },
	lift: func(on bool) error {
		enabled := "True"
		if on {
			enabled = "False"
		}
		_, err := powershell(`Set-NetFirewallRule -Name '` + firewallRule + `' -Enabled ` + enabled + ` -ErrorAction Stop`)
		return err
	},
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// waitService waits until the restarted service answers on its socket.
func waitService() (*control.Client, error) {
	var err error
	for deadline := time.Now().Add(15 * time.Second); ; {
		var c *control.Client
		if c, err = control.Dial(control.SocketPath()); err == nil {
			return c, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the service did not come back after its restart: %w", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
