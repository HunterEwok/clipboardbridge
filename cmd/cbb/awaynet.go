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

// On Linux the service's unit lets it reach only the home network
// (packaging/linux/clipboardbridge.service). Sync away from home reaches the
// group's hub, forwarder or relay on the internet, so turning it on adds a
// drop-in that lets the service reach any address, and turning it off
// removes it. Both need root.
var (
	onLinux     = runtime.GOOS == "linux"
	serviceUnit = "/etc/systemd/system/clipboardbridge.service"
	awayDropIn  = "/etc/systemd/system/clipboardbridge.service.d/away.conf"
	euid        = os.Geteuid
	systemctl   = func(args ...string) error {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
)

const awayDropInText = `# Written by cbb global on or cbb pair -invite; cbb global off removes it.
# The unit lets the service reach only the home network; sync away from
# home reaches the group's hub, forwarder or relay on the internet.
[Service]
IPAddressAllow=any
`

// errNeedRoot is what a user sees who changes sync away from home without
// sudo on a Linux computer whose service is confined to the home network.
var errNeedRoot = errors.New("on this computer the service may reach only the home network, and only root can change that: run the command again with sudo")

// confined reports whether this computer's service runs from the unit that
// confines it to the home network.
func confined() bool {
	if !onLinux {
		return false
	}
	_, err := os.Stat(serviceUnit)
	return err == nil
}

// awayNetOpen reports whether the service may reach the internet.
func awayNetOpen() bool {
	_, err := os.Stat(awayDropIn)
	return err == nil
}

// checkAwayNet fails before anything changes when opening (on) or closing
// the service's network needs root that this command does not have.
func checkAwayNet(on bool) error {
	if !confined() || on == awayNetOpen() || euid() == 0 {
		return nil
	}
	return errNeedRoot
}

// setAwayNet lets the service reach the internet (on) or only the home
// network, and restarts it when that changed; the caller waits for its
// socket with waitService.
func setAwayNet(on bool) (changed bool, err error) {
	if !confined() || on == awayNetOpen() {
		return false, nil
	}
	if euid() != 0 {
		return false, errNeedRoot
	}
	if on {
		if err := os.MkdirAll(filepath.Dir(awayDropIn), 0o755); err != nil {
			return false, err
		}
		if err := os.WriteFile(awayDropIn, []byte(awayDropInText), 0o644); err != nil {
			return false, err
		}
	} else if err := os.Remove(awayDropIn); err != nil {
		return false, err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return true, err
	}
	return true, systemctl("restart", "clipboardbridge.service")
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
