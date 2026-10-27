// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Inventory is the bench's description of its devices
// (docs/testbench.md, section 13).
type Inventory struct {
	Controller string             `toml:"controller"`
	Device     map[string]*Device `toml:"device"`
	Router     *Host              `toml:"router"`
	Forwarder  *Host              `toml:"forwarder"`
	Relay      *Host              `toml:"relay"`
}

// Device is one device under test.
type Device struct {
	Name      string   `toml:"-"`
	OS        string   `toml:"os"`        // linux, linux-lite, darwin, windows, docker, openwrt, freebsd
	SSH       string   `toml:"ssh"`       // user@host; the user is the one signed in on the desktop
	Clipboard string   `toml:"clipboard"` // wayland, x11, none, macos, windows
	Roles     []string `toml:"roles"`     // member, hub, away
	Address   string   `toml:"address"`   // host:port others dial to pair with it, when mDNS cannot find it
	VM        *VM      `toml:"vm"`
	Container string   `toml:"container"` // os docker: the container's name on the host ssh reaches
	Firewall  string   `toml:"firewall"`  // linux and windows, for reset: "yes" lets the installer open the member port, "no" leaves the firewall alone
	Setup     string   `toml:"setup"`     // os docker, for reset: tools/bench/setup-docker.sh on the host
}

// VM names a virtual machine that the bench may revert to a snapshot.
type VM struct {
	Host     string `toml:"host"`
	VMX      string `toml:"vmx"`
	Snapshot string `toml:"snapshot"`
}

// Host is a machine that is not a member: the router, the forwarder or the
// blind relay.
type Host struct {
	SSH         string `toml:"ssh"`
	Kind        string `toml:"kind"`
	AwayNetwork string `toml:"away_network"` // the router's network for the away device
	Address     string `toml:"address"`      // the forwarder's or relay's address:port
	Key         string `toml:"key"`          // its key, as cbb forward -show-key or cbb relay -show-key prints it
	Service     string `toml:"service"`      // its systemd unit, which F7 stops and starts
}

var (
	knownOS        = []string{"linux", "linux-lite", "darwin", "windows", "docker", "openwrt", "freebsd"}
	knownClipboard = []string{"wayland", "x11", "none", "macos", "windows"}
)

// LoadInventory reads and checks the inventory.
func LoadInventory(path string) (*Inventory, error) {
	var inv Inventory
	md, err := toml.DecodeFile(path, &inv)
	if err != nil {
		return nil, fmt.Errorf("cannot read the inventory %s: %w", path, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		return nil, fmt.Errorf("the inventory %s has unknown keys: %v", path, u)
	}
	if len(inv.Device) == 0 {
		return nil, fmt.Errorf("the inventory %s names no devices", path)
	}
	for name, d := range inv.Device {
		d.Name = name
		if !slices.Contains(knownOS, d.OS) {
			return nil, fmt.Errorf("device %s: os %q is not one of %s", name, d.OS, strings.Join(knownOS, ", "))
		}
		if d.SSH == "" {
			return nil, fmt.Errorf("device %s: ssh is missing", name)
		}
		if d.Clipboard == "" {
			d.Clipboard = "none"
		}
		if !slices.Contains(knownClipboard, d.Clipboard) {
			return nil, fmt.Errorf("device %s: clipboard %q is not one of %s", name, d.Clipboard, strings.Join(knownClipboard, ", "))
		}
		if d.OS == "docker" {
			// A container has no desktop: the bench copies and pastes with
			// cbb inside it.
			if d.Clipboard != "none" {
				return nil, fmt.Errorf("device %s: a container has no clipboard but cbb's; leave out clipboard", name)
			}
			if d.Container == "" {
				d.Container = "clipboardbridge"
			}
			// The hub makes the group with cbb new and so holds its CA
			// keys, which never go into a container (docs/roadmap.md,
			// "Docker"): it joins as an ordinary member.
			if d.Has("hub") {
				return nil, fmt.Errorf("device %s: a container joins as an ordinary member and never holds the group's keys; give the role hub to another device", name)
			}
		} else if d.Container != "" {
			return nil, fmt.Errorf("device %s: container is only for os docker", name)
		}
	}
	return &inv, nil
}

// Select returns the devices named in a comma-separated list, or all of
// them, sorted by name.
func (inv *Inventory) Select(only string) ([]*Device, error) {
	var out []*Device
	if only == "" {
		for _, d := range inv.Device {
			out = append(out, d)
		}
	} else {
		for _, name := range strings.Split(only, ",") {
			d, ok := inv.Device[strings.TrimSpace(name)]
			if !ok {
				return nil, fmt.Errorf("no device %q in the inventory", name)
			}
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Has reports whether the device has a role.
func (d *Device) Has(role string) bool { return slices.Contains(d.Roles, role) }
