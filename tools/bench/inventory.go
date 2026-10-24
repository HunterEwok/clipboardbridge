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
	Relay      *Host              `toml:"relay"`
}

// Device is one device under test.
type Device struct {
	Name      string   `toml:"-"`
	OS        string   `toml:"os"`        // linux, linux-lite, darwin, windows
	SSH       string   `toml:"ssh"`       // user@host; the user is the one signed in on the desktop
	Clipboard string   `toml:"clipboard"` // wayland, x11, none, macos, windows
	Roles     []string `toml:"roles"`     // member, hub, away
	Address   string   `toml:"address"`   // host:port others dial to pair with it, when mDNS cannot find it
	VM        *VM      `toml:"vm"`
}

// VM names a virtual machine that the bench may revert to a snapshot.
type VM struct {
	Host     string `toml:"host"`
	VMX      string `toml:"vmx"`
	Snapshot string `toml:"snapshot"`
}

// Host is a machine that is not a member: the router or the relay.
type Host struct {
	SSH         string `toml:"ssh"`
	Kind        string `toml:"kind"`
	AwayNetwork string `toml:"away_network"` // the router's network for the away device
}

var (
	knownOS        = []string{"linux", "linux-lite", "darwin", "windows"}
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
