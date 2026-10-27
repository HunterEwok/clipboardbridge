// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/version"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// Desk is what the window and the tray know of the service on this
// computer: its status and the group's devices, read from the control
// socket. Its exported methods are what the window calls.
type Desk struct {
	app    *application.App
	window *application.WebviewWindow
	tray   *application.SystemTray

	socket       string
	lang         string
	tr           map[string]string
	settingsPath string

	mu       sync.Mutex
	settings Settings
	status   *control.Status
	devices  []control.Device
	problem  string
	message  string
	busy     bool
}

// State is the window's whole picture, read again every few seconds.
type State struct {
	Lang     string           `json:"lang"`
	Problem  string           `json:"problem,omitempty"`
	Status   *control.Status  `json:"status,omitempty"`
	Devices  []control.Device `json:"devices"`
	Busy     bool             `json:"busy"`
	Message  string           `json:"message,omitempty"`
	Settings Settings         `json:"settings"`
	Version  string           `json:"version"`
	// ShowDetails is whether messages show the error underneath, as
	// Settings.Details or else the build sets it.
	ShowDetails bool `json:"show_details"`
}

// Settings are the window's choices, kept in the user's configuration
// folder.
type Settings struct {
	Color      string `json:"color"`
	Appearance string `json:"appearance"` // system, dark or light
	Layout     string `json:"layout"`     // tiles, list or orbit
	// Details shows the error underneath each message; nil follows the
	// build and CBB_DEBUG (showDetails).
	Details *bool `json:"details,omitempty"`
}

// NewDesk reads the settings and the language; it reaches the service only
// when asked.
func NewDesk() *Desk {
	d := &Desk{socket: control.SocketPath(), lang: language(), settings: Settings{Color: "terminal", Appearance: "system", Layout: "tiles"}}
	d.tr = translations(d.lang)
	if dir, err := os.UserConfigDir(); err == nil {
		d.settingsPath = filepath.Join(dir, "clipboardbridge", "desktop.json")
		if data, err := os.ReadFile(d.settingsPath); err == nil {
			if err := json.Unmarshal(data, &d.settings); err != nil {
				log.Printf("settings: %v", err)
			}
		}
	}
	return d
}

// T translates an English text into the user's language.
func (d *Desk) T(s string) string {
	if t, ok := d.tr[s]; ok {
		return t
	}
	return s
}

// State reads the service again and returns what the window shows.
func (d *Desk) State() State {
	d.refresh()
	return d.snapshot()
}

func (d *Desk) snapshot() State {
	details := d.showDetails()
	d.mu.Lock()
	defer d.mu.Unlock()
	return State{Lang: d.lang, Problem: d.problem, Status: d.status, Devices: d.devices, Busy: d.busy,
		Message: d.message, Settings: d.settings, Version: version.String(), ShowDetails: details}
}

func (d *Desk) refresh() {
	var st *control.Status
	var devices []control.Device
	m, _, err := d.request(control.OpStatus, nil)
	if err == nil {
		st = m.Status
		if st != nil && st.Group != "" && !st.Removed {
			var dm *control.Message
			if dm, _, err = d.request(control.OpDevices, nil); err == nil {
				devices = dm.Devices
			}
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.problem = d.describe(err)
		return
	}
	d.problem, d.status, d.devices = "", st, devices
}

// request sends one request on its own connection and returns the answer
// and its payload.
func (d *Desk) request(op string, payload []byte) (*control.Message, []byte, error) {
	c, err := control.Dial(d.socket)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	m, err := c.Do(&control.Message{Header: control.Header{Op: op}, Payload: payload})
	if err != nil {
		return nil, nil, err
	}
	return m, m.Payload, nil
}

// Send sends the text on this computer's clipboard to the group, as a copy
// here.
func (d *Desk) Send() {
	d.act(func() (string, error) {
		text, ok := d.app.Clipboard.Text()
		if !ok || text == "" {
			return d.T("The clipboard holds no text."), nil
		}
		if _, _, err := d.request(control.OpCopy, []byte(text)); err != nil {
			return "", err
		}
		return d.T("Sent to the group."), nil
	})
}

// Fetch puts the group's latest text on this computer's clipboard.
func (d *Desk) Fetch() {
	d.act(func() (string, error) {
		_, body, err := d.request(control.OpPaste, nil)
		if err != nil {
			return "", err
		}
		if len(body) == 0 {
			return d.T("The group has no text yet."), nil
		}
		d.app.Clipboard.SetText(string(body))
		return d.T("Fetched from the group."), nil
	})
}

// Rename, Remove, MakeAdmin, Freeze, Unfreeze, SetAway and SetMode change the group:
// cbb does them as the administrator (admin_*.go), after the system asks.
// MakeAdmin's dialog warns that the computer's key is a file, which
// -allow-file-key consents to.
func (d *Desk) Rename(id, name string) { d.admin([]string{"rename", id, name}, false, "Renamed.") }
func (d *Desk) Remove(id string)       { d.admin([]string{"revoke", id}, false, "Removed from the group.") }
func (d *Desk) MakeAdmin(id string) {
	d.admin([]string{"admin", "-allow-file-key", id}, false, "It is an admin now.")
}
func (d *Desk) Freeze(id string)   { d.admin([]string{"freeze", id}, false, "Frozen.") }
func (d *Desk) Unfreeze(id string) { d.admin([]string{"unfreeze", id}, false, "Unfrozen.") }

// Update installs the newest signed release the group passed around, as
// cbb update does as the administrator.
func (d *Desk) Update() { d.admin([]string{"update"}, false, "Clipboard Bridge is updated.") }

// SetAway turns sync away from home on or off; on answers yes to the
// warning the window showed, which cbb asks for.
func (d *Desk) SetAway(on bool) {
	if on {
		d.admin([]string{"global", "on"}, true, "Sync away from home is on.")
	} else {
		d.admin([]string{"global", "off"}, false, "Sync away from home is off.")
	}
}

// SetMode sets the sync mode: this computer's with id empty, or on an admin
// another device's, which cbb sends it as a signed command.
func (d *Desk) SetMode(id, mode string) {
	args := []string{"mode", mode}
	if id != "" {
		args = []string{"mode", "-on", id, mode}
	}
	d.admin(args, false, "The sync mode is set.")
}

func (d *Desk) admin(args []string, yes bool, done string) {
	details := d.showDetails()
	d.act(func() (string, error) {
		if err := runAdmin(args, yes, details); err != nil {
			return "", err
		}
		return d.T(done), nil
	})
}

// act runs one action at a time, then reads the service again.
func (d *Desk) act(work func() (string, error)) {
	d.mu.Lock()
	if d.busy {
		d.mu.Unlock()
		return
	}
	d.busy = true
	d.mu.Unlock()
	msg, err := work()
	if errors.Is(err, errCancelled) {
		msg, err = "", nil
	}
	if err != nil {
		msg = d.describe(err)
	}
	d.mu.Lock()
	d.busy, d.message = false, msg
	d.mu.Unlock()
	d.refresh()
	d.updateTray()
}

// SaveSettings keeps the window's choices.
func (d *Desk) SaveSettings(s Settings) error {
	d.mu.Lock()
	d.settings = s
	d.mu.Unlock()
	if d.settingsPath == "" {
		return errors.New("no configuration folder")
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.settingsPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(d.settingsPath, data, 0o600)
}

// showDetails tells whether messages show the error underneath them: the
// setting when there is one, else as cbb does (CBB_DEBUG=1 or 0, or on in a
// build without a release version).
func (d *Desk) showDetails() bool {
	d.mu.Lock()
	set := d.settings.Details
	d.mu.Unlock()
	if set != nil {
		return *set
	}
	switch os.Getenv("CBB_DEBUG") {
	case "1":
		return true
	case "0":
		return false
	}
	return version.Version == "dev"
}

// describe turns an error into the message for the user, with the error
// underneath when details are on; the log has it either way.
func (d *Desk) describe(err error) string {
	text, detail := d.summary(err)
	log.Printf("%s: %s", text, detail)
	if d.showDetails() && detail != "" && detail != text {
		return text + "\n\n" + detail
	}
	return text
}

func (d *Desk) summary(err error) (string, string) {
	var dial *control.DialError
	var req *control.RequestError
	var adm *adminError
	switch {
	case errors.As(err, &dial) && dial.Denied:
		return d.T(deniedText), dial.Error()
	case errors.As(err, &dial):
		return d.T("The Clipboard Bridge service is not running on this computer."), fmt.Sprint(dial.Err)
	case errors.As(err, &req):
		return req.Msg, req.Detail
	case errors.As(err, &adm):
		return d.T(adm.msg), adm.detail
	}
	return d.T("Something failed on this computer."), err.Error()
}

// Open shows the window.
func (d *Desk) Open() {
	if d.window == nil {
		return
	}
	d.window.Show()
	d.window.Focus()
}

// watch keeps the tray up to date.
func (d *Desk) watch() {
	for range time.Tick(5 * time.Second) {
		d.refresh()
		d.updateTray()
	}
}

// updateTray writes the tray's menu: where the group stands, send, fetch,
// the window.
func (d *Desk) updateTray() {
	if d.tray == nil || d.app == nil {
		return
	}
	s := d.snapshot()
	menu := d.app.NewMenu()
	menu.Add(d.headline(s)).SetEnabled(false)
	if s.Message != "" {
		menu.Add(s.Message).SetEnabled(false)
	}
	menu.AddSeparator()
	inGroup := s.Problem == "" && s.Status != nil && s.Status.Group != ""
	menu.Add(d.T("Send the clipboard")).SetEnabled(inGroup && !s.Busy).OnClick(func(*application.Context) { go d.Send() })
	menu.Add(d.T("Fetch")).SetEnabled(inGroup && !s.Busy).OnClick(func(*application.Context) { go d.Fetch() })
	if s.Problem == "" && s.Status != nil && s.Status.Update != "" {
		menu.AddSeparator()
		menu.Add(fmt.Sprintf(d.T("Update to %s"), s.Status.Update)).SetEnabled(!s.Busy).OnClick(func(*application.Context) { go d.Update() })
	}
	menu.AddSeparator()
	menu.Add(d.T("Open Clipboard Bridge")).OnClick(func(*application.Context) { d.Open() })
	menu.Add(d.T("Quit")).OnClick(func(*application.Context) { d.app.Quit() })
	d.tray.SetMenu(menu)
	d.tray.SetTooltip("Clipboard Bridge · " + d.headline(s))
}

// headline is the group in a line.
func (d *Desk) headline(s State) string {
	switch {
	case s.Problem != "":
		return d.T("The service does not answer")
	case s.Status == nil || s.Status.Group == "":
		return d.T("This computer is in no group yet")
	}
	online, others := 0, 0
	for _, dev := range s.Devices {
		if dev.Self {
			continue
		}
		others++
		if dev.Online {
			online++
		}
	}
	return fmt.Sprintf(d.T("%d of %d online"), online, others)
}
