// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"

	"github.com/HunterEwok/clipboardbridge/internal/blekeyboard"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/keyboard"
	"github.com/HunterEwok/clipboardbridge/internal/node"
)

// This computer as a Bluetooth keyboard (docs/roadmap.md, item 25, way 3;
// internal/blekeyboard): on Linux the service registers a BLE keyboard
// with BlueZ when its user turned it on with cbb keyboard on, types what
// cbb keyboard type gives it, and, when the user sends them there, the
// remote pastes of the group's admins.

// visibleFor is how long cbb keyboard pair makes the keyboard
// discoverable.
const visibleFor = 2 * time.Minute

// errKeyboardOS is the answer where there is no Bluetooth keyboard.
var errKeyboardOS = errors.New("only a Linux computer can be a Bluetooth keyboard: macOS and Windows let no program be one; an Android phone or the Nano ESP32 can")

// keyboardBus connects to the bus BlueZ is on: the system bus, or the
// one Config.KeyboardBus gives.
func (s *Service) keyboardBus() (*dbus.Conn, error) {
	if s.cfg.KeyboardBus != nil {
		return s.cfg.KeyboardBus()
	}
	if s.cfg.OS != group.OSLinux {
		return nil, errKeyboardOS
	}
	return dbus.ConnectSystemBus()
}

// keyboardName is what a host shows for the keyboard: this device's name,
// short enough for an advertisement.
func (s *Service) keyboardName() string {
	name := s.cfg.Name
	for len(name) > 20 {
		_, n := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-n]
	}
	return strings.TrimSpace("CBB " + name)
}

// applyKeyboard opens the keyboard when it is on in the settings and closes
// it when it is off. The reason it does not run is kept for the status.
func (s *Service) applyKeyboard() error {
	set, err := blekeyboard.Load(s.cfg.StateDir)
	if err != nil {
		return fmt.Errorf("reading the keyboard settings: %w", err)
	}
	s.kbdMu.Lock()
	defer s.kbdMu.Unlock()
	if !set.On {
		s.closeKeyboardLocked()
		s.kbdErr = nil
		return nil
	}
	if s.kbd != nil {
		return nil
	}
	conn, err := s.keyboardBus()
	if err == nil {
		var k *blekeyboard.Keyboard
		if k, err = blekeyboard.Open(conn, s.keyboardName(), s.logf); err == nil {
			s.kbd, s.kbdConn, s.kbdErr = k, conn, nil
			s.logf("cbb: this computer is a Bluetooth keyboard")
			return nil
		}
		conn.Close()
	}
	s.kbdErr = err
	s.logf("cbb: the Bluetooth keyboard: %v", err)
	return err
}

func (s *Service) closeKeyboardLocked() {
	if s.kbd == nil {
		return
	}
	s.kbd.Close()
	s.kbdConn.Close()
	s.kbd, s.kbdConn = nil, nil
}

// closeKeyboard takes the keyboard off BlueZ, as the service stops.
func (s *Service) closeKeyboard() {
	s.kbdMu.Lock()
	defer s.kbdMu.Unlock()
	s.closeKeyboardLocked()
}

// openKeyboard returns the running keyboard, opening it again when it
// could not open before (Bluetooth was off), or why there is none.
func (s *Service) openKeyboard() (*blekeyboard.Keyboard, error) {
	s.kbdMu.Lock()
	k := s.kbd
	s.kbdMu.Unlock()
	if k != nil {
		return k, nil
	}
	if err := s.applyKeyboard(); err != nil {
		return nil, err
	}
	s.kbdMu.Lock()
	defer s.kbdMu.Unlock()
	if s.kbd == nil {
		return nil, errors.New("the Bluetooth keyboard is off here; its user turns it on with cbb keyboard on")
	}
	return s.kbd, nil
}

// keyboard serves cbb keyboard: on with the settings, off, pair (visible
// for a while), type (the payload), or the status with no name.
func (s *Service) keyboard(ctx context.Context, m *control.Message) error {
	if s.cfg.KeyboardBus == nil && s.cfg.OS != group.OSLinux {
		return errKeyboardOS
	}
	set, err := blekeyboard.Load(s.cfg.StateDir)
	if err != nil {
		return err
	}
	switch m.Name {
	case "":
		return nil
	case "on":
		if k := m.Keyboard; k != nil {
			if k.Layout != "" {
				if !keyboard.Layout(k.Layout).Known() {
					return fmt.Errorf("the layout is us or ru, not %q", k.Layout)
				}
				set.Layout = keyboard.Layout(k.Layout)
			}
			if k.Rate != 0 {
				if k.Rate < blekeyboard.MinRate || k.Rate > blekeyboard.MaxRate {
					return fmt.Errorf("the rate is %d to %d characters a second", blekeyboard.MinRate, blekeyboard.MaxRate)
				}
				set.Rate = k.Rate
			}
			set.Pastes = k.Pastes
		}
		set.On = true
	case "off":
		set = blekeyboard.Settings{}
	case "pair":
		k, err := s.openKeyboard()
		if err != nil {
			return err
		}
		return k.Visible(visibleFor)
	case "type":
		k, err := s.openKeyboard()
		if err != nil {
			return err
		}
		text := strings.ReplaceAll(string(m.Payload), "\r\n", "\n")
		return k.Type(ctx, text, set.Layout, set.Rate)
	default:
		return fmt.Errorf("cbb keyboard takes on, off, pair or type, not %q", m.Name)
	}
	if err := blekeyboard.Save(s.cfg.StateDir, set); err != nil {
		return fmt.Errorf("saving the keyboard settings: %w", err)
	}
	s.logf("cbb: the Bluetooth keyboard is %s here (layout %s, rate %d, pastes %v)", m.Name, set.Layout, set.Rate, set.Pastes)
	err = s.applyKeyboard()
	if m.Name == "on" && err != nil {
		return fmt.Errorf("the keyboard is on, but it does not run yet: %w", err)
	}
	return nil
}

// keyboardStatus describes the keyboard for cbb status: nil where there is
// none and it was never turned on.
func (s *Service) keyboardStatus() *control.Keyboard {
	set, err := blekeyboard.Load(s.cfg.StateDir)
	if err != nil {
		return &control.Keyboard{Problem: err.Error()}
	}
	if s.cfg.OS != group.OSLinux && s.cfg.KeyboardBus == nil {
		return nil
	}
	st := &control.Keyboard{On: set.On, Layout: string(set.Layout), Rate: set.Rate, Pastes: set.Pastes}
	s.kbdMu.Lock()
	k, kerr := s.kbd, s.kbdErr
	s.kbdMu.Unlock()
	switch {
	case k != nil:
		st.Connected = k.Connected()
		if t := k.VisibleUntil(); !t.IsZero() {
			st.VisibleUntilMS = t.UnixMilli()
		}
	case set.On && kerr != nil:
		st.Problem = kerr.Error()
	}
	return st
}

// keyboardPaste types a remote paste on the keyboard's host, when the user
// sends pastes there; ok is false when they go to this computer's screen.
// Keys go straight in there, so a line break presses Enter: a text with
// one is refused unless the user allowed Enter. The answer is done once
// typing starts, as a long text takes longer than the sender waits.
func (s *Service) keyboardPaste(body group.CommandBody, text string, enter bool) (node.Result, bool) {
	set, err := blekeyboard.Load(s.cfg.StateDir)
	if err != nil || !set.On || !set.Pastes {
		return node.Result{}, false
	}
	res := node.Result{ID: body.ID, Status: node.ResultRefused}
	if strings.Contains(text, "\n") && !enter {
		res.Reason = "the text has a line break, which the Bluetooth keyboard types as Enter, and this device takes pastes without Enter only; send it as one line"
		return res, true
	}
	if body.Enter {
		text += "\n"
	}
	k, err := s.openKeyboard()
	if err == nil {
		err = k.Check(text, set.Layout)
	}
	var refusal *blekeyboard.Refusal
	switch {
	case errors.As(err, &refusal):
		res.Reason = refusal.Reason
		return res, true
	case err != nil:
		res.Status, res.Reason = node.ResultFailed, err.Error()
		return res, true
	}
	go func() {
		if err := k.Type(context.Background(), text, set.Layout, set.Rate); err != nil {
			s.logf("cbb: typing a paste from %s on the Bluetooth keyboard: %v", body.By, err)
		}
	}()
	return node.Result{ID: body.ID, Status: node.ResultDone}, true
}
