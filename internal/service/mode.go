// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/clip"
)

// modeFile holds the sync mode, in the state directory. A device that made
// or joined its group gets one at once, with own; without it, the device
// joined before sync modes existed and keeps sharing as it did.
const modeFile = "mode"

// loadMode reads the sync mode from dir.
func loadMode(dir string) (clip.Mode, error) {
	b, err := os.ReadFile(filepath.Join(dir, modeFile))
	if errors.Is(err, os.ErrNotExist) {
		return clip.Shared, nil
	}
	if err != nil {
		return clip.Shared, err
	}
	m, err := clip.ParseMode(strings.TrimSpace(string(b)))
	if err != nil {
		return clip.Shared, fmt.Errorf("%s: %w", modeFile, err)
	}
	return m, nil
}

// saveMode writes the sync mode to dir.
func saveMode(dir string, m clip.Mode) error {
	return atomicfile.Write(filepath.Join(dir, modeFile), []byte(m.String()+"\n"), 0o600)
}

// newDeviceMode gives a device that just made or joined a group the sync
// mode of a new device, own, unless it has a mode from an earlier group.
func (s *Service) newDeviceMode() error {
	_, err := os.Stat(filepath.Join(s.cfg.StateDir, modeFile))
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m := clip.Own
	if s.cfg.newMode != nil {
		m = *s.cfg.newMode
	}
	if err := saveMode(s.cfg.StateDir, m); err != nil {
		return fmt.Errorf("saving the sync mode: %w", err)
	}
	return nil
}

// setMode changes the sync mode and saves it.
func (s *Service) setMode(name string) error {
	m, err := clip.ParseMode(name)
	if err != nil {
		return err
	}
	e := s.engine()
	if e == nil {
		return s.errNoGroup()
	}
	if err := saveMode(s.cfg.StateDir, m); err != nil {
		return fmt.Errorf("saving the sync mode: %w", err)
	}
	e.SetMode(m)
	s.logf("cbb: the sync mode is %s now", m)
	return nil
}

// pasteText is what cbb paste prints: the local clipboard's text in a mode
// that takes the group's copies, and the group's current text in one that
// keeps its clipboard to itself, so that the group's text is at hand there
// on request.
func pasteText(e *clip.Engine) (string, clip.Kind, bool) {
	if e.Mode().Receives() {
		text, kind, _, ok := e.Local()
		return text, kind, ok
	}
	ev, ok := e.Current()
	return ev.Text, ev.Kind, ok
}
