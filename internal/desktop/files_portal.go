// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	docsBus      = "org.freedesktop.portal.Documents"
	docsPath     = dbus.ObjectPath("/org/freedesktop/portal/documents")
	fileTransfer = "org.freedesktop.portal.FileTransfer"
	// transferCall bounds a call to the portal, which should answer at
	// once.
	transferCall = 2 * time.Second
)

// transfers offers written files to Flatpak apps through the FileTransfer
// portal: one transfer for the clipboard's files, stopped when the
// clipboard changes.
type transfers struct {
	logf func(string, ...any)
	mu   sync.Mutex
	conn *dbus.Conn // nil until the first write of files
	none bool       // the session has no portal: do not ask again
	key  string     // the transfer of the clipboard's files
}

// connect returns the session bus, dialed at first use.
func (t *transfers) connect() *dbus.Conn {
	if t.conn == nil && !t.none {
		conn, err := dbus.ConnectSessionBus()
		if err != nil {
			t.none = true
			return nil
		}
		t.conn = conn
	}
	return t.conn
}

// start stops the transfer of the clipboard's last files, if any, and
// starts one for paths; it returns its key, or "" when the session has
// no FileTransfer portal.
func (t *transfers) start(paths []string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
	conn := t.connect()
	if conn == nil {
		return ""
	}
	key, err := startTransfer(conn, paths)
	if err != nil {
		t.logf("cbb: the FileTransfer portal: %v; Flatpak apps cannot paste the files", err)
		t.none = true
		return ""
	}
	t.key = key
	return key
}

// stop stops the transfer of the clipboard's files, if any.
func (t *transfers) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
}

func (t *transfers) stopLocked() {
	if t.key != "" && t.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), transferCall)
		t.conn.Object(docsBus, docsPath).CallWithContext(ctx, fileTransfer+".StopTransfer", 0, t.key)
		cancel()
	}
	t.key = ""
}

// close stops the transfer and closes the bus.
func (t *transfers) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}

// startTransfer registers paths with the portal for every paste, read
// only, and returns the transfer's key.
func startTransfer(conn *dbus.Conn, paths []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), transferCall)
	defer cancel()
	obj := conn.Object(docsBus, docsPath)
	var key string
	opts := map[string]dbus.Variant{"writable": dbus.MakeVariant(false), "autostop": dbus.MakeVariant(false)}
	if err := obj.CallWithContext(ctx, fileTransfer+".StartTransfer", 0, opts).Store(&key); err != nil {
		return "", fmt.Errorf("StartTransfer: %w", err)
	}
	fds := make([]dbus.UnixFD, 0, len(paths))
	defer func() {
		for _, fd := range fds {
			unix.Close(int(fd))
		}
	}()
	for _, p := range paths {
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return "", err
		}
		fds = append(fds, dbus.UnixFD(fd))
	}
	if err := obj.CallWithContext(ctx, fileTransfer+".AddFiles", 0, key, fds, map[string]dbus.Variant{}).Err; err != nil {
		obj.CallWithContext(ctx, fileTransfer+".StopTransfer", 0, key)
		return "", fmt.Errorf("AddFiles: %w", err)
	}
	return key, nil
}
