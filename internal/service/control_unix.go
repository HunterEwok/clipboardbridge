// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build unix

package service

import (
	"net"
	"os"
	"path/filepath"
	"sync"
)

// listenControl listens on the control socket with mode 0660: only the
// service's user, root, and members of the service's group may connect. The
// socket is made and narrowed in a new directory that only the service can
// enter, and then moved into place, so nobody can connect before its mode is
// right.
func listenControl(path string) (net.Listener, error) {
	tmp, err := os.MkdirTemp(filepath.Dir(path), ".c")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	tmpPath := filepath.Join(tmp, "s")
	ln, err := net.Listen("unix", tmpPath)
	if err != nil {
		return nil, err
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	if err := os.Chmod(tmpPath, 0o660); err != nil {
		ul.Close()
		os.Remove(tmpPath)
		return nil, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		ul.Close()
		os.Remove(tmpPath)
		return nil, err
	}
	return &controlListener{UnixListener: ul, path: path}, nil
}

// controlListener removes the socket when it is closed.
type controlListener struct {
	*net.UnixListener
	path string
	once sync.Once
}

func (l *controlListener) Close() error {
	err := l.UnixListener.Close()
	l.once.Do(func() { os.Remove(l.path) })
	return err
}
