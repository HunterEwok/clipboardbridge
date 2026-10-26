// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/connector"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/tmuxpaste"
)

// cmdPasteHelper runs a paste target without a clipboard (design.md,
// "Remote paste"): cbb paste-helper tmux, which clipboardbridge's tmux.conf
// starts in the background, or cbb paste-helper console on Linux, which the
// clipboardbridge-console unit runs.
func cmdPasteHelper(args []string, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "tmux" && args[0] != "console") {
		fmt.Fprintln(stderr, "usage: cbb paste-helper tmux|console")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if args[0] == "console" {
		return runConsoleHelper(ctx, stderr)
	}
	return runTmuxHelper(ctx, stderr)
}

// runTmuxHelper is the helper for tmux. One runs for each tmux server,
// until the server ends; it logs to the user's state directory, since tmux
// shows a background command's output in a pane.
func runTmuxHelper(ctx context.Context, stderr io.Writer) int {
	sock, _, _ := strings.Cut(os.Getenv("TMUX"), ",")
	if sock == "" {
		return fail(stderr, errors.New("not inside tmux: start it from tmux, as clipboardbridge's tmux.conf does"))
	}
	lock, ok := lockHelper(sock)
	if !ok {
		return 0 // this server has its helper
	}
	if lock != nil {
		defer lock.Close() // locked until the helper ends
	}
	logw := stderr
	if dir, err := stateDir(); err == nil {
		if l, err := openLog(filepath.Join(dir, "paste-helper.log")); err == nil {
			defer l.Close()
			logw = l
		}
	}
	logf := func(format string, args ...any) { fmt.Fprintf(logw, format+"\n", args...) }
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tm := &tmuxpaste.Tmux{Args: []string{"-S", sock}, Console: os.Geteuid() == 0}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
			if !tm.Alive(ctx) {
				logf("cbb: the tmux server ended")
				cancel()
				return
			}
		}
	}()
	logf("cbb: pasting into tmux at %s as the %s target", sock, tm.Target())
	if err := connector.Run(ctx, connector.Config{Socket: control.SocketPath(), Target: tm, Logf: logf}); err != nil {
		logf("cbb: %v", err)
		return 1
	}
	return 0
}

// stateDir is the user's directory for clipboardbridge's own files, made
// if missing.
func stateDir() (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "state")
	}
	dir = filepath.Join(dir, "clipboardbridge")
	return dir, os.MkdirAll(dir, 0o700)
}

// lockHelper reports whether this is the only helper of the tmux server at
// sock: tmux runs the config again on every source-file. The lock lasts
// while the file it returns is open; without one, running twice beats not
// running.
func lockHelper(sock string) (*os.File, bool) {
	sum := sha256.Sum256([]byte(sock))
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Dir(sock) // tmux's own directory, the user's alone
	}
	f, err := os.OpenFile(filepath.Join(dir, "clipboardbridge-tmux-"+hex.EncodeToString(sum[:8])+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, true
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, !errors.Is(err, syscall.EWOULDBLOCK)
	}
	return f, true
}
