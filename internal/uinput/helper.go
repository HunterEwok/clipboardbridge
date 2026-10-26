// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package uinput

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/clipboardbridge/internal/connector"
	"github.com/HunterEwok/clipboardbridge/internal/lockcheck"
)

// Socket is where the helper listens. The connection is one line from the
// desktop connector, "paste" (Shift+Insert) or "enter", and one line back:
// "ok", "refused REASON" or "error MESSAGE".
const Socket = "/run/clipboardbridge-keys/keys"

// The keys of each request.
var requests = map[string][]Key{
	"paste": {{KeyLeftShift, true}, {KeyInsert, true}, {KeyInsert, false}, {KeyLeftShift, false}},
	"enter": {{KeyEnter, true}, {KeyEnter, false}},
}

// names name the keys of each request in the log.
var names = map[string]string{"paste": "Shift+Insert", "enter": "Enter"}

// Presser presses keys: a Keyboard, or a fake in tests.
type Presser interface {
	Press([]Key) error
}

// Helper serves the desktop connectors' requests.
type Helper struct {
	Keys Presser
	Logf func(string, ...any)
	// Check says why the user uid may not have keys pressed now, or "";
	// nil checks logind's active session (Allowed).
	Check func(uid uint32) string

	mu sync.Mutex // one paste at a time
}

// Serve answers on ln until ctx ends.
func (h *Helper) Serve(ctx context.Context, ln *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go h.serve(c)
	}
}

func (h *Helper) serve(c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	req := strings.TrimSpace(line)
	answer := func(s string) { fmt.Fprintln(c, s) }
	keys, ok := requests[req]
	if !ok {
		answer("error the keys helper presses paste or enter, not " + strconv.Quote(req))
		return
	}
	uid, err := peerUID(c)
	if err != nil {
		answer("error " + err.Error())
		return
	}
	check := h.Check
	if check == nil {
		check = Allowed
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if why := check(uid); why != "" {
		h.Logf("cbb: refused %s for user %d: %s", names[req], uid, why)
		answer("refused " + why)
		return
	}
	if err := h.Keys.Press(keys); err != nil {
		h.Logf("cbb: pressing %s: %v", names[req], err)
		answer("error " + err.Error())
		return
	}
	h.Logf("cbb: pressed %s for user %d", names[req], uid)
	answer("ok")
}

func peerUID(c *net.UnixConn) (uint32, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, fmt.Errorf("reading the caller: %w", cerr)
	}
	return cred.Uid, nil
}

// Allowed says why the keys may not go to the user uid now, or "": they go
// only to the user of the graphical session active on the computer's own
// screen (seat0), never to a login screen, and not while it is locked.
func Allowed(uid uint32) string {
	id := lockcheck.ActiveSession("seat0")
	if id == "" {
		return "no session is active on this computer's screen"
	}
	p := lockcheck.Show(id, "User", "Type", "Class", "LockedHint")
	switch {
	case !strings.HasPrefix(p["Class"], "user"): // user, or systemd's user-early and user-light; not greeter or lock-screen
		return "the login screen is showing"
	case p["User"] != strconv.FormatUint(uint64(uid), 10):
		return "the keys go only to the user of the session on the screen"
	case p["Type"] != "x11" && p["Type"] != "wayland":
		return "the session on the screen is not graphical"
	case p["LockedHint"] == "yes":
		return "the session is locked"
	}
	if name := lockcheck.Locker(true); name != "" {
		return "the screen is locked (" + name + " runs)"
	}
	return ""
}

// Ask asks the helper at socket to press the keys of req, "paste" or
// "enter". A refusal comes back as a connector.Refusal.
func Ask(ctx context.Context, socket, req string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("the keys helper: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c, req); err != nil {
		return fmt.Errorf("the keys helper: %w", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return fmt.Errorf("the keys helper did not answer: %w", err)
	}
	kind, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
	switch kind {
	case "ok":
		return nil
	case "refused":
		return &connector.Refusal{Reason: rest}
	case "error":
		return errors.New("the keys helper: " + rest)
	}
	return fmt.Errorf("the keys helper answered %q", line)
}
