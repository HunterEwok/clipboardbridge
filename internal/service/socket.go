// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/HunterEwok/clipbridge/internal/clip"
	"github.com/HunterEwok/clipbridge/internal/control"
	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/mdns"
	"github.com/HunterEwok/clipbridge/internal/node"
	"github.com/HunterEwok/clipbridge/internal/pair"
	"github.com/HunterEwok/clipbridge/internal/version"
)

// listenControl listens on the control socket with mode 0660: only the
// service's user, root, and members of the service's group may connect.
func listenControl(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (s *Service) serveControl(ctx context.Context, ln net.Listener) {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleControl(ctx, c)
	}
}

func reply(c net.Conn, h control.Header, payload []byte) error {
	h.Op = control.OpReply
	return control.Write(c, &control.Message{Header: h, Payload: payload})
}

func fail(c net.Conn, err error) {
	reply(c, control.Header{Error: err.Error(), Done: true}, nil)
}

var errNoGroup = errors.New("this device is in no group; run clipbridge pair on a Linux member and clipbridge join here")

func (s *Service) handleControl(ctx context.Context, c net.Conn) {
	defer c.Close()
	r := control.NewReader(c)
	m, err := r.Read()
	if err != nil {
		return
	}
	switch m.Op {
	case control.OpCopy:
		kind, via, err := parseKind(m.Kind, m.Via)
		if err == nil {
			err = s.withNode(func(nd *node.Node) error { return nd.Send(string(m.Payload), kind, via) })
		}
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Done: true}, nil)
	case control.OpPaste:
		e := s.engine()
		if e == nil {
			fail(c, errNoGroup)
			return
		}
		text, kind, _, ok := e.Local()
		if !ok {
			fail(c, errors.New("the clipboard is empty"))
			return
		}
		reply(c, control.Header{Kind: kindName(kind), Done: true}, []byte(text))
	case control.OpStatus:
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpPair:
		s.pair(ctx, c, r)
	case control.OpJoin:
		s.join(ctx, c, m)
	case control.OpWatch:
		s.watch(ctx, c, r)
	default:
		fail(c, fmt.Errorf("unknown operation %q", m.Op))
	}
}

func parseKind(kind, via string) (clip.Kind, clip.Via, error) {
	var k clip.Kind
	var v clip.Via
	if kind == "" {
		kind = "text"
	}
	if via == "" {
		via = "copy"
	}
	if err := k.UnmarshalText([]byte(kind)); err != nil {
		return 0, 0, err
	}
	if err := v.UnmarshalText([]byte(via)); err != nil {
		return 0, 0, err
	}
	return k, v, nil
}

// secretLeft returns how long the secret in the member's own clipboard
// may still be used: the secret lifetime less its age.
func (s *Service) secretLeft() time.Duration {
	e := s.engine()
	if e == nil {
		return 0
	}
	if _, kind, age, ok := e.Local(); ok && kind == clip.Secret {
		return max(clip.DefaultSecretTTL-age, time.Millisecond)
	}
	return time.Millisecond
}

func kindName(k clip.Kind) string {
	b, _ := k.MarshalText()
	return string(b)
}

func viaName(v clip.Via) string {
	b, _ := v.MarshalText()
	return string(b)
}

func (s *Service) withNode(f func(*node.Node) error) error {
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil {
		return errNoGroup
	}
	return f(nd)
}

func (s *Service) status() *control.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &control.Status{Role: string(s.cfg.Role), Version: version.String(), Holder: s.holder}
	if s.id == nil {
		return st
	}
	st.Device, st.Group = string(s.id.ID), group.Tag(s.id.GroupCA.Cert)
	skews := s.eng.Skews()
	for _, p := range s.nd.Peers() {
		st.Peers = append(st.Peers, control.Device{ID: string(p.ID), Role: string(p.Role), SkewMS: skews[string(p.ID)].Milliseconds()})
	}
	return st
}

// pair opens a pairing window and reports its end; a client that hangs up
// closes the window. On a Linux device in no group, it creates the group
// first.
func (s *Service) pair(ctx context.Context, c net.Conn, r *control.Reader) {
	if s.cfg.Role != node.Linux {
		fail(c, errors.New("only a Linux member can admit devices; run clipbridge pair on one"))
		return
	}
	s.mu.Lock()
	id, open := s.id, s.window != nil
	s.mu.Unlock()
	if open {
		fail(c, errors.New("a pairing window is already open"))
		return
	}
	if id == nil {
		var err error
		if id, err = group.Create(time.Now()); err == nil {
			err = id.Save(s.cfg.StateDir)
		}
		if err == nil {
			err = s.startGroup(ctx, id)
		}
		if err != nil {
			fail(c, fmt.Errorf("creating the group: %w", err))
			return
		}
		s.logf("clipbridge: created a new group %s", group.Tag(id.GroupCA.Cert))
	}
	code := pair.NewCode()
	w, err := pair.Open(id, code, pair.Options{})
	if err != nil {
		fail(c, err)
		return
	}
	s.mu.Lock()
	s.window = w
	s.responder.SetTXT(s.txtLocked())
	port := s.port
	s.mu.Unlock()
	defer func() {
		w.Close()
		s.mu.Lock()
		s.window = nil
		s.responder.SetTXT(s.txtLocked())
		s.mu.Unlock()
	}()
	reply(c, control.Header{Code: code, Expires: int(pair.Lifetime / time.Second), Address: localAddress(port)}, nil)
	hangup := make(chan struct{})
	go func() {
		r.Read() // returns when the client hangs up
		close(hangup)
	}()
	select {
	case <-w.Done():
	case <-hangup:
		return
	case <-ctx.Done():
		return
	}
	res, err := w.Result()
	if err != nil {
		fail(c, err)
		return
	}
	if !res.Confirmed {
		// It holds a certificate, and on Linux the CA keys, but may not
		// have stored them.
		s.logf("clipbridge: %s (%s) got its certificate but did not confirm it stored it", res.Info.Name, res.Device)
		fail(c, fmt.Errorf("%s got its certificate but did not confirm that it stored it; check it with clipbridge status there, and pair it again if needed", res.Info.Name))
		return
	}
	s.logf("clipbridge: %s (%s) joined the group", res.Info.Name, res.Device)
	reply(c, control.Header{Name: res.Info.Name, Done: true}, nil)
}

// localAddress returns an address of this member that a joining device can
// use when multicast does not work: the first private IPv4 address.
func localAddress(port uint16) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && ip4.IsPrivate() {
				return net.JoinHostPort(ip4.String(), fmt.Sprint(port))
			}
		}
	}
	return ""
}

// join joins a group with a code: at the address the user gave, or at a
// Linux member that announces an open pairing window.
func (s *Service) join(ctx context.Context, c net.Conn, m *control.Message) {
	s.mu.Lock()
	inGroup := s.id != nil
	s.mu.Unlock()
	if inGroup {
		fail(c, errors.New("this device is already in a group"))
		return
	}
	// A Linux member gets the CA keys and can admit devices; a Mac cannot.
	osName := "darwin"
	if s.cfg.Role == node.Linux {
		osName = "linux"
	}
	j, err := pair.NewJoiner(pair.Info{Name: s.cfg.Name, OS: osName})
	if err != nil {
		fail(c, err)
		return
	}
	addrs := []string{m.Address}
	if m.Address == "" {
		if addrs, err = s.findPairing(ctx); err != nil {
			fail(c, err)
			return
		}
	}
	var lastErr error
	for _, addr := range addrs {
		d := net.Dialer{Timeout: handshakeTimeout}
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		id, err := j.Join(ctx, raw, m.Code, func(id *group.Identity) error { return id.Save(s.cfg.StateDir) })
		if err != nil {
			lastErr = err
			if errors.Is(err, pair.ErrWrongCode) {
				break
			}
			continue
		}
		if err := s.startGroup(ctx, id); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Done: true}, nil)
		return
	}
	fail(c, lastErr)
}

// findPairing returns the addresses of the members that announce an open
// pairing window, browsing for up to ten seconds.
func (s *Service) findPairing(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	found := make(chan []string, 1)
	d, err := s.cfg.Discover(DiscoveryConfig{
		ID: "browse-" + clip.NewID()[:16], BrowseOnly: true, Logf: s.logf,
		OnPeers: func(peers []mdns.Peer) {
			var addrs []string
			for _, p := range peers {
				if v, _ := p.TXTValue("p"); v != "1" {
					continue
				}
				for _, a := range p.Addrs {
					addrs = append(addrs, net.JoinHostPort(a.String(), fmt.Sprint(p.Port)))
				}
			}
			if len(addrs) > 0 {
				select {
				case found <- addrs:
				default:
				}
			}
		},
	})
	if err != nil {
		return nil, err
	}
	go d.Run(ctx)
	select {
	case addrs := <-found:
		return addrs, nil
	case <-ctx.Done():
		return nil, errors.New("no member with an open pairing window found; run clipbridge pair on a Linux member, or give its address")
	}
}

// watcher is a desktop connector or pasteboard agent connected to the
// socket.
type watcher struct {
	out chan node.Write
}

func (w *watcher) send(wr node.Write) {
	select {
	case w.out <- wr:
	default: // a watcher that does not keep up misses writes; the next one wins anyway
	}
}

// watch serves a watcher: writes go out, reported copies come in.
func (s *Service) watch(ctx context.Context, c net.Conn, r *control.Reader) {
	if s.withNode(func(*node.Node) error { return nil }) != nil {
		fail(c, errNoGroup)
		return
	}
	w := &watcher{out: make(chan node.Write, 16)}
	s.mu.Lock()
	s.watchers[w] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.watchers, w)
		s.mu.Unlock()
	}()
	reply(c, control.Header{}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			m, err := r.Read()
			if err != nil {
				return
			}
			kind, via, err := parseKind(m.Kind, m.Via)
			if err != nil {
				continue
			}
			switch m.Op {
			case control.OpCopied:
				s.withNode(func(nd *node.Node) error {
					_, err := nd.Copied(string(m.Payload), kind, via)
					return err
				})
			case control.OpClipboard:
				if e := s.engine(); e != nil {
					e.ClipboardIs(string(m.Payload), kind)
				}
			}
		}
	}()
	for {
		select {
		case wr := <-w.out:
			h := control.Header{Op: control.OpWrite, Kind: kindName(wr.Kind), Via: viaName(wr.Via), Seq: wr.Seq}
			if wr.Kind == clip.Secret {
				h.TTLMS = s.secretLeft().Milliseconds()
			}
			if control.Write(c, &control.Message{Header: h, Payload: []byte(wr.Text)}) != nil {
				return
			}
		case <-done:
			return
		case <-ctx.Done():
			return
		}
	}
}
