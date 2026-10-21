// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func (s *Service) serveControl(ctx context.Context, ln net.Listener) {
	acceptLoop(ctx, ln, s.logf, "the control socket", func(c net.Conn) {
		go s.handleControl(ctx, c)
	})
}

func reply(c net.Conn, h control.Header, payload []byte) error {
	h.Op = control.OpReply
	return control.Write(c, &control.Message{Header: h, Payload: payload})
}

func fail(c net.Conn, err error) {
	reply(c, control.Header{Error: err.Error(), Done: true}, nil)
}

// errNoGroup is the error for a request that needs a group.
func (s *Service) errNoGroup() error {
	if s.cfg.Role == node.Linux {
		return errors.New("this device is in no group; run clipbridge pair here to start one, or clipbridge join to join one")
	}
	return errors.New("this device is in no group; run clipbridge pair on a Linux member, then clipbridge join here")
}

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
			fail(c, s.errNoGroup())
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
		s.join(ctx, c, r, m)
	case control.OpWatch:
		s.watch(ctx, c, r, m)
	default:
		fail(c, fmt.Errorf("unknown operation %q", m.Op))
	}
}

func parseKind(kind, via string) (clip.Kind, clip.Via, error) {
	var k clip.Kind
	var v clip.Via
	if kind == "" {
		kind = control.KindText
	}
	if via == "" {
		via = control.ViaCopy
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
		return s.errNoGroup()
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
	id, busy := s.id, s.window != nil || s.opening
	joining := s.joining
	if !busy && !joining {
		s.opening = true
	}
	s.mu.Unlock()
	switch {
	case busy:
		fail(c, errors.New("a pairing window is already open"))
		return
	case joining:
		fail(c, errors.New("this device is joining a group"))
		return
	}
	// end closes the window, or ends the opening; it runs before the last
	// answer, so the client can pair again at once.
	var w *pair.Window
	ended := false
	end := func() {
		if ended {
			return
		}
		ended = true
		if w != nil {
			w.Close()
		}
		s.mu.Lock()
		if s.window != nil && s.window == w {
			s.window = nil
			s.responder.SetTXT(s.txtLocked())
		}
		s.opening = false
		s.mu.Unlock()
	}
	defer end()
	abort := func(err error) {
		end()
		fail(c, err)
	}
	if id == nil {
		var err error
		if id, err = group.Create(time.Now()); err == nil {
			err = id.Save(s.cfg.StateDir)
		}
		if err == nil {
			err = s.startGroup(id)
		}
		if err != nil {
			abort(fmt.Errorf("creating the group: %w", err))
			return
		}
		s.logf("clipbridge: created a new group %s", group.Tag(id.GroupCA.Cert))
	}
	code := pair.NewCode()
	opened, err := pair.Open(id, code, pair.Options{})
	if err != nil {
		abort(err)
		return
	}
	w = opened
	s.mu.Lock()
	s.window, s.opening = w, false
	s.responder.SetTXT(s.txtLocked())
	port := s.port
	s.mu.Unlock()
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
		abort(err)
		return
	}
	if !res.Confirmed {
		// It holds a certificate, and on Linux the CA keys, but may not
		// have stored them.
		s.logf("clipbridge: %s (%s) got its certificate but did not confirm it stored it", res.Info.Name, res.Device)
		abort(fmt.Errorf("%s got its certificate but did not confirm that it stored it; check it with clipbridge status there, and pair it again if needed", res.Info.Name))
		return
	}
	s.logf("clipbridge: %s (%s) joined the group", res.Info.Name, res.Device)
	end()
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

// joinTimeout bounds a whole join: browsing, dialing and the attempt.
const joinTimeout = 2 * time.Minute

// join joins a group with a code: at the address the user gave, or at the
// one Linux member that announces an open pairing window. It tries that
// member's addresses until one answers, and stops after the first attempt
// in which the other side could check the code, so a device on the network
// that only pretends to pair gets one guess at most. A client that hangs up
// cancels the join.
func (s *Service) join(ctx context.Context, c net.Conn, r *control.Reader, m *control.Message) {
	code, err := pair.NormalizeCode(m.Code)
	if err != nil {
		fail(c, err)
		return
	}
	s.mu.Lock()
	inGroup, busy := s.id != nil, s.joining || s.opening
	if !inGroup && !busy {
		s.joining = true
	}
	s.mu.Unlock()
	switch {
	case inGroup:
		fail(c, errors.New("this device is already in a group"))
		return
	case busy:
		fail(c, errors.New("a join or a pairing is already running here"))
		return
	}
	// end ends the join; it runs before the answer, so the client can try
	// again at once.
	ended := false
	end := func() {
		if !ended {
			ended = true
			s.mu.Lock()
			s.joining = false
			s.mu.Unlock()
		}
	}
	defer end()
	abort := func(err error) {
		end()
		fail(c, err)
	}
	ctx, cancel := context.WithTimeout(ctx, joinTimeout)
	defer cancel()
	go func() {
		r.Read() // returns when the client hangs up, or when the join ends
		cancel()
	}()

	// A Linux member gets the CA keys and can admit devices; a Mac cannot.
	osName := "darwin"
	if s.cfg.Role == node.Linux {
		osName = "linux"
	}
	j, err := pair.NewJoiner(pair.Info{Name: s.cfg.Name, OS: osName})
	if err != nil {
		abort(err)
		return
	}
	addrs := []string{m.Address}
	if m.Address == "" {
		if addrs, err = s.findPairing(ctx); err != nil {
			abort(err)
			return
		}
	}
	var lastErr error
	for i, addr := range addrs {
		if i == pair.MaxFailures {
			break
		}
		d := net.Dialer{Timeout: handshakeTimeout}
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		id, err := j.Join(ctx, raw, code, func(id *group.Identity) error { return id.Save(s.cfg.StateDir) })
		if err != nil {
			if ctx.Err() != nil {
				err = fmt.Errorf("the join was cancelled or took too long: %w", err)
			}
			lastErr = err
			if pair.Spent(err) || ctx.Err() != nil {
				break
			}
			continue
		}
		if err := s.startGroup(id); err != nil {
			abort(err)
			return
		}
		end()
		reply(c, control.Header{Done: true}, nil)
		return
	}
	abort(lastErr)
}

// findPairing returns the addresses of the one member that announces an
// open pairing window, best first, browsing for up to ten seconds. When
// more than one announces a window, it refuses: the user gives the address
// that pair showed.
func (s *Service) findPairing(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.browseFor)
	defer cancel()
	found := make(chan []mdns.Peer, 1)
	d, err := s.cfg.Discover(DiscoveryConfig{
		ID: "browse-" + clip.NewID()[:16], BrowseOnly: true, Logf: s.logf,
		OnPeers: func(peers []mdns.Peer) {
			var open []mdns.Peer
			for _, p := range peers {
				if v, _ := p.TXTValue("p"); v == "1" && len(p.Addrs) > 0 {
					open = append(open, p)
				}
			}
			if len(open) > 0 {
				select {
				case found <- open:
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
	case open := <-found:
		if len(open) > 1 {
			var ids []string
			for _, p := range open {
				ids = append(ids, p.ID)
			}
			return nil, fmt.Errorf("%d devices announce a pairing window (%s); give the address that clipbridge pair showed", len(open), strings.Join(ids, ", "))
		}
		return addresses(open[0]), nil
	case <-ctx.Done():
		return nil, errors.New("no member with an open pairing window found; run clipbridge pair on a Linux member, or give its address")
	}
}

// watcher is a desktop connector or pasteboard agent connected to the
// socket.
type watcher struct {
	out chan node.Write
}

// send queues a write. A watcher that does not keep up loses its oldest
// queued write, never the newest: the clipboard must end on the latest.
func (w *watcher) send(wr node.Write) {
	for {
		select {
		case w.out <- wr:
			return
		default:
		}
		select {
		case <-w.out:
		default:
		}
	}
}

// watch serves a watcher: writes go out, reported copies come in. The watch
// request carries what the clipboard holds. A write that no watcher got,
// such as the group's text after the service started, goes to the clipboard
// instead, if it is still the member's own text.
func (s *Service) watch(ctx context.Context, c net.Conn, r *control.Reader, m *control.Message) {
	w := &watcher{out: make(chan node.Write, 16)}
	s.mu.Lock()
	eng := s.eng
	if eng == nil {
		s.mu.Unlock()
		fail(c, s.errNoGroup())
		return
	}
	replay := false
	if p := s.pending; p != nil {
		text, _, _, ok := eng.Local()
		replay = ok && text == p.Text
		s.pending = nil
		if replay {
			w.send(*p)
		}
	}
	if !replay && len(m.Payload) > 0 {
		if kind, _, err := parseKind(m.Kind, m.Via); err != nil {
			s.logf("clipbridge: a watcher reported a clipboard that is not understood: %v", err)
		} else {
			eng.ClipboardIs(string(m.Payload), kind)
		}
	}
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
				s.logf("clipbridge: a watcher's report is not understood: %v", err)
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
			default:
				s.logf("clipbridge: a watcher sent %q, which is not a report", m.Op)
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
