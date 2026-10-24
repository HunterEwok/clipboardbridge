// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/phone"
	"github.com/HunterEwok/clipboardbridge/internal/version"
)

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
	if !s.mac() {
		return errors.New("this device is in no group; run cbb pair here to start one, or cbb join to join one")
	}
	return errors.New("this device is in no group; run cbb pair on a Linux or Windows member, then cbb join here")
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
	case control.OpPairPhone:
		s.pairPhone(ctx, c, r)
	case control.OpJoin:
		s.join(ctx, c, r, m)
	case control.OpInvite:
		s.invite(ctx, c, r, m)
	case control.OpWatch:
		s.watch(ctx, c, r, m)
	case control.OpDevices:
		devs, err := s.devices()
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Devices: devs, Done: true}, nil)
	case control.OpAway:
		if err := s.away(m); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpHolder:
		if err := s.setHolder(m.Name); err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Status: s.status(), Done: true}, nil)
	case control.OpRevoke:
		name, err := s.revoke(m.Name)
		if err != nil {
			fail(c, err)
			return
		}
		reply(c, control.Header{Name: name, Done: true}, nil)
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
	st := &control.Status{Role: string(s.cfg.Role), OS: s.cfg.OS, Version: version.String(), Holder: s.holder,
		HoldSetting: s.holdSetting, HoldPriority: s.priorityLocked(s.id), Battery: s.battery}
	if s.id == nil {
		return st
	}
	st.Device, st.Group = string(s.id.ID), group.Tag(s.id.GroupCA.Cert)
	skews := s.eng.Skews()
	for _, p := range s.nd.Peers() {
		st.Peers = append(st.Peers, control.Device{ID: string(p.ID), Role: string(p.Role), OS: p.OS, SkewMS: skews[string(p.ID)].Milliseconds()})
	}
	st.Away = s.awayStatus()
	return st
}

// pair opens a pairing window and reports its end; a client that hangs up
// closes the window. On a Linux device in no group, it creates the group
// first.
func (s *Service) pair(ctx context.Context, c net.Conn, r *control.Reader) {
	w, _, end, err := s.openWindow(pair.NewCode(), true, true)
	if err != nil {
		fail(c, err)
		return
	}
	defer end()
	s.mu.Lock()
	port := s.port
	s.mu.Unlock()
	reply(c, control.Header{Code: w.Code(), Expires: int(pair.Lifetime / time.Second), Address: localAddress(port)}, nil)
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
	res, err := s.windowResult(w)
	end()
	if err != nil {
		fail(c, err)
		return
	}
	reply(c, control.Header{Name: res.Info.Name, Done: true}, nil)
}

// openWindow reserves the pairing window and opens it with code. On a
// Linux device in no group it first creates the group, when create is set.
// With announce, the window is published and takes pairing connections on
// the member port; without, it only serves the member's own dials to a
// listening joiner. end closes the window and frees it; it may be called
// more than once, and runs before the last answer to a client, so it can
// pair again at once.
func (s *Service) openWindow(code string, create, announce bool) (*pair.Window, *group.Identity, func(), error) {
	if s.mac() {
		return nil, nil, nil, errors.New("a Mac cannot admit devices yet; run cbb pair on a Linux or Windows member")
	}
	s.mu.Lock()
	id, busy, joining := s.id, s.window != nil || s.dialWindow != nil || s.opening, s.joining
	if !busy && !joining {
		s.opening = true
	}
	s.mu.Unlock()
	switch {
	case busy:
		return nil, nil, nil, errors.New("a pairing window is already open")
	case joining:
		return nil, nil, nil, errors.New("this device is joining a group")
	}
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
		if s.dialWindow != nil && s.dialWindow == w {
			s.dialWindow = nil
		}
		s.opening = false
		s.mu.Unlock()
	}
	if id == nil {
		if !create {
			end()
			return nil, nil, nil, s.errNoGroup()
		}
		var err error
		if id, err = s.createGroup(); err != nil {
			end()
			return nil, nil, nil, err
		}
	}
	opened, err := pair.Open(id, code, pair.Options{})
	if err != nil {
		end()
		return nil, nil, nil, err
	}
	w = opened
	s.mu.Lock()
	if announce {
		s.window = w
		s.responder.SetTXT(s.txtLocked())
	} else {
		s.dialWindow = w
	}
	s.opening = false
	s.mu.Unlock()
	return w, id, end, nil
}

// createGroup creates a group on a Linux device in no group and starts it.
// One creation runs at a time, so two requests cannot save two identities.
func (s *Service) createGroup() (*group.Identity, error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id != nil {
		return id, nil // another request created it meanwhile
	}
	id, err := group.Create(time.Now())
	if err == nil {
		err = id.Save(s.cfg.StateDir)
	}
	if err == nil {
		err = s.startGroup(id)
	}
	if err != nil {
		return nil, fmt.Errorf("creating the group: %w", err)
	}
	s.logf("cbb: created a new group %s", group.Tag(id.GroupCA.Cert))
	return id, nil
}

// windowResult returns how a window that closed ended, and logs it.
func (s *Service) windowResult(w *pair.Window) (*pair.Result, error) {
	res, err := w.Result()
	if err != nil {
		return nil, err
	}
	if !res.Confirmed {
		// It holds a certificate, and on Linux the CA keys, but may not
		// have stored them.
		s.logf("cbb: %s (%s) got its certificate but did not confirm it stored it", res.Info.Name, res.Device)
		return nil, fmt.Errorf("%s got its certificate but did not confirm that it stored it; check it with cbb status there, and pair it again if needed", res.Info.Name)
	}
	s.logf("cbb: %s (%s) joined the group", res.Info.Name, res.Device)
	s.recordAdmitted(res)
	return res, nil
}

// admit adds a computer whose QR code a paired phone scanned: it dials the
// addresses in it and pairs with the computer that has the certificate the
// QR code names. The phone's token is the authority: the phone is the main
// device of the group. The window is not announced and takes no pairing
// connections, so the code is good only against that computer.
func (s *Service) admit(jc phone.JoinCode) error {
	if _, err := pair.NormalizeCode(jc.Code); err != nil {
		return err
	}
	if len(jc.Addrs) == 0 || jc.Fingerprint == "" {
		return errors.New("the QR code is from an older clipboardbridge; update clipboardbridge on the computer")
	}
	w, _, end, err := s.openWindow(jc.Code, false, false)
	if err != nil {
		return err
	}
	s.logf("cbb: the iPhone asked to add a computer at %s", strings.Join(jc.Addrs, ", "))
	go func() {
		defer end()
		ctx, cancel := context.WithTimeout(context.Background(), joinTimeout)
		defer cancel()
		stop := context.AfterFunc(ctx, w.Close)
		defer stop()
		var lastErr error
		for _, addr := range jc.Addrs {
			d := net.Dialer{Timeout: handshakeTimeout}
			raw, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				lastErr = err
				continue
			}
			if lastErr = w.Dial(ctx, raw, jc.Fingerprint); closed(w) {
				break
			}
		}
		if !closed(w) {
			s.logf("cbb: adding a computer from the iPhone: %v", lastErr)
			return
		}
		if _, err := s.windowResult(w); err != nil {
			s.logf("cbb: adding a computer from the iPhone: %v", err)
		}
	}()
	return nil
}

// closed reports whether a window has closed.
func closed(w *pair.Window) bool {
	select {
	case <-w.Done():
		return true
	default:
		return false
	}
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

// join joins a group with a code. With Listen it waits for a member to dial
// this device, at the addresses and with the certificate it answers with
// first, for the QR code; otherwise it dials the address the user gave, or
// the one Linux member that announces an open pairing window; with an
// invitation, it joins through the hub's tunnel (invite.go). A client that
// hangs up cancels the join.
func (s *Service) join(ctx context.Context, c net.Conn, r *control.Reader, m *control.Message) {
	var code string
	var err error
	if m.Invite == "" {
		if code, err = pair.NormalizeCode(m.Code); err != nil {
			fail(c, err)
			return
		}
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
	wait := joinTimeout + s.cfg.browseFor
	if m.Invite != "" {
		wait = joinTimeout + confirmWait
	} else if m.Listen {
		wait = pair.Lifetime
		if m.Expires > 0 {
			wait = min(time.Duration(m.Expires)*time.Second, wait)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	go func() {
		r.Read() // returns when the client hangs up, or when the join ends
		cancel()
	}()

	j, err := pair.NewJoiner(pair.Info{Name: s.cfg.Name, OS: s.cfg.OS})
	if err != nil {
		end()
		fail(c, err)
		return
	}
	var id *group.Identity
	var after func(bool)
	switch {
	case m.Invite != "":
		id, after, err = s.joinInvite(ctx, c, j, m)
	case m.Listen:
		id, err = s.listenForMember(ctx, c, j, code)
	default:
		id, err = s.dialMember(ctx, j, code, m.Address)
	}
	if err == nil {
		err = s.startGroup(id)
		if after != nil {
			after(err == nil)
		}
	}
	end()
	if err != nil {
		fail(c, err)
		return
	}
	if !m.Listen && m.Address != "" && j.Member != "" {
		s.dialJoined(j.Member, m.Address)
	}
	reply(c, control.Header{Done: true}, nil)
}

func (s *Service) saveIdentity(id *group.Identity) error { return id.Save(s.cfg.StateDir) }

// dialMember joins at the address the user gave, or at the one member that
// announces an open pairing window. It tries that member's addresses until
// one answers, and stops after the first attempt in which the other side
// could check the code, so a device on the network that only pretends to
// pair gets one guess at most.
func (s *Service) dialMember(ctx context.Context, j *pair.Joiner, code, address string) (*group.Identity, error) {
	addrs := []string{address}
	if address == "" {
		var err error
		if addrs, err = s.findPairing(ctx, s.cfg.browseFor); err != nil {
			return nil, err
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
		id, err := j.Join(ctx, raw, code, s.saveIdentity)
		if err == nil {
			return id, nil
		}
		if ctx.Err() != nil {
			err = fmt.Errorf("the join was cancelled or took too long: %w", err)
		}
		lastErr = err
		if pair.Spent(err) || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// listenForMember waits for a member, or a phone, to dial this device and
// admit it. It first answers the client with the addresses it listens at and
// the fingerprint of the joiner's certificate, for the QR code. Only devices
// on the home network may connect, one attempt at a time; the member
// confirms the code first, so a wrong attempt reveals nothing, and the join
// ends after three of them.
func (s *Service) listenForMember(ctx context.Context, c net.Conn, j *pair.Joiner, code string) (*group.Identity, error) {
	fp, err := j.Fingerprint()
	if err != nil {
		return nil, err
	}
	ln, err := s.cfg.joinListen()
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	reply(c, control.Header{Addrs: s.cfg.joinAddrs(port), Fingerprint: fp}, nil)
	failures := 0
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil, errors.New("no device added this one in time; scan the QR code with the phone, or run cbb pair on a Linux member and cbb join -code here")
			}
			return nil, err
		}
		ap, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
		if !mdns.Published(ap.Addr()) && !ap.Addr().Unmap().IsLoopback() {
			raw.Close()
			continue
		}
		id, err := j.Accept(ctx, raw, code, s.saveIdentity)
		if err == nil {
			return id, nil
		}
		s.logf("cbb: a pairing attempt from %s failed: %v", ap.Addr(), err)
		switch {
		case ctx.Err() != nil:
			return nil, fmt.Errorf("the join was cancelled or took too long: %w", err)
		case pair.Spent(err):
			return nil, err // the welcome came, but saving failed
		case errors.Is(err, pair.ErrWrongCode):
			if failures++; failures >= pair.MaxFailures {
				return nil, pair.ErrTooMany
			}
		}
	}
}

// joinAddresses returns where a listening join can be reached: the
// addresses mDNS would publish, IPv4 first, at most four.
func joinAddresses(port uint16) []string {
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var v4, v6 []string
	for _, a := range ifaddrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		// Link-local addresses need a zone, which a QR code cannot carry.
		if !ok || !mdns.Published(ip) || ip.IsLinkLocalUnicast() {
			continue
		}
		hp := netip.AddrPortFrom(ip.Unmap(), port).String()
		if ip.Unmap().Is4() {
			v4 = append(v4, hp)
		} else {
			v6 = append(v6, hp)
		}
	}
	all := append(v4, v6...)
	return all[:min(len(all), 4)]
}

// findPairing returns the addresses of the one member that announces an
// open pairing window, best first, browsing for up to browse. When
// more than one announces a window, it refuses: the user gives the address
// that pair showed.
func (s *Service) findPairing(ctx context.Context, browse time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, browse)
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
			return nil, fmt.Errorf("%d devices announce a pairing window (%s); give the address that cbb pair showed", len(open), strings.Join(ids, ", "))
		}
		return addresses(open[0]), nil
	case <-ctx.Done():
		return nil, errors.New("no member with an open pairing window found; run cbb pair on a Linux member, or give its address")
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
			s.logf("cbb: a watcher reported a clipboard that is not understood: %v", err)
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
				s.logf("cbb: a watcher's report is not understood: %v", err)
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
				s.logf("cbb: a watcher sent %q, which is not a report", m.Op)
			}
		}
	}()
	for {
		select {
		case wr := <-w.out:
			// The clipboard will hold this text. A report that came in
			// after the engine decided on it, such as the watch request
			// itself, must not leave the engine thinking otherwise.
			if e := s.engine(); e != nil {
				if text, _, _, ok := e.Local(); !ok || text != wr.Text {
					e.ClipboardIs(wr.Text, wr.Kind)
				}
			}
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
