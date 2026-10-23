// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/phone"
)

// phoneGroup is the member as the iPhone endpoint sees it.
type phoneGroup struct{ s *Service }

func (g phoneGroup) Current() (clip.Event, bool) { return g.s.engine().Current() }

func (g phoneGroup) Local() (string, clip.Kind, time.Duration, bool) { return g.s.engine().Local() }

func (g phoneGroup) Send(text string, kind clip.Kind, via clip.Via) error {
	return g.s.withNode(func(nd *node.Node) error { return nd.Send(text, kind, via) })
}

func (g phoneGroup) PhoneCA() *group.CA {
	g.s.mu.Lock()
	defer g.s.mu.Unlock()
	return g.s.id.PhoneCA
}

// homeOnly refuses requests from outside the home network.
func homeOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !(mdns.Published(ap.Addr()) || ap.Addr().Unmap().IsLoopback()) {
			http.Error(w, "only for the home network", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// servePhone serves the shortcut's HTTPS on a Linux member, until ctx is
// done: the member port at addr passes it the connections (see demux.go).
func (s *Service) servePhone(ctx context.Context, addr net.Addr) {
	s.mu.Lock()
	admin := s.id.Phone != nil
	s.mu.Unlock()
	if !admin {
		return
	}
	// The certificate is looked up for each connection, so a renewed one
	// is used at once.
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.id.PhoneCertificate(), nil
		}}
	mux := http.NewServeMux()
	mux.Handle("/sync", phone.SyncHandler(phoneGroup{s}))
	mux.Handle("/admit", phone.AdmitHandler(phoneGroup{s}, s.admit))
	mux.Handle("/pair", phone.PairHandler(func() *phone.Window {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.phoneWindow
	}))
	srv := &http.Server{Handler: homeOnly(mux), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ln := newConnListener(addr)
	s.mu.Lock()
	s.phoneConns, s.phoneTLS = ln, cfg
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		s.phoneConns, s.phoneTLS = nil, nil
		s.mu.Unlock()
		srv.Close()
	}()
	// The connections come with their TLS handshake done.
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logf("cbb: the shortcut's HTTPS: %v", err)
	}
}

// pairPhone opens an iPhone pairing window on the member that answers for
// clipboardbridge.local, serves the profile while it is open, and reports the
// end; a client that hangs up closes the window.
func (s *Service) pairPhone(ctx context.Context, c net.Conn, r *control.Reader) {
	// The phone is the group's main device: pairing it with the first
	// computer creates the group.
	if s.engine() == nil && s.cfg.Role == node.Linux {
		if _, err := s.createGroup(); err != nil {
			fail(c, err)
			return
		}
	}
	s.mu.Lock()
	id, holder, busy := s.id, s.holder, s.phoneWindow != nil || s.phoneOpening
	ok := id != nil && id.Admin() && holder && !busy
	if ok {
		s.phoneOpening = true
	}
	s.mu.Unlock()
	switch {
	case id == nil || !id.Admin():
		fail(c, errors.New("only a Linux member in a group can pair an iPhone; run cbb pair on it first"))
		return
	case !holder:
		fail(c, errors.New("this member does not answer for clipboardbridge.local; run cbb pair -phone on the member that cbb status shows as holding it"))
		return
	case busy:
		fail(c, errors.New("an iPhone pairing window is already open"))
		return
	}
	// end closes the window and the profile; it runs before the last
	// answer, so the client can pair again at once.
	var w *phone.Window
	var srv *http.Server
	ended := false
	end := func() {
		if ended {
			return
		}
		ended = true
		if w != nil {
			w.Close()
		}
		if srv != nil {
			srv.Close()
		}
		s.mu.Lock()
		if s.phoneWindow == w {
			s.phoneWindow, s.profileConns = nil, nil
		}
		s.phoneOpening = false
		s.mu.Unlock()
	}
	defer end()
	abort := func(err error) {
		end()
		fail(c, err)
	}
	code := pair.NewCode()
	opened, err := phone.OpenWindow(id.PhoneCA, code)
	if err != nil {
		abort(err)
		return
	}
	w = opened
	// The profile is plain HTTP on the member port, which passes it the
	// connections that do not start with TLS (see demux.go).
	s.mu.Lock()
	port := s.port
	s.mu.Unlock()
	ln := newConnListener(&net.TCPAddr{Port: int(port)})
	srv = &http.Server{Handler: homeOnly(phone.ProfileHandler(id.PhoneCA)), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	go srv.Serve(ln)
	s.mu.Lock()
	s.phoneWindow, s.phoneOpening, s.profileConns = w, false, ln
	s.mu.Unlock()
	reply(c, control.Header{Code: code, Expires: int(pair.Lifetime / time.Second), Fingerprint: phone.Fingerprint(id.PhoneCA),
		Address: localAddress(port)}, nil)
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
	phoneID, err := w.Result()
	if err != nil {
		abort(err)
		return
	}
	s.logf("cbb: an iPhone (%s) was paired", phoneID)
	s.recordPhone(phoneID)
	end()
	reply(c, control.Header{Name: phoneID, Done: true}, nil)
}
