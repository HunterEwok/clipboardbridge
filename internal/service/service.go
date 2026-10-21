// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package service is the clipbridge service: it holds the device's identity,
// the sync engine and the member connections, publishes and browses on
// Linux, admits devices, and serves the local control socket.
package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/HunterEwok/clipbridge/internal/atomicfile"
	"github.com/HunterEwok/clipbridge/internal/clip"
	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/hlc"
	"github.com/HunterEwok/clipbridge/internal/mdns"
	"github.com/HunterEwok/clipbridge/internal/node"
	"github.com/HunterEwok/clipbridge/internal/pair"
	"github.com/HunterEwok/clipbridge/internal/phone"
)

// markFile holds the hybrid clock's saved mark, in the state directory.
const markFile = "hlc.mark"

// Config configures the service.
type Config struct {
	StateDir string    // identity and clock mark
	Socket   string    // the control socket
	Role     node.Role // Linux listens and publishes; a Mac only dials
	Name     string    // this device's name, shown to the others; the host name if empty
	Logf     func(format string, args ...any)

	// Discover publishes this member and finds the others; mDNS if nil.
	// Tests replace it, and the Mac's Bonjour browser will plug in here.
	Discover func(DiscoveryConfig) (Discovery, error)

	// listen opens the member port; any port on all addresses if nil.
	listen func() (net.Listener, error)
	// phoneListen and profileListen open the iPhone's ports; 8765 and
	// 8766 on all addresses if nil.
	phoneListen, profileListen func() (net.Listener, error)
}

// DiscoveryConfig is what discovery publishes and whom it tells.
type DiscoveryConfig struct {
	ID         string
	Port       uint16
	TXT        []string
	BrowseOnly bool // find members without publishing this device
	OnPeers    func([]mdns.Peer)
	Logf       func(string, ...any)
}

// Discovery publishes a member and finds the others.
type Discovery interface {
	Run(ctx context.Context) error
	SetTXT(txt []string)
	SetHolder(hold bool)
}

func mdnsDiscovery(c DiscoveryConfig) (Discovery, error) {
	return mdns.New(mdns.Config{ID: c.ID, Port: c.Port, TXT: c.TXT, BrowseOnly: c.BrowseOnly, OnPeers: c.OnPeers, Logf: c.Logf})
}

// Service is a running clipbridge service.
type Service struct {
	cfg   Config
	clock *hlc.Clock
	logf  func(string, ...any)

	mu            sync.Mutex
	id            *group.Identity // nil while the device is in no group
	eng           *clip.Engine    // made with the identity
	nd            *node.Node
	responder     Discovery
	discoveryStop context.CancelFunc
	discoveryDone chan struct{}
	port          uint16
	window        *pair.Window
	phoneWindow   *phone.Window
	holder        bool
	dialers       map[group.DeviceID]context.CancelFunc
	watchers      map[*watcher]bool
	lastSeq       uint64

	groupCtx    context.Context
	groupCancel context.CancelFunc
	wg          sync.WaitGroup
}

// Run runs the service until ctx is done.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Name == "" {
		cfg.Name, _ = os.Hostname()
	}
	if cfg.Discover == nil {
		cfg.Discover = mdnsDiscovery
	}
	if cfg.listen == nil {
		cfg.listen = func() (net.Listener, error) { return net.Listen("tcp", ":0") }
	}
	if cfg.phoneListen == nil {
		cfg.phoneListen = func() (net.Listener, error) { return net.Listen("tcp", fmt.Sprintf(":%d", PhonePort)) }
	}
	if cfg.profileListen == nil {
		cfg.profileListen = func() (net.Listener, error) { return net.Listen("tcp", fmt.Sprintf(":%d", ProfilePort)) }
	}
	s := &Service{cfg: cfg, logf: cfg.Logf, dialers: map[group.DeviceID]context.CancelFunc{}, watchers: map[*watcher]bool{}}

	floor, err := loadMark(cfg.StateDir)
	if err != nil {
		return err
	}
	clock := hlc.NewClock(nil, floor, func(m hlc.Timestamp) error {
		err := atomicfile.Write(filepath.Join(cfg.StateDir, markFile), []byte(m.String()+"\n"), 0o600)
		if err != nil {
			cfg.Logf("clipbridge: saving the clock mark: %v", err)
		}
		return err
	})

	id, err := group.Load(cfg.StateDir)
	switch {
	case errors.Is(err, group.ErrNoGroup):
		cfg.Logf("clipbridge: this device is in no group yet")
		id = nil
	case err != nil:
		return err
	}
	s.clock = clock

	ln, err := listenControl(cfg.Socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	go s.serveControl(ctx, ln)

	if id != nil {
		if err := s.startGroup(ctx, id); err != nil {
			return err
		}
	}
	go s.watchSleep(ctx)

	<-ctx.Done()
	s.stopGroup()
	return nil
}

// engine returns the sync engine, or nil while the device is in no group.
func (s *Service) engine() *clip.Engine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eng
}

func loadMark(dir string) (hlc.Timestamp, error) {
	data, err := os.ReadFile(filepath.Join(dir, markFile))
	if errors.Is(err, os.ErrNotExist) {
		return hlc.Timestamp{}, nil
	}
	if err != nil {
		return hlc.Timestamp{}, err
	}
	var ts hlc.Timestamp
	if err := ts.UnmarshalText([]byte(strings.TrimSpace(string(data)))); err != nil {
		return hlc.Timestamp{}, fmt.Errorf("%s: %w", markFile, err)
	}
	return ts, nil
}

// startGroup starts the network part with an identity: the member
// connections and discovery; on Linux also the member port, publishing and
// clipbridge.local. A Mac only browses.
func (s *Service) startGroup(ctx context.Context, id *group.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	gctx, cancel := context.WithCancel(ctx)
	s.id, s.groupCtx, s.groupCancel = id, gctx, cancel
	s.eng = clip.New(clip.Config{Self: string(id.ID), Clock: s.clock})
	s.nd = node.New(node.Config{
		Identity: id, Role: s.cfg.Role, Engine: s.eng,
		OnWrite: s.write, OnPeers: s.peersChanged, Logf: s.logf,
	})
	s.nd.Rejoin() // the service just started
	dc := DiscoveryConfig{ID: string(id.ID), TXT: s.txtLocked(), OnPeers: s.found, Logf: s.logf, BrowseOnly: s.cfg.Role != node.Linux}
	if s.cfg.Role == node.Linux {
		ln, err := s.cfg.listen()
		if err != nil {
			cancel()
			return err
		}
		s.port = uint16(ln.Addr().(*net.TCPAddr).Port)
		dc.Port = s.port
		s.wg.Add(2)
		go func() {
			defer s.wg.Done()
			s.accept(gctx, ln)
		}()
		go func() {
			defer s.wg.Done()
			s.servePhone(gctx)
		}()
	}
	r, err := s.cfg.Discover(dc)
	if err != nil {
		cancel()
		return err
	}
	// Discovery has its own context, so it can say goodbye for
	// clipbridge.local before the member connections close.
	dctx, dcancel := context.WithCancel(gctx)
	s.responder, s.discoveryStop, s.discoveryDone = r, dcancel, make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		if err := r.Run(dctx); err != nil {
			s.logf("clipbridge: discovery: %v", err)
		}
	}(s.discoveryDone)
	s.electLocked() // alone, a Linux member holds clipbridge.local at once
	return nil
}

// stopGroup stops the network part: first discovery, which sends the
// goodbyes for this member's names, then the member connections, which say
// goodbye too, so the next holder takes clipbridge.local over at once.
func (s *Service) stopGroup() {
	s.mu.Lock()
	cancel, nd, w := s.groupCancel, s.nd, s.window
	stopDiscovery, discoveryDone := s.discoveryStop, s.discoveryDone
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
	if stopDiscovery != nil {
		stopDiscovery()
		<-discoveryDone
	}
	if nd != nil {
		nd.Close()
	}
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

// txtLocked returns the TXT record: the protocol version, the group tag,
// and whether a pairing window is open.
func (s *Service) txtLocked() []string {
	txt := []string{"v=1", "g=" + group.Tag(s.id.GroupCA.Cert)}
	if s.window != nil {
		txt = append(txt, "p=1")
	}
	return txt
}

// accept serves the member port: pairing connections while a window is
// open, member connections otherwise. Only addresses of the home network
// are accepted.
func (s *Service) accept(ctx context.Context, ln net.Listener) {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		ap, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
		if !mdns.Published(ap.Addr()) && !ap.Addr().Unmap().IsLoopback() {
			raw.Close()
			continue
		}
		go s.serveMember(ctx, raw)
	}
}
