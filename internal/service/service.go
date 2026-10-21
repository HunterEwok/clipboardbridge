// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package service is the clipbridge service: it holds the device's identity,
// the sync engine and the member connections, publishes and browses with
// mDNS on Linux and only browses on a Mac (D-32), admits devices, and serves
// the local control socket.
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
	"time"

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

	// Discover publishes this member and finds the others; mDNS if nil, on
	// a Mac in browse-only mode. Tests replace it.
	Discover func(DiscoveryConfig) (Discovery, error)

	// listen opens the member port; MemberPort, or any free port, on all
	// addresses if nil.
	listen func() (net.Listener, error)
	// now is the clock for certificates; time.Now if nil.
	now func() time.Time
	// browseFor is how long join looks for a pairing window; ten seconds
	// if zero.
	browseFor time.Duration
	// joinListen opens the port a listening join waits at, JoinPort or any
	// free port on all addresses if nil; joinAddrs returns the addresses for its QR code,
	// joinAddresses if nil.
	joinListen func() (net.Listener, error)
	joinAddrs  func(port uint16) []string
	// phoneListen and profileListen open the iPhone's ports; PhonePort and
	// ProfilePort on all addresses if nil.
	phoneListen, profileListen func() (net.Listener, error)
}

// MemberPort and JoinPort are the ports the member port and a listening
// join prefer, so a firewall can open them; when one is taken, any free
// port does, since discovery and the QR code carry the port.
const (
	MemberPort = 8764
	JoinPort   = 8767
)

// listenPreferring listens on port on all addresses, or on any free port if
// that one is taken.
func listenPreferring(port int) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		ln, err = net.Listen("tcp", ":0")
	}
	return ln, err
}

// maxHandshakes is how many connections to the member port may wait for
// their TLS handshake, or run a pairing attempt, at once.
const maxHandshakes = 32

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

	createMu      sync.Mutex // one group creation at a time
	mu            sync.Mutex
	id            *group.Identity // nil while the device is in no group
	eng           *clip.Engine    // made with the identity
	nd            *node.Node
	responder     Discovery
	discoveryStop context.CancelFunc
	discoveryDone chan struct{}
	port          uint16
	window        *pair.Window // announced; takes pairing connections
	dialWindow    *pair.Window // not announced; dials a listening joiner for the phone
	opening       bool         // a pairing window is being opened, maybe with a new group
	phoneWindow   *phone.Window
	phoneOpening  bool // an iPhone pairing window is being opened
	joining       bool // a join is running
	stopping      bool // the service is stopping: no new group, no election
	holder        bool
	dialers       map[group.DeviceID]*dialer
	watchers      map[*watcher]bool
	lastSeq       uint64
	pending       *node.Write // a write that no watcher got, for the next one

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
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.browseFor == 0 {
		cfg.browseFor = 10 * time.Second
	}
	if cfg.listen == nil {
		cfg.listen = func() (net.Listener, error) { return listenPreferring(MemberPort) }
	}
	if cfg.joinListen == nil {
		cfg.joinListen = func() (net.Listener, error) { return listenPreferring(JoinPort) }
	}
	if cfg.joinAddrs == nil {
		cfg.joinAddrs = joinAddresses
	}
	if cfg.phoneListen == nil {
		cfg.phoneListen = func() (net.Listener, error) { return net.Listen("tcp", fmt.Sprintf(":%d", PhonePort)) }
	}
	if cfg.profileListen == nil {
		cfg.profileListen = func() (net.Listener, error) { return net.Listen("tcp", fmt.Sprintf(":%d", ProfilePort)) }
	}
	s := &Service{cfg: cfg, logf: cfg.Logf, dialers: map[group.DeviceID]*dialer{}, watchers: map[*watcher]bool{}}

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
		if err := s.startGroup(id); err != nil {
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
// clipbridge.local. A Mac only browses. Its state is set only when all of it
// started.
//
// The group's context does not derive from Run's: only stopGroup ends it,
// after the goodbyes, so a stopping service leaves in order.
func (s *Service) startGroup(id *group.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.stopping:
		return errors.New("the service is stopping")
	case s.id != nil:
		return errors.New("this device is already in a group")
	}
	gctx, cancel := context.WithCancel(context.Background())
	eng := clip.New(clip.Config{Self: string(id.ID), Clock: s.clock})
	nd := node.New(node.Config{
		Identity: id, Role: s.cfg.Role, Engine: eng,
		OnWrite: s.write, OnPeers: s.peersChanged, OnCert: s.certRenewed, Now: s.cfg.now, Logf: s.logf,
	})
	dc := DiscoveryConfig{ID: string(id.ID), TXT: txt(id, false), OnPeers: s.found, Logf: s.logf, BrowseOnly: s.cfg.Role != node.Linux}
	var ln net.Listener
	if s.cfg.Role == node.Linux {
		var err error
		if ln, err = s.cfg.listen(); err != nil {
			cancel()
			return err
		}
		dc.Port = uint16(ln.Addr().(*net.TCPAddr).Port)
	}
	r, err := s.cfg.Discover(dc)
	if err != nil {
		if ln != nil {
			ln.Close()
		}
		cancel()
		return err
	}

	s.id, s.eng, s.nd, s.port = id, eng, nd, dc.Port
	s.groupCtx, s.groupCancel = gctx, cancel
	nd.Rejoin() // the service just started; there are no connections yet
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.renewLoop(gctx)
	}()
	if ln != nil {
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
	s.stopping = true
	cancel, nd, w, dw, pw := s.groupCancel, s.nd, s.window, s.dialWindow, s.phoneWindow
	stopDiscovery, discoveryDone := s.discoveryStop, s.discoveryDone
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
	if dw != nil {
		dw.Close()
	}
	if pw != nil {
		pw.Close()
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

// txtLocked returns the TXT record of this member.
func (s *Service) txtLocked() []string { return txt(s.id, s.window != nil) }

// txt returns a TXT record: the protocol version, the group tag, and
// whether a pairing window is open.
func txt(id *group.Identity, window bool) []string {
	t := []string{"v=1", "g=" + group.Tag(id.GroupCA.Cert)}
	if window {
		t = append(t, "p=1")
	}
	return t
}

// accept serves the member port: pairing connections while a window is
// open, member connections otherwise. Only addresses of the home network
// are accepted, and at most maxHandshakes connections that have not yet
// proved they belong to the group.
func (s *Service) accept(ctx context.Context, ln net.Listener) {
	slots := make(chan struct{}, maxHandshakes)
	acceptLoop(ctx, ln, s.logf, "the member port", func(raw net.Conn) {
		ap, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
		if !mdns.Published(ap.Addr()) && !ap.Addr().Unmap().IsLoopback() {
			raw.Close()
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			raw.Close()
			return
		}
		go s.serveMember(ctx, raw, func() { <-slots })
	})
}

// acceptLoop accepts connections until ctx is done or ln is closed. Other
// errors, such as running out of file descriptors, only pause it, with a
// growing pause as net/http does.
func acceptLoop(ctx context.Context, ln net.Listener, logf func(string, ...any), what string, handle func(net.Conn)) {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	defer ln.Close()
	var pause time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			pause = min(max(2*pause, 5*time.Millisecond), time.Second)
			logf("clipbridge: %s: %v; trying again in %v", what, err, pause)
			select {
			case <-ctx.Done():
				return
			case <-time.After(pause):
			}
			continue
		}
		pause = 0
		handle(c)
	}
}
