// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package service is the clipboardbridge service: it holds the device's identity,
// the sync engine and the member connections, publishes and browses with
// mDNS (D-12, D-32), admits devices,
// and serves the local control socket.
package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/hlc"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/phone"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// markFile holds the hybrid clock's saved mark, in the state directory.
const markFile = "hlc.mark"

// Config configures the service.
type Config struct {
	StateDir string    // identity and clock mark
	Socket   string    // the control socket
	Role     node.Role // every role listens and publishes; a computer is node.Full
	// OS is this device's operating system (group.OSLinux, OSWindows or
	// OSMacOS), shown to the others; a Mac does not admit devices yet.
	OS   string
	Name string // this device's name, shown to the others; the host name if empty
	Logf func(format string, args ...any)

	// Discover publishes this member and finds the others; mDNS if nil.
	// Tests replace it.
	Discover func(DiscoveryConfig) (Discovery, error)

	// listen opens the member port; the one Port names, or any free port,
	// on all addresses if nil.
	listen func() (net.Listener, error)
	// now is the clock for certificates; time.Now if nil.
	now func() time.Time
	// browseFor is how long join looks for a pairing window; ten seconds
	// if zero.
	browseFor time.Duration
	// joinListen opens the port a listening join waits at, the member port or any
	// free port on all addresses if nil; joinAddrs returns the addresses for its QR code,
	// joinAddresses if nil.
	joinListen func() (net.Listener, error)
	joinAddrs  func(port uint16) []string
	// battery reports whether the machine has a battery, for the holder
	// priority; hasBattery if nil.
	battery func() bool
	// fallbackAfter is how long a full member waits for one with a lower
	// device ID to dial it before it dials that one; fallbackDial if zero.
	fallbackAfter time.Duration
}

// MemberPort is the member port by default (CBB_PORT moves it, see
// Port), so a firewall can open it; a listening join, which comes before
// the device is in a group, waits there too. When it is taken, any free port
// does, since discovery and the QR code carry the port.
const MemberPort = 8764

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

// Service is a running clipboardbridge service.
type Service struct {
	cfg    Config
	clock  *hlc.Clock
	logf   func(string, ...any)
	broken *control.RequestError // the group's files cannot be read; set once at start

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
	phoneOpening  bool          // an iPhone pairing window is being opened
	phoneConns    *connListener // the shortcut's HTTPS on the member port; nil if not served
	phoneTLS      *tls.Config   // the shortcut's TLS, with phoneConns
	profileConns  *connListener // the profile's plain HTTP while an iPhone pairing window is open
	joining       bool          // a join is running
	stopping      bool          // the service is stopping: no new group, no election
	holder        bool
	holdSetting   string // HolderAuto, HolderFirst, HolderFallback or HolderNever
	battery       bool   // the machine has a battery, guessed at the start
	// pendingPhoneCA is an iPhone CA another admin sent while this one held
	// another that still stood, kept in case the records revoke that one.
	pendingPhoneCA *group.CA
	dialers        map[group.DeviceID]*dialer
	nearby         map[group.DeviceID]bool // the members of the group that discovery finds on this network
	prio           map[group.DeviceID]int  // their holder priority (TXT h), for those that can hold the name
	watchers       map[*watcher]bool
	lastSeq        uint64
	pending        *node.Write                  // a write that no watcher got, for the next one
	seen           map[group.DeviceID]time.Time // when each peer was last seen connected
	online         map[group.DeviceID]bool

	listMu  sync.Mutex     // one ensureListed at a time, so a device is recorded once
	recMu   sync.Mutex     // guards records; taken after mu, never before
	records *group.Records // the group's device records; nil while in no group

	tunMu      sync.Mutex            // guards tunnel and the rest of the tun fields; taken after mu, before recMu
	tunnel     *tunnel.State         // the tunnel keys (tunnel.go); nil while sync away from home is off
	tunCtx     context.Context       // the group's context, for the tunnel; nil while in no group
	tunSelf    string                // this device's ID, for its tunnel address
	tunRun     *tunRun               // the hub or the link to it, while it runs
	tunThrough bool                  // connected to the hub through the tunnel now
	tunErr     string                // what went wrong last, for status; "" if nothing
	tunDetail  string                // the underlying error
	tunFwd     *control.Forwarder    // on the hub: its registration with its forwarder; nil without one
	tunRelay   *control.Relay        // on a device with a relay: its link to it; nil without one
	tunRelayed int                   // member connections through the relay now
	guests     map[netip.Addr]*guest // on the hub: the guest tunnels of open remote invitations (invite.go)

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
	if cfg.listen == nil || cfg.joinListen == nil {
		port, err := Port()
		if err != nil {
			return err
		}
		if cfg.listen == nil {
			cfg.listen = func() (net.Listener, error) { return listenPreferring(port) }
		}
		if cfg.joinListen == nil {
			cfg.joinListen = func() (net.Listener, error) { return listenPreferring(port) }
		}
	}
	if cfg.joinAddrs == nil {
		cfg.joinAddrs = joinAddresses
	}
	if cfg.battery == nil {
		cfg.battery = hasBattery
	}
	if cfg.fallbackAfter == 0 {
		cfg.fallbackAfter = fallbackDial
	}
	s := &Service{cfg: cfg, logf: cfg.Logf, dialers: map[group.DeviceID]*dialer{}, watchers: map[*watcher]bool{},
		seen: map[group.DeviceID]time.Time{}, online: map[group.DeviceID]bool{}, battery: cfg.battery()}
	var err error
	if s.holdSetting, err = loadHolder(cfg.StateDir); err != nil {
		cfg.Logf("cbb: the holder setting: %v; using auto", err)
	}

	floor, err := loadMark(cfg.StateDir)
	if err != nil {
		return err
	}
	clock := hlc.NewClock(nil, floor, func(m hlc.Timestamp) error {
		err := atomicfile.Write(filepath.Join(cfg.StateDir, markFile), []byte(m.String()+"\n"), 0o600)
		if err != nil {
			cfg.Logf("cbb: saving the clock mark: %v", err)
		}
		return err
	})

	id, err := group.Load(cfg.StateDir)
	switch {
	case errors.Is(err, group.ErrNoGroup):
		cfg.Logf("cbb: this device is in no group yet")
		id = nil
	case err != nil:
		// The service keeps running without its group, so that cbb
		// says what is wrong, and refuses everything else, so that
		// nothing writes over the damaged file.
		s.broken = &control.RequestError{Msg: errBroken, Detail: err.Error()}
		cfg.Logf("cbb: %s (%v)", errBroken, err)
		id = nil
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

// errBroken is what the user sees when the device's group file cannot be
// read.
const errBroken = "this device's group file (identity.json in the service's state directory) is damaged, so the service does not start the group; restore the file from a backup, or remove clipboardbridge with its keys (uninstall --purge, -Purge on Windows), install it again and join"

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
// connections, discovery and the member port; on Linux also
// clipboardbridge.local. Its state is set only when all of it started.
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
	id = s.withAdminKey(id)
	gctx, cancel := context.WithCancel(context.Background())
	eng := clip.New(clip.Config{Self: string(id.ID), Clock: s.clock})
	s.recMu.Lock()
	s.records = s.loadRecords(id)
	s.recMu.Unlock()
	tun := s.loadTunnel(id)
	s.tunMu.Lock()
	s.tunnel, s.tunCtx, s.tunSelf = tun, gctx, string(id.ID)
	s.tunMu.Unlock()
	nd := node.New(node.Config{
		Identity: id, Role: s.cfg.Role, Name: s.cfg.Name, OS: s.cfg.OS, Engine: eng,
		OnWrite: s.write, OnPeers: s.peersChanged, OnCert: s.certRenewed, OnAdmin: s.becomeAdmin,
		PhoneCAFor: s.phoneCAFor, OnPhoneCA: s.phoneCAReceived, Now: s.cfg.now, Logf: s.logf,
		Records: recordStore{s}, Allow: s.allow,
		TunnelKey: tunnelKey(tun), OnTunnelKey: s.tunnelKeyOffered, OnTunnel: s.tunnelOffered,
	})
	// Every member listens, so that phones and lite members reach it, and
	// the other full members when it has the lower device ID.
	ln, err := s.cfg.listen()
	if err != nil {
		cancel()
		return err
	}
	dc := DiscoveryConfig{ID: string(id.ID), TXT: txt(id, s.priorityLocked(id), false), OnPeers: s.found, Logf: s.logf,
		Port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	r, err := s.cfg.Discover(dc)
	if err != nil {
		ln.Close()
		cancel()
		return err
	}

	s.id, s.eng, s.nd, s.port = id, eng, nd, dc.Port
	s.groupCtx, s.groupCancel = gctx, cancel
	if err := s.adoptRootsLocked(); err != nil {
		s.logf("cbb: trusting the group's new root: %v", err)
	}
	nd.Rejoin() // the service just started; there are no connections yet
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.renewLoop(gctx)
	}()
	go func() {
		defer s.wg.Done()
		s.ensureListed()
	}()
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.accept(gctx, ln)
	}()
	go func() {
		defer s.wg.Done()
		s.servePhone(gctx, ln.Addr())
	}()
	// Discovery has its own context, so it can say goodbye for
	// clipboardbridge.local before the member connections close.
	dctx, dcancel := context.WithCancel(gctx)
	s.responder, s.discoveryStop, s.discoveryDone = r, dcancel, make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		if err := r.Run(dctx); err != nil {
			s.logf("cbb: discovery: %v", err)
		}
	}(s.discoveryDone)
	s.electLocked() // alone, a member that can hold clipboardbridge.local holds it at once
	s.tunMu.Lock()
	s.runTunnelLocked()
	s.tunMu.Unlock()
	return nil
}

// stopGroup stops the network part: first discovery, which sends the
// goodbyes for this member's names, then the member connections, which say
// goodbye too, so the next holder takes clipboardbridge.local over at once.
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
	s.tunMu.Lock()
	s.tunCtx = nil // a control request still running may not start the tunnel again
	s.stopTunnelLocked()
	s.tunMu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

// txtLocked returns the TXT record of this member.
func (s *Service) txtLocked() []string { return txt(s.id, s.priorityLocked(s.id), s.window != nil) }

// priorityLocked returns this member's priority for clipboardbridge.local,
// 0 if it never holds the name (see priority).
func (s *Service) priorityLocked(id *group.Identity) int {
	return priority(s.holdSetting, id != nil && id.Phone != nil, s.battery)
}

// txt returns a TXT record: the protocol version, the group tag, the
// holder priority if the member can hold clipboardbridge.local, and whether
// a pairing window is open.
func txt(id *group.Identity, prio int, window bool) []string {
	t := []string{"v=1", "g=" + group.Tag(id.GroupCA.Cert)}
	if prio > 0 {
		t = append(t, "h="+strconv.Itoa(prio))
	}
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
			logf("cbb: %s: %v; trying again in %v", what, err, pause)
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
