// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/forward"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/netguard"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/relay"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
	"github.com/HunterEwok/clipboardbridge/internal/uptime"
	"github.com/HunterEwok/clipboardbridge/internal/vless"
)

// The tunnel keys travel inside the member protocol (docs/protocol.md,
// section 11): every member offers its WireGuard public key in its hello,
// the group's hub admits it and answers with its own key, the member's
// preshared key and its addresses, and the member keeps that offer. Since
// it happens only inside member TLS, a device gets into the tunnel only
// after it met the hub as a member, and only with the key that member sent.
// None of it happens on a device where the user has not turned sync away
// from home on.

// loadTunnel reads the tunnel state for the group of id. Sync away from
// home is off until the user turns it on, which writes the state file; until
// then, or when the state cannot be read, the member offers no tunnel key and
// keeps no offer: it syncs at home only.
func (s *Service) loadTunnel(id *group.Identity) *tunnel.State {
	if _, err := os.Stat(filepath.Join(s.cfg.StateDir, tunnel.StateFile)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	st, err := tunnel.LoadState(s.cfg.StateDir)
	if err != nil {
		s.logf("cbb: sync away from home is off: %v", err)
		return nil
	}
	tag := group.Tag(id.GroupCA.Cert)
	if st.Group != "" && st.Group != tag {
		// It was turned on for another group; this one has to ask again.
		if err := os.Remove(filepath.Join(s.cfg.StateDir, tunnel.StateFile)); err != nil {
			s.logf("cbb: sync away from home is off: %v", err)
		} else {
			s.logf("cbb: sync away from home is off, since this device is in another group now")
		}
		return nil
	}
	if st.ForGroup(tag) {
		if err := st.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: sync away from home is off: %v", err)
			return nil
		}
	}
	return st
}

// tunnelKey returns this member's WireGuard public key for its hello; nil
// when the tunnel state could not be read.
func tunnelKey(st *tunnel.State) []byte {
	if st == nil {
		return nil
	}
	k := st.Key.Public()
	return k[:]
}

// tunnelKeyOffered admits the tunnel key a peer offered, if this member is
// the group's hub, and returns the offer for the peer.
func (s *Service) tunnelKeyOffered(peer group.DeviceID, chain []*x509.Certificate, key []byte) *node.TunnelOffer {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil || !st.IsHub {
		return nil
	}
	var pub tunnel.Key
	if len(key) != len(pub) {
		s.logf("cbb: %s offered a tunnel key of %d bytes", peer, len(key))
		return nil
	}
	copy(pub[:], key)
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	m, changed, err := st.Admit(string(peer), pub, ders)
	if err != nil {
		s.logf("cbb: admitting the tunnel key of %s: %v", peer, err)
		return nil
	}
	if changed {
		if err := st.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: saving the tunnel state: %v", err)
			return nil
		}
		s.logf("cbb: %s can reach this hub away from home", peer)
		s.hubPeersLocked()
	}
	hub := st.Key.Public()
	o := &node.TunnelOffer{HubKey: hub[:], PSK: m.PresharedKey[:]}
	for _, ep := range st.HubEndpoints() {
		o.Endpoints = append(o.Endpoints, ep.String())
	}
	if st.Obfuscation != nil {
		if o.Obfuscation, err = json.Marshal(st.Obfuscation); err != nil {
			s.logf("cbb: the tunnel's obfuscation settings: %v", err)
			return nil
		}
	}
	if fw := st.Forwarder; fw != nil && fw.VLESSID != "" {
		if fw.VLESS == nil {
			// The clients may come only over VLESS, whose settings come
			// with the forwarder's answer; the offer waits for them.
			return nil
		}
		if o.VLESS, err = json.Marshal(fw.VLESS); err != nil {
			s.logf("cbb: the tunnel's VLESS settings: %v", err)
			return nil
		}
	}
	return o
}

// tunnelOffered keeps the offer of the group's hub for this member's key.
func (s *Service) tunnelOffered(from group.DeviceID, o node.TunnelOffer) error {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil {
		return errors.New("the tunnel is off on this device")
	}
	if st.IsHub {
		return errors.New("this device is the hub itself; the group has two hubs")
	}
	if st.Relay != nil {
		return errors.New("this device meets the others at its relay, but the group has a hub too")
	}
	h := tunnel.HubLink{Device: string(from)}
	if len(o.HubKey) != len(h.PublicKey) || len(o.PSK) != len(h.PresharedKey) {
		return errors.New("the keys are not 32 bytes")
	}
	copy(h.PublicKey[:], o.HubKey)
	copy(h.PresharedKey[:], o.PSK)
	for _, e := range o.Endpoints {
		ep, err := netip.ParseAddrPort(e)
		if err != nil {
			return fmt.Errorf("a bad endpoint: %w", err)
		}
		h.Endpoints = append(h.Endpoints, ep)
	}
	if len(o.Obfuscation) > 0 {
		h.Obfuscation = new(tunnel.Obfuscation)
		if err := json.Unmarshal(o.Obfuscation, h.Obfuscation); err != nil {
			return fmt.Errorf("bad obfuscation settings: %w", err)
		}
	}
	if len(o.VLESS) > 0 {
		h.VLESS = new(tunnel.VLESS)
		if err := json.Unmarshal(o.VLESS, h.VLESS); err != nil {
			return fmt.Errorf("bad VLESS settings: %w", err)
		}
	}
	old := st.ToHub
	changed, err := st.SetHub(h)
	if err != nil || !changed {
		return err
	}
	if err := st.Save(s.cfg.StateDir); err != nil {
		return fmt.Errorf("saving the tunnel state: %w", err)
	}
	if old == nil || old.Device != h.Device {
		s.logf("cbb: %s is the group's hub for sync away from home", from)
	}
	s.stopTunnelLocked()
	s.runTunnelLocked()
	return nil
}

// pruneTunnel forgets, on the hub, the members the records now refuse.
func (s *Service) pruneTunnel() {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil || len(st.Members) == 0 {
		return
	}
	gone := st.Prune(func(m tunnel.Member) bool {
		chain := make([]*x509.Certificate, 0, len(m.Chain))
		for _, der := range m.Chain {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return false
			}
			chain = append(chain, c)
		}
		return s.allow(group.DeviceID(m.Device), chain) == nil
	})
	if len(gone) == 0 {
		return
	}
	for _, d := range gone {
		s.logf("cbb: %s was removed from the group; the hub drops its tunnel", d)
	}
	if err := st.Save(s.cfg.StateDir); err != nil {
		s.logf("cbb: saving the tunnel state: %v", err)
	}
	s.hubPeersLocked()
}

// awayCheck is how often a member that is not reaching its hub through
// the tunnel looks again whether it has to: while the hub is on the home
// network, it syncs there without the tunnel.
const awayCheck = 5 * time.Second

// tunRun is the tunnel at work: the hub, or this member's link to it.
type tunRun struct {
	cancel context.CancelFunc
	hub    *tunnel.Hub
	client *tunnel.Client
	vless  *vless.Client // the client's way to the hub's forwarder over VLESS
}

// runTunnelLocked starts the tunnel the state asks for: the hub, or the
// link to the hub once the hub offered it. It fails closed: when the tunnel
// cannot start, the member syncs at home only and status says why.
func (s *Service) runTunnelLocked() {
	st, gctx := s.tunnel, s.tunCtx
	if st == nil || gctx == nil || s.tunRun != nil {
		return
	}
	self, err := tunnel.Addr(s.tunSelf)
	if err != nil {
		s.tunFailedLocked("this device has no tunnel address", err)
		return
	}
	ctx, cancel := context.WithCancel(gctx)
	switch {
	case st.IsHub:
		port := st.ListenPort
		if port == 0 {
			port = tunnel.Port
		}
		h, err := tunnel.StartHub(tunnel.HubConfig{PrivateKey: st.Key, Addr: self, ListenPort: port, Peers: s.hubPeerListLocked(),
			Obfuscation: st.Obfuscation, Logf: s.logf, Verbose: tunnelVerbose()})
		if err != nil {
			cancel()
			s.tunFailedLocked(fmt.Sprintf("the hub could not listen on UDP port %d", port), err)
			return
		}
		s.tunRun = &tunRun{cancel: cancel, hub: h}
		s.tunFailedLocked("", nil)
		s.registerForwarderLocked(ctx, h, st)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptTunnel(ctx, h.Listener())
		}()
	case st.Relay != nil:
		run := &tunRun{cancel: cancel}
		s.tunRun = run
		s.tunFailedLocked("", nil)
		s.joinRelayLocked(ctx, run, *st.Relay, st.Key)
	case st.ToHub != nil:
		link := *st.ToHub
		if len(link.Endpoints) == 0 {
			cancel()
			s.tunFailedLocked("the hub has no address away from home yet; run cbb away hub with its addresses there", nil)
			return
		}
		hubAddr, err := tunnel.Addr(link.Device)
		if err != nil {
			cancel()
			s.tunFailedLocked("the hub's offer names no device", err)
			return
		}
		var vc *vless.Client
		if link.VLESS != nil {
			// The only way to the hub is VLESS to its forwarder.
			if vc, err = vless.Dial(*link.VLESS); err != nil {
				cancel()
				s.tunFailedLocked("the way over VLESS to the hub's forwarder could not start", err)
				return
			}
			link.Endpoints = []netip.AddrPort{vc.Addr()}
		}
		c, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: st.Key, PresharedKey: link.PresharedKey, Addr: self,
			HubPublicKey: link.PublicKey, HubAddr: hubAddr, Endpoint: link.Endpoints[0], Obfuscation: link.Obfuscation,
			Logf: s.logf, Verbose: tunnelVerbose()})
		if err != nil {
			cancel()
			if vc != nil {
				vc.Close()
			}
			s.tunFailedLocked("the tunnel to the hub could not start", err)
			return
		}
		s.tunRun = &tunRun{cancel: cancel, client: c, vless: vc}
		s.tunFailedLocked("", nil)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.reachHub(ctx, c, link)
		}()
	default:
		cancel() // waits for the hub's offer, which comes at home
	}
}

// stopTunnelLocked stops the hub or the link to it, with every connection
// through it.
func (s *Service) stopTunnelLocked() {
	r := s.tunRun
	if r == nil {
		return
	}
	s.tunRun, s.tunThrough, s.tunFwd, s.tunRelay, s.tunRelayed = nil, false, nil, nil, 0
	r.cancel()
	if r.hub != nil {
		r.hub.Close()
	}
	if r.client != nil {
		r.client.Close()
	}
	if r.vless != nil {
		r.vless.Close()
	}
}

// tunFailedLocked keeps what went wrong for status, and logs it; an empty
// msg clears it.
func (s *Service) tunFailedLocked(msg string, err error) {
	s.tunErr, s.tunDetail = msg, ""
	if err != nil {
		s.tunDetail = err.Error()
	}
	if msg != "" {
		if err != nil {
			s.logf("cbb: sync away from home: %s: %v", msg, err)
		} else {
			s.logf("cbb: sync away from home: %s", msg)
		}
	}
}

// hubPeersLocked gives the running hub the clients the state admits now,
// and the guests of open invitations.
func (s *Service) hubPeersLocked() {
	if r := s.tunRun; r != nil && r.hub != nil {
		if err := r.hub.SetPeers(s.hubPeerListLocked()); err != nil {
			s.tunFailedLocked("the hub could not take its clients", err)
		}
	}
}

// acceptTunnel serves, on the hub, the member connections that come through
// the tunnel: the member protocol only, from the device whose WireGuard key
// the connection came with.
func (s *Service) acceptTunnel(ctx context.Context, ln net.Listener) {
	slots := make(chan struct{}, maxHandshakes)
	acceptLoop(ctx, ln, s.logf, "the tunnel", func(raw net.Conn) {
		select {
		case slots <- struct{}{}:
		default:
			raw.Close()
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveTunnelMember(ctx, raw, func() { <-slots })
		}()
	})
}

func (s *Service) serveTunnelMember(ctx context.Context, raw net.Conn, release func()) {
	from, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
	if tunnel.IsGuest(from.Addr()) {
		s.serveGuest(ctx, raw, from.Addr(), release)
		return
	}
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil {
		release()
		raw.Close()
		return
	}
	tc := tls.Server(raw, nd.ServerTLS())
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	release()
	if err != nil {
		raw.Close()
		return
	}
	id, err := group.PeerID(tc.ConnectionState())
	if want, aerr := tunnel.Addr(string(id)); err != nil || aerr != nil || from.Addr() != want {
		s.logf("cbb: a member connection through the tunnel from %v is not from the device of that key; closed", from.Addr())
		raw.Close()
		return
	}
	if err := nd.Serve(ctx, tc); err != nil && ctx.Err() == nil {
		s.logf("cbb: connection from %s through the tunnel: %v", id, err)
	}
}

// reachHub connects to the group's hub through the tunnel whenever the hub
// is not on this network: neither found by discovery nor connected. It
// tries the hub's addresses in turn.
func (s *Service) reachHub(ctx context.Context, c *tunnel.Client, link tunnel.HubLink) {
	hub := group.DeviceID(link.Device)
	backoff := minBackoff
	for i := 0; ctx.Err() == nil; i++ {
		s.mu.Lock()
		nd, near := s.nd, s.nearby[hub]
		s.mu.Unlock()
		if nd == nil {
			return
		}
		if near || slices.ContainsFunc(nd.Peers(), func(p node.Peer) bool { return p.ID == hub }) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(awayCheck):
			}
			continue
		}
		ep := link.Endpoints[i%len(link.Endpoints)]
		err := c.SetEndpoint(ep)
		var raw net.Conn
		if err == nil {
			dctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
			raw, err = c.Dial(dctx)
			cancel()
		}
		if err == nil {
			start := uptime.Now()
			s.tunMu.Lock()
			s.tunThrough = true
			s.tunFailedLocked("", nil)
			s.tunMu.Unlock()
			err = nd.DialConn(ctx, hub, raw)
			s.tunMu.Lock()
			s.tunThrough = false
			s.tunMu.Unlock()
			if uptime.Now()-start > maxBackoff {
				backoff = minBackoff
			}
		}
		if ctx.Err() != nil {
			return
		}
		s.tunMu.Lock()
		if s.tunRun != nil && s.tunRun.client == c {
			s.tunFailedLocked(fmt.Sprintf("the hub did not answer at %v", ep), err)
		}
		s.tunMu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// tunnelVerbose tells whether the service logs WireGuard's own messages too:
// only with CBB_DEBUG=1 in its environment, since they come every few
// seconds while a tunnel is up.
func tunnelVerbose() bool { return os.Getenv("CBB_DEBUG") == "1" }

// keysInFile tells whether this device keeps its keys in files, not in
// hardware; every computer does until the keys move to a TPM or a Secure
// Enclave (docs/roadmap.md, "Device keys in hardware").
const keysInFile = true

// away turns sync away from home on or off on this device, or makes it the
// group's hub (docs/design.md, "Turning it on, step by step").
func (s *Service) away(m *control.Message) error {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return s.errNoGroup()
	}
	reconnect, key, err := s.awayLocked(m, group.Tag(id.GroupCA.Cert))
	if err != nil {
		return err
	}
	if reconnect {
		// The members connect again, so their hellos carry the new key or
		// the hub's new offer.
		nd.SetTunnelKey(key)
		nd.Reconnect()
	}
	return nil
}

func (s *Service) awayLocked(m *control.Message, tag string) (reconnect bool, key []byte, err error) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	path := filepath.Join(s.cfg.StateDir, tunnel.StateFile)
	switch m.Name {
	case "on":
		if s.tunnel != nil {
			return false, nil, nil
		}
		if keysInFile && !m.Consent {
			return false, nil, errors.New("this device keeps its keys in files, so sync away from home needs your consent; run cbb away on and read what it says")
		}
		st, err := tunnel.NewState()
		if err != nil {
			return false, nil, err
		}
		st.ForGroup(tag)
		st.KeysInFile = keysInFile
		if err := st.Save(s.cfg.StateDir); err != nil {
			return false, nil, fmt.Errorf("saving the tunnel state: %w", err)
		}
		s.tunnel = st
		netguard.SetOpen(true)
		s.logf("cbb: sync away from home is on")
		return true, tunnelKey(st), nil
	case "off":
		if s.tunnel == nil {
			return false, nil, nil
		}
		s.stopTunnelLocked()
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, nil, err
		}
		s.tunnel = nil
		netguard.SetOpen(false)
		s.tunFailedLocked("", nil)
		s.logf("cbb: sync away from home is off; its keys are gone")
		return true, nil, nil
	case "hub":
		st := s.tunnel
		if st == nil {
			return false, nil, errors.New("sync away from home is off here; turn it on first: cbb away on")
		}
		if m.Port < 0 || m.Port > 65535 {
			return false, nil, fmt.Errorf("a bad port %d", m.Port)
		}
		var fw *tunnel.ForwarderLink
		if m.Forwarder != "" {
			ep, err := netip.ParseAddrPort(m.Forwarder)
			if err != nil || ep.Port() == 0 {
				return false, nil, fmt.Errorf("%q is not the forwarder's address with a port, such as 203.0.113.9:8764", m.Forwarder)
			}
			if err := forward.CheckPin(m.ForwarderKey); err != nil {
				return false, nil, err
			}
			fw = &tunnel.ForwarderLink{Endpoint: netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()), Pin: m.ForwarderKey}
		} else if m.ForwarderKey != "" {
			return false, nil, errors.New("a forwarder's key without its address")
		}
		var eps []netip.AddrPort
		for _, a := range m.Addrs {
			ep, err := netip.ParseAddrPort(a)
			if err != nil || ep.Port() == 0 {
				return false, nil, fmt.Errorf("%q is not an address with a port, such as 203.0.113.7:8764 or [2001:db8::7]:8764", a)
			}
			eps = append(eps, netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()))
		}
		if len(eps) > 7 || (fw == nil && len(eps) > 8) {
			return false, nil, errors.New("at most 8 addresses, the forwarder's included")
		}
		if len(eps) == 0 && fw == nil {
			return false, nil, errors.New("the hub needs an address away from home or a forwarder")
		}
		if m.VLESS {
			if fw == nil {
				return false, nil, errors.New("VLESS goes to a forwarder; give one with -forwarder and -forwarder-key")
			}
			// The group keeps its ID, and the forwarder's settings while
			// the forwarder stays the same.
			if old := st.Forwarder; old != nil && old.VLESSID != "" {
				fw.VLESSID = old.VLESSID
				if old.Endpoint == fw.Endpoint && old.Pin == fw.Pin {
					fw.VLESS = old.VLESS
				}
			} else if fw.VLESSID, err = tunnel.NewVLESSID(); err != nil {
				return false, nil, err
			}
		}
		obf := st.Obfuscation
		switch {
		case !m.Obfuscate:
			obf = nil
		case obf == nil:
			// Kept as they are when the hub is set again, so its clients'
			// offers stay good.
			if obf, err = tunnel.NewObfuscation(); err != nil {
				return false, nil, err
			}
		}
		old := *st
		st.IsHub, st.ToHub, st.Endpoints, st.ListenPort, st.Forwarder, st.Relay, st.Obfuscation = true, nil, eps, m.Port, fw, nil, obf
		if err := st.Save(s.cfg.StateDir); err != nil {
			*st = old
			return false, nil, fmt.Errorf("saving the tunnel state: %w", err)
		}
		s.stopTunnelLocked()
		s.runTunnelLocked()
		s.logf("cbb: this device is the group's hub for sync away from home")
		return true, tunnelKey(st), nil
	case "relay":
		st := s.tunnel
		if st == nil {
			return false, nil, errors.New("sync away from home is off here; turn it on first: cbb away on")
		}
		ep, err := netip.ParseAddrPort(m.Relay)
		if err != nil || ep.Port() == 0 {
			return false, nil, fmt.Errorf("%q is not the relay's address with a port, such as 203.0.113.9:8764", m.Relay)
		}
		if err := relay.CheckPin(m.RelayKey); err != nil {
			return false, nil, err
		}
		old := *st
		*st = tunnel.State{Key: st.Key, Group: st.Group, KeysInFile: st.KeysInFile,
			Relay: &tunnel.RelayLink{Endpoint: netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()), Pin: m.RelayKey}}
		if err := st.Save(s.cfg.StateDir); err != nil {
			*st = old
			return false, nil, fmt.Errorf("saving the tunnel state: %w", err)
		}
		s.stopTunnelLocked()
		s.runTunnelLocked()
		s.logf("cbb: sync away from home goes through the relay at %v", st.Relay.Endpoint)
		return true, tunnelKey(st), nil
	}
	return false, nil, fmt.Errorf("unknown away request %q", m.Name)
}

// awayStatus describes sync away from home for status; nil while it is
// off.
func (s *Service) awayStatus() *control.Away {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil {
		return nil
	}
	a := &control.Away{Hub: st.IsHub, KeysInFile: st.KeysInFile, Error: s.tunErr, Detail: s.tunDetail}
	if st.IsHub {
		a.Obfuscated = st.Obfuscation != nil
		a.VLESS = st.Forwarder != nil && st.Forwarder.VLESSID != ""
	} else if st.ToHub != nil {
		a.Obfuscated = st.ToHub.Obfuscation != nil
		a.VLESS = st.ToHub.VLESS != nil
	}
	if st.IsHub && st.Forwarder != nil {
		a.Forwarder = &control.Forwarder{Endpoint: st.Forwarder.Endpoint.String(), Error: "the hub is not running"}
		if f := s.tunFwd; f != nil {
			c := *f
			a.Forwarder = &c
		}
	}
	switch {
	case st.IsHub:
		a.Port, a.Clients = st.ListenPort, len(st.Members)
		if a.Port == 0 {
			a.Port = tunnel.Port
		}
		for _, ep := range st.Endpoints {
			a.Endpoints = append(a.Endpoints, ep.String())
		}
	case st.Relay != nil:
		a.Relay, a.Through = &control.Relay{Endpoint: st.Relay.Endpoint.String(), Error: "the link to the relay is not running"}, s.tunRelayed > 0
		if r := s.tunRelay; r != nil {
			c := *r
			c.Online = slices.Clone(r.Online)
			a.Relay = &c
		}
	case st.ToHub != nil:
		a.HubDevice, a.Through = st.ToHub.Device, s.tunThrough
		for _, ep := range st.ToHub.Endpoints {
			a.Endpoints = append(a.Endpoints, ep.String())
		}
	}
	return a
}
