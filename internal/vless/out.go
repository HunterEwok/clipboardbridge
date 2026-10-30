// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package vless

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// idle ends a client's UDP flow to the forwarder after this long without a
// packet either way, as Xray's freedom outbound does by default.
const idle = 5 * time.Minute

// toForwarder is the forwarder's side's only outbound: it passes a client's
// UDP packets to the forwarder's UDP port, whatever the client asked for,
// from a port of its own for each flow, and the answers back. It remembers
// which VLESS user each of those ports serves, so that the forwarder can
// tell the clients of one group from those of another though all of them
// come from its own address (Server.User). A TCP stream goes
// nowhere: it would reach the forwarder's registrations.
type toForwarder struct {
	to netip.AddrPort

	mu    sync.Mutex
	users map[netip.AddrPort]string // by the address each flow is sent from
}

func (o *toForwarder) Tag() string                          { return "to-forwarder" }
func (o *toForwarder) Start() error                         { return nil }
func (o *toForwarder) Close() error                         { return nil }
func (o *toForwarder) SenderSettings() *serial.TypedMessage { return nil }
func (o *toForwarder) ProxySettings() *serial.TypedMessage  { return nil }

// user returns the VLESS user whose packets are sent from the address.
func (o *toForwarder) user(from netip.AddrPort) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	u, ok := o.users[netip.AddrPortFrom(from.Addr().Unmap(), from.Port())]
	return u, ok
}

// Dispatch carries one flow of a client.
func (o *toForwarder) Dispatch(ctx context.Context, link *transport.Link) {
	if err := o.carry(ctx, link); err != nil && !errors.Is(err, io.EOF) {
		common.Interrupt(link.Writer)
		common.Interrupt(link.Reader)
		return
	}
	common.Close(link.Writer)
	common.Interrupt(link.Reader)
}

func (o *toForwarder) carry(ctx context.Context, link *transport.Link) error {
	in := session.InboundFromContext(ctx)
	outs := session.OutboundsFromContext(ctx)
	if in == nil || in.User == nil || in.User.Email == "" || len(outs) == 0 || outs[len(outs)-1].Target.Network != xnet.Network_UDP {
		return net.ErrClosed
	}
	target := outs[len(outs)-1].Target
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(o.to))
	if err != nil {
		return err
	}
	defer conn.Close()
	la := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	from := netip.AddrPortFrom(la.Addr().Unmap(), la.Port())
	o.mu.Lock()
	if o.users == nil {
		o.users = map[netip.AddrPort]string{}
	}
	o.users[from] = in.User.Email
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		delete(o.users, from)
		o.mu.Unlock()
	}()

	var last atomic.Int64 // when a packet last went either way, Unix ns
	last.Store(time.Now().UnixNano())
	done := make(chan error, 2)
	go func() {
		// The client's packets, each a buffer, to the forwarder.
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			for _, b := range mb {
				if !b.IsEmpty() {
					last.Store(time.Now().UnixNano())
					if _, werr := conn.Write(b.Bytes()); werr != nil && err == nil {
						err = werr
					}
				}
			}
			buf.ReleaseMulti(mb)
			if err != nil {
				done <- err
				return
			}
		}
	}()
	go func() {
		// The forwarder's answers, each a buffer, to the client, as from
		// what it asked for.
		for {
			b := buf.New()
			b.Resize(0, buf.Size)
			conn.SetReadDeadline(time.Now().Add(idle))
			n, err := conn.Read(b.Bytes())
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Since(time.Unix(0, last.Load())) < idle {
				b.Release()
				continue
			}
			if err != nil {
				b.Release()
				done <- err
				return
			}
			last.Store(time.Now().UnixNano())
			b.Resize(0, int32(n))
			b.UDP = &target
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				done <- err
				return
			}
		}
	}()
	err = <-done
	conn.Close()
	common.Interrupt(link.Reader)
	return err
}
