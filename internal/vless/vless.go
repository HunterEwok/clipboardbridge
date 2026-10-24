// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package vless carries a group's WireGuard packets between a client and
// the forwarder inside VLESS with REALITY, for networks that block
// WireGuard and AmneziaWG alike (docs/design.md, "Blocked networks"). To
// the network the connection is TLS 1.3 to a well-known site, whose
// handshake the forwarder borrows; VLESS inside it carries the UDP packets.
// It adds no security of its own: the packets are the group's WireGuard,
// with the member TLS inside it.
//
// It runs Xray-core in the process. The client side is a local UDP port
// that WireGuard sends to; the forwarder's side passes every packet to the
// forwarder's own UDP port, and nowhere else, so it cannot be used as a
// proxy.
package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
	"github.com/xtls/xray-core/app/dispatcher"
	xlog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	xvless "github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"google.golang.org/protobuf/proto"

	// What the two sides use of Xray, registered by their init functions.
	// The configs are built here rather than from Xray's JSON, whose
	// package pulls in much more, some of which gomobile cannot link.
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

// ServerConfig configures the forwarder's side.
type ServerConfig struct {
	Listen string // the TCP address to listen on, such as ":443"
	// Dest is the site whose TLS the forwarder borrows, as host:port: a
	// probe that is not a client gets that site's answers.
	Dest       string
	ServerName string   // the name the clients' handshakes carry
	Key        [32]byte // the REALITY private key, X25519
	// To is the forwarder's own UDP port, where every packet goes.
	To netip.AddrPort
}

// ShortID returns the REALITY short ID of the private key: it needs no
// keeping, and it tells nothing about the key.
func ShortID(key [32]byte) string {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("clipboardbridge reality short id"))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// PublicKey returns the REALITY public key of the private key.
func PublicKey(key [32]byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(key[:])
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// Server is the forwarder's side, running.
type Server struct {
	inst  *core.Instance
	users proxy.UserManager
	port  uint16
}

const inboundTag = "vless-in"

// Listen starts the forwarder's side with no users; AddUser lets a
// group's clients in.
func Listen(cfg ServerConfig) (*Server, error) {
	if err := tunnel.CheckServerName(cfg.ServerName); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	if port == "0" || port == "" {
		// Xray needs the port; take a free one.
		l, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			return nil, fmt.Errorf("vless: %w", err)
		}
		_, port, _ = net.SplitHostPort(l.Addr().String())
		l.Close()
	}
	if host == "" {
		host = "0.0.0.0"
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	listen := netip.AddrPortFrom(ip, uint16(p))
	sid, _ := hex.DecodeString(ShortID(cfg.Key))
	stream := realityStream(&reality.Config{
		Dest:        cfg.Dest,
		Type:        "tcp",
		ServerNames: []string{cfg.ServerName},
		PrivateKey:  cfg.Key[:],
		ShortIds:    [][]byte{sid},
		// No limits, as Xray's JSON has it.
		LimitFallbackUpload:   &reality.LimitFallback{},
		LimitFallbackDownload: &reality.LimitFallback{},
	})
	// Whatever a client asks for, its packets go to the forwarder's UDP
	// port, which Xray lets through only by name since it is a private
	// address; nothing else, and no TCP stream, which would reach the
	// forwarder's registrations.
	to, err := geodata.ParseIPRules([]string{cfg.To.Addr().String()})
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	out := &freedom.Config{
		DestinationOverride: &freedom.DestinationOverride{Server: endpoint(cfg.To)},
		FinalRules: []*freedom.FinalRuleConfig{
			{Action: freedom.RuleAction_Allow, Networks: []xnet.Network{xnet.Network_UDP}, PortList: ports(cfg.To.Port()), Ip: to},
			{Action: freedom.RuleAction_Block},
		},
	}
	inst, err := start(inboundHandler(inboundTag, listen, stream, &vlessin.Config{Decryption: "none"}), out)
	if err != nil {
		return nil, err
	}
	s := &Server{inst: inst, port: listen.Port()}
	m, _ := inst.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if m == nil {
		inst.Close()
		return nil, errors.New("vless: no inbound manager")
	}
	h, err := m.GetHandler(context.Background(), inboundTag)
	if err != nil {
		inst.Close()
		return nil, fmt.Errorf("vless: %w", err)
	}
	gi, ok := h.(proxy.GetInbound)
	if !ok {
		inst.Close()
		return nil, errors.New("vless: the inbound has no users")
	}
	if s.users, ok = gi.GetInbound().(proxy.UserManager); !ok {
		inst.Close()
		return nil, errors.New("vless: the inbound has no users")
	}
	return s, nil
}

// Port returns the TCP port the server listens on.
func (s *Server) Port() uint16 { return s.port }

// AddUser lets in the clients of the group whose user ID is id.
func (s *Server) AddUser(id string) error {
	if err := tunnel.CheckVLESSID(id); err != nil {
		return err
	}
	u, err := (&protocol.User{Email: id, Account: serial.ToTypedMessage(&xvless.Account{Id: id, Encryption: "none"})}).ToMemoryUser()
	if err != nil {
		return fmt.Errorf("vless: %w", err)
	}
	return s.users.AddUser(context.Background(), u)
}

// RemoveUser shuts out the clients of a group.
func (s *Server) RemoveUser(id string) error {
	return s.users.RemoveUser(context.Background(), id)
}

// Close stops the server.
func (s *Server) Close() error { return s.inst.Close() }

// Client is a client's side, running: a local UDP port whose packets go to
// the forwarder inside VLESS.
type Client struct {
	inst *core.Instance
	addr netip.AddrPort
}

// Dial starts the client's side for the link. WireGuard then sends to
// Addr.
func Dial(l tunnel.VLESS) (*Client, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	// Xray needs the port; take a free one.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	pc.Close()
	sid, err := hex.DecodeString(l.ShortID)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	stream := realityStream(&reality.Config{
		Fingerprint: "chrome",
		ServerName:  l.ServerName,
		PublicKey:   l.PublicKey,
		ShortId:     sid,
		SpiderX:     "/",
		SpiderY:     make([]int64, 10),
	})
	// The address means nothing: the forwarder sends every packet to its
	// own port.
	in := &dokodemo.Config{
		RewriteAddress:  xnet.NewIPOrDomain(xnet.LocalHostIP),
		RewritePort:     9,
		AllowedNetworks: []xnet.Network{xnet.Network_UDP},
	}
	server := endpoint(l.Endpoint)
	server.User = &protocol.User{Account: serial.ToTypedMessage(&xvless.Account{Id: l.ID, Encryption: "none"})}
	inst, err := start(inboundHandler("", addr, nil, in), &vlessout.Config{Vnext: server}, stream)
	if err != nil {
		return nil, err
	}
	return &Client{inst: inst, addr: addr}, nil
}

// Addr returns the local UDP address WireGuard sends to.
func (c *Client) Addr() netip.AddrPort { return c.addr }

// Close stops the client's side.
func (c *Client) Close() error { return c.inst.Close() }

func realityStream(c *reality.Config) *internet.StreamConfig {
	tm := serial.ToTypedMessage(c)
	return &internet.StreamConfig{ProtocolName: "tcp", SecurityType: tm.Type, SecuritySettings: []*serial.TypedMessage{tm}}
}

func endpoint(a netip.AddrPort) *protocol.ServerEndpoint {
	return &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.IPAddress(a.Addr().AsSlice())), Port: uint32(a.Port())}
}

func ports(p uint16) *xnet.PortList {
	return &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(p))}}
}

func inboundHandler(tag string, listen netip.AddrPort, stream *internet.StreamConfig, settings proto.Message) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		Tag: tag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			PortList:       ports(listen.Port()),
			Listen:         xnet.NewIPOrDomain(xnet.IPAddress(listen.Addr().AsSlice())),
			StreamSettings: stream,
		}),
		ProxySettings: serial.ToTypedMessage(settings),
	}
}

// start runs Xray with one inbound and one outbound, logging nothing.
func start(in *core.InboundHandlerConfig, out proto.Message, outStream ...*internet.StreamConfig) (*core.Instance, error) {
	sender := &proxyman.SenderConfig{}
	if len(outStream) > 0 {
		sender.StreamSettings = outStream[0]
	}
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&xlog.Config{ErrorLogType: xlog.LogType_None, AccessLogType: xlog.LogType_None}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound:  []*core.InboundHandlerConfig{in},
		Outbound: []*core.OutboundHandlerConfig{{SenderSettings: serial.ToTypedMessage(sender), ProxySettings: serial.ToTypedMessage(out)}},
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, fmt.Errorf("vless: %w", err)
	}
	return inst, nil
}
