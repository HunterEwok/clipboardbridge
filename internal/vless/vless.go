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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy"
	xvless "github.com/xtls/xray-core/proxy/vless"

	confserial "github.com/xtls/xray-core/infra/conf/serial"

	// What the two sides use of Xray, registered by their init functions.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/reality"
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
	js, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "none", "access": "none", "error": "none"},
		"inbounds": []any{map[string]any{
			"tag": inboundTag, "listen": host, "port": port, "protocol": "vless",
			"settings": map[string]any{"clients": []any{}, "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"dest":        cfg.Dest,
					"serverNames": []string{cfg.ServerName},
					"privateKey":  base64.RawURLEncoding.EncodeToString(cfg.Key[:]),
					"shortIds":    []string{ShortID(cfg.Key)},
				},
			},
		}},
		"outbounds": []any{
			map[string]any{
				"protocol": "freedom",
				// Whatever a client asks for, its packets go to the forwarder,
				// which Xray lets through only by name since it is a private
				// address; nothing else.
				"settings": map[string]any{"redirect": cfg.To.String(), "finalRules": []any{
					map[string]any{"action": "allow", "network": "udp", "ip": []string{cfg.To.Addr().String()}, "port": int(cfg.To.Port())},
					map[string]any{"action": "block"},
				}},
			},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		// Only UDP: a TCP stream would reach the forwarder's registrations.
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "network": "tcp", "outboundTag": "block"},
		}},
	})
	if err != nil {
		return nil, err
	}
	inst, err := start(js)
	if err != nil {
		return nil, err
	}
	s := &Server{inst: inst}
	fmt.Sscan(port, &s.port)
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
	js, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "none", "access": "none", "error": "none"},
		"inbounds": []any{map[string]any{
			"listen": addr.Addr().String(), "port": addr.Port(), "protocol": "dokodemo-door",
			// The address means nothing: the forwarder sends every packet
			// to its own port.
			"settings": map[string]any{"address": "127.0.0.1", "port": 9, "network": "udp"},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": l.Endpoint.Addr().String(), "port": l.Endpoint.Port(),
				"users": []any{map[string]any{"id": l.ID, "encryption": "none"}},
			}}},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"serverName":  l.ServerName,
					"publicKey":   base64.RawURLEncoding.EncodeToString(l.PublicKey),
					"shortId":     l.ShortID,
					"fingerprint": "chrome",
				},
			},
		}},
	})
	if err != nil {
		return nil, err
	}
	inst, err := start(js)
	if err != nil {
		return nil, err
	}
	return &Client{inst: inst, addr: addr}, nil
}

// Addr returns the local UDP address WireGuard sends to.
func (c *Client) Addr() netip.AddrPort { return c.addr }

// Close stops the client's side.
func (c *Client) Close() error { return c.inst.Close() }

func start(js []byte) (*core.Instance, error) {
	c, err := confserial.DecodeJSONConfig(strings.NewReader(string(js)))
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	pb, err := c.Build()
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	inst, err := core.New(pb)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, fmt.Errorf("vless: %w", err)
	}
	return inst, nil
}
