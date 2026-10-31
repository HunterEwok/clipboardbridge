// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// What a stranger on the network learns (D4, D5, S21): forge
// mdns-resolve:NAME asks once over multicast DNS, from a port of its own as
// a plain resolver does, for NAME's IPv4 address and prints each answer as
// "A NAME ADDRESS"; forge tls-peek:HOST:PORT opens TLS to a member without
// a certificate of its own and prints the certificate the member shows, as
// "subject ...", "dns ..." and "ip ..." lines, or the handshake's error.
func probeCase(arg string) bool {
	return strings.HasPrefix(arg, "mdns-resolve:") || strings.HasPrefix(arg, "tls-peek:")
}

func runProbe(arg string) error {
	if host, ok := strings.CutPrefix(arg, "tls-peek:"); ok {
		return tlsPeek(host)
	}
	return mdnsResolve(strings.TrimPrefix(arg, "mdns-resolve:"))
}

func mdnsResolve(name string) error {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return err
	}
	msg := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	q, err := msg.Pack()
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.WriteToUDP(q, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}); err != nil {
		return err
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	seen := map[string]bool{}
	buf := make([]byte, 9000)
	for {
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return nil // the deadline: every answer is in
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil {
			continue
		}
		for _, rr := range append(m.Answers, m.Additionals...) {
			a, ok := rr.Body.(*dnsmessage.AResource)
			if !ok || !strings.EqualFold(rr.Header.Name.String(), name) {
				continue
			}
			ip := net.IP(a.A[:]).String()
			if !seen[ip] {
				seen[ip] = true
				fmt.Println("A", strings.TrimSuffix(name, "."), ip)
			}
		}
	}
}

// insecurePeekConfig is the TLS of a stranger on the LAN, which has no CA to
// check the member's certificate against: it takes any certificate, since
// what the member hands a stranger is what S21 looks at. (The name tells
// CodeQL that skipping the check is the point here.)
func insecurePeekConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
}

func tlsPeek(host string) error {
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", host, insecurePeekConfig())
	if err != nil {
		fmt.Println("handshake:", err)
		return nil
	}
	defer c.Close()
	for _, cert := range c.ConnectionState().PeerCertificates {
		fmt.Println("subject", cert.Subject.String())
		for _, n := range cert.DNSNames {
			fmt.Println("dns", n)
		}
		for _, ip := range cert.IPAddresses {
			fmt.Println("ip", ip)
		}
	}
	return nil
}
