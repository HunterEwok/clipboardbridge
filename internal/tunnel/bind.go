// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import "golang.zx2c4.com/wireguard/conn"

// newBind returns the UDP socket for a hub or a client: wireguard-go's
// default, whose receive skips the errors that only report an ICMP message
// for an earlier packet. On Windows a UDP socket reports a "port
// unreachable" for a packet it sent, for example to a client that went
// away, as an error on its next receive, and wireguard-go stops receiving
// for good on such an error: a hub would then hear no client again.
func newBind() conn.Bind { return icmpTolerantBind{conn.NewDefaultBind()} }

type icmpTolerantBind struct{ conn.Bind }

func (b icmpTolerantBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	for i, recv := range fns {
		fns[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			for {
				n, err := recv(packets, sizes, eps)
				if err == nil || !icmpReport(err) {
					return n, err
				}
			}
		}
	}
	return fns, actual, err
}
