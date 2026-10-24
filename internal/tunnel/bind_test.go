// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"errors"
	"syscall"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn"
)

// scriptedBind returns the receive results it is given, in turn.
type scriptedBind struct {
	conn.Bind
	errs []error
}

func (b *scriptedBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{func([][]byte, []int, []conn.Endpoint) (int, error) {
		err := b.errs[0]
		b.errs = b.errs[1:]
		if err != nil {
			return 0, err
		}
		return 1, nil
	}}, 1, nil
}

// TestBindSkipsICMPReports checks that a receive goes on past an error
// that only reports an ICMP message, and returns any other.
func TestBindSkipsICMPReports(t *testing.T) {
	reset := syscall.Errno(10054) // WSAECONNRESET on Windows
	other := errors.New("broken")
	if !icmpReport(reset) {
		t.Skip("only Windows reports ICMP messages as receive errors")
	}
	b := icmpTolerantBind{&scriptedBind{errs: []error{reset, reset, nil, other}}}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := fns[0](nil, nil, nil); n != 1 || err != nil {
		t.Errorf("the first receive gave %d, %v, want the packet", n, err)
	}
	if _, err := fns[0](nil, nil, nil); err != other {
		t.Errorf("the second receive gave %v, want %v", err, other)
	}
}
