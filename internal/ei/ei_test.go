// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package ei

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeEIS is the server side of the protocol, as far as a keyboard needs.
type fakeEIS struct {
	t *testing.T
	c *net.UnixConn
}

type msg struct {
	id   uint64
	op   uint32
	args *args
}

func (f *fakeEIS) send(id uint64, op uint32, a ...[]byte) {
	f.t.Helper()
	k := &Keyboard{c: f.c}
	if err := k.send(id, op, a...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeEIS) recv() msg {
	f.t.Helper()
	f.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	h := make([]byte, 16)
	if _, err := ioReadFull(f.c, h); err != nil {
		f.t.Fatal(err)
	}
	size := binary.NativeEndian.Uint32(h[8:])
	body := make([]byte, size-16)
	if _, err := ioReadFull(f.c, body); err != nil {
		f.t.Fatal(err)
	}
	return msg{id: binary.NativeEndian.Uint64(h), op: binary.NativeEndian.Uint32(h[12:]), args: &args{b: body}}
}

func ioReadFull(c *net.UnixConn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

func (f *fakeEIS) expect(id uint64, op uint32) *args {
	f.t.Helper()
	m := f.recv()
	if m.id != id || m.op != op {
		f.t.Fatalf("got object %#x op %d, want %#x op %d", m.id, m.op, id, op)
	}
	return m.args
}

func TestKeyboard(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sf := os.NewFile(uintptr(fds[1]), "server")
	sc, err := net.FileConn(sf)
	sf.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	f := &fakeEIS{t: t, c: sc.(*net.UnixConn)}

	const (
		conn = 0xff00000000000001
		seat = 0xff00000000000002
		dev  = 0xff00000000000003
		kbd  = 0xff00000000000004
		ping = 0xff00000000000005
	)
	done := make(chan *Keyboard, 1)
	errc := make(chan error, 1)
	go func() {
		k, err := Dial(fds[0], "cbb test", 5*time.Second)
		if err != nil {
			errc <- err
			return
		}
		done <- k
	}()
	f.send(0, hsEvHandshakeVersion, u32(1))
	if v := f.expect(0, hsReqHandshakeVersion).u32(); v != 1 {
		t.Errorf("handshake version %d", v)
	}
	if c := f.expect(0, hsReqContextType).u32(); c != contextSender {
		t.Errorf("context type %d", c)
	}
	if n := f.expect(0, hsReqName).str(); n != "cbb test" {
		t.Errorf("name %q", n)
	}
	for range interfaces {
		f.expect(0, hsReqInterfaceVersion)
	}
	f.expect(0, hsReqFinish)
	f.send(0, hsEvConnection, u32(1), u64(conn), u32(1))
	f.send(conn, connEvPing, u64(ping), u32(1))
	f.expect(ping, pingReqDone)
	f.send(conn, connEvSeat, u64(seat), u32(1))
	f.send(seat, 1, str("seat0")) // name
	f.send(seat, seatEvCapability, u64(1<<3), str("ei_pointer"))
	f.send(seat, seatEvCapability, u64(1<<5), str("ei_keyboard"))
	f.send(seat, seatEvDone)
	if mask := f.expect(seat, seatReqBind).u64(); mask != 1<<5 {
		t.Errorf("bound %#x", mask)
	}
	f.send(seat, seatEvDevice, u64(dev), u32(1))
	f.send(dev, devEvInterface, u64(kbd), str("ei_keyboard"), u32(1))
	f.send(dev, 6) // done
	f.send(dev, devEvResumed, u32(7))

	var k *Keyboard
	select {
	case k = <-done:
	case err := <-errc:
		t.Fatal(err)
	}
	defer k.Close()
	go func() {
		errc <- k.Press([]Key{{KeyLeftShift, true}, {KeyInsert, true}, {KeyInsert, false}, {KeyLeftShift, false}})
	}()
	a := f.expect(dev, devReqStartEmulating)
	if s := a.u32(); s != 7 {
		t.Errorf("start_emulating serial %d", s)
	}
	for _, want := range []struct{ code, state uint32 }{{KeyLeftShift, 1}, {KeyInsert, 1}, {KeyInsert, 0}, {KeyLeftShift, 0}} {
		a := f.expect(kbd, kbdReqKey)
		if code, state := a.u32(), a.u32(); code != want.code || state != want.state {
			t.Errorf("key %d %d, want %d %d", code, state, want.code, want.state)
		}
		f.expect(dev, devReqFrame)
	}
	f.expect(dev, devReqStopEmulating)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}

	// A paused keyboard takes no keys.
	f.send(dev, devEvPaused, u32(8))
	time.Sleep(100 * time.Millisecond)
	if err := k.Press([]Key{{KeyEnter, true}}); err == nil {
		t.Error("a paused keyboard took a key")
	}
}
