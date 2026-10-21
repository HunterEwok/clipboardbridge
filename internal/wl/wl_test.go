// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package wl

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeCompositor is the other end of a Display: it reads requests and
// writes events by hand.
type fakeCompositor struct {
	t *testing.T
	c *net.UnixConn
}

func newPair(t *testing.T) (*Display, *fakeCompositor) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "wayland")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c.(*net.UnixConn)
	}
	d := &Display{conn: conn(fds[0]), nextID: displayID + 1, handlers: map[uint32]Handler{}}
	d.handlers[displayID] = d.displayEvent
	return d, &fakeCompositor{t: t, c: conn(fds[1])}
}

// request reads one request and returns its object, opcode, body and fds.
func (f *fakeCompositor) request() (uint32, uint16, []byte, []int) {
	f.t.Helper()
	buf := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, _, _, err := f.c.ReadMsgUnix(buf[:8], oob)
	if err != nil || n != 8 {
		f.t.Fatalf("reading a request header: %v", err)
	}
	id := binary.NativeEndian.Uint32(buf)
	word := binary.NativeEndian.Uint32(buf[4:])
	size := int(word >> 16)
	body := make([]byte, size-8)
	if size > 8 {
		m, _, _, _, err := f.c.ReadMsgUnix(body, nil)
		if err != nil || m != size-8 {
			f.t.Fatalf("reading a request body: %v", err)
		}
	}
	var fds []int
	if oobn > 0 {
		msgs, _ := unix.ParseSocketControlMessage(oob[:oobn])
		for _, m := range msgs {
			got, _ := unix.ParseUnixRights(&m)
			fds = append(fds, got...)
		}
	}
	return id, uint16(word), body, fds
}

// event writes an event, with an fd if fd >= 0.
func (f *fakeCompositor) event(id uint32, op uint16, r *Request, fd int) {
	f.t.Helper()
	if r == nil {
		r = &Request{}
	}
	msg := binary.NativeEndian.AppendUint32(nil, id)
	msg = binary.NativeEndian.AppendUint32(msg, uint32(8+len(r.buf))<<16|uint32(op))
	msg = append(msg, r.buf...)
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	if _, _, err := f.c.WriteMsgUnix(msg, oob, nil); err != nil {
		f.t.Fatal(err)
	}
}

func TestStringEncoding(t *testing.T) {
	for s, want := range map[string]int{"": 8, "abc": 8, "abcd": 12, "wl_seat": 12} {
		r := (&Request{}).String(s)
		if len(r.buf) != want || len(r.buf)%4 != 0 {
			t.Errorf("String(%q) is %d bytes, want %d", s, len(r.buf), want)
		}
		a := &Args{b: r.buf}
		if got := a.String(); got != s || a.Err != nil {
			t.Errorf("round trip of %q: %q, %v", s, got, a.Err)
		}
	}
	// A string without its zero, or cut short, is an error, not a panic.
	for _, bad := range [][]byte{{5, 0, 0, 0, 'a', 'b'}, {2, 0, 0, 0, 'a', 'b', 0, 0}} {
		bad := append([]byte(nil), bad...)
		binary.NativeEndian.PutUint32(bad, binary.NativeEndian.Uint32(bad))
		a := &Args{b: bad}
		_ = a.String()
		if a.Err == nil {
			t.Errorf("Args.String(%v) accepted a bad string", bad)
		}
	}
	a := &Args{b: []byte{1, 2}}
	if a.Uint(); a.Err == nil {
		t.Error("Uint accepted 2 bytes")
	}
}

func TestRegistryAndRoundtrip(t *testing.T) {
	d, f := newPair(t)
	done := make(chan *Registry, 1)
	go func() {
		r, err := d.GetRegistry()
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	// get_registry, then sync.
	id, op, body, _ := f.request()
	if id != displayID || op != 1 {
		t.Fatalf("first request %d/%d, want get_registry", id, op)
	}
	reg := binary.NativeEndian.Uint32(body)
	id, op, body, _ = f.request()
	if id != displayID || op != 0 {
		t.Fatalf("second request %d/%d, want sync", id, op)
	}
	cb := binary.NativeEndian.Uint32(body)
	f.event(reg, 0, (&Request{}).Uint(1).String("wl_seat").Uint(7), -1)
	f.event(reg, 0, (&Request{}).Uint(2).String("ext_data_control_manager_v1").Uint(1), -1)
	f.event(reg, 1, (&Request{}).Uint(1), -1) // the seat goes away
	f.event(reg, 0, (&Request{}).Uint(3).String("wl_seat").Uint(9), -1)
	f.event(cb, 0, (&Request{}).Uint(0), -1)
	r := <-done
	if r == nil {
		t.Fatal("no registry")
	}
	g, ok := r.Find("wl_seat")
	if !ok || g.Name != 3 || g.Version != 9 {
		t.Errorf("Find(wl_seat) = %+v, %v", g, ok)
	}
	if _, ok := r.Find("zwlr_data_control_manager_v1"); ok {
		t.Error("found a global that was not announced")
	}
	// Bind sends the name, interface, the lower version and the new ID.
	newID := r.Bind(g, 2, nil)
	id, op, body, _ = f.request()
	a := &Args{b: body}
	if id != reg || op != 0 || a.Uint() != 3 || a.String() != "wl_seat" || a.Uint() != 2 || a.Uint() != newID {
		t.Errorf("bind request %d/%d %v", id, op, body)
	}
}

func TestFileDescriptors(t *testing.T) {
	d, f := newPair(t)
	// A request carries an fd beside its bytes.
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(p[0])
	if err := d.Send(42, 0, (&Request{}).String("text/plain").FD(p[1])); err != nil {
		t.Fatal(err)
	}
	unix.Close(p[1])
	_, _, _, fds := f.request()
	if len(fds) != 1 {
		t.Fatalf("%d fds arrived with the request", len(fds))
	}
	unix.Write(fds[0], []byte("through the fd"))
	unix.Close(fds[0])
	buf := make([]byte, 64)
	n, _ := unix.Read(p[0], buf)
	if string(buf[:n]) != "through the fd" {
		t.Errorf("read %q through the passed fd", buf[:n])
	}

	// An event's fd is taken by the handler that expects it.
	got := make(chan int, 1)
	obj := d.NewID(func(op uint16, a *Args) error {
		_ = a.String()
		got <- a.FD()
		return a.Err
	})
	var q [2]int
	unix.Pipe(q[:])
	defer unix.Close(q[0])
	f.event(obj, 0, (&Request{}).String("text/plain"), q[1])
	unix.Close(q[1])
	if err := d.Dispatch(); err != nil {
		t.Fatal(err)
	}
	fd := <-got
	if fd < 0 {
		t.Fatal("the handler got no fd")
	}
	unix.Write(fd, []byte("x"))
	unix.Close(fd)
	if n, _ := unix.Read(q[0], buf); n != 1 {
		t.Error("the event's fd does not reach the pipe")
	}
}

func TestProtocolError(t *testing.T) {
	d, f := newPair(t)
	f.event(displayID, 0, (&Request{}).Uint(5).Uint(1).String("bad request"), -1)
	err := d.Dispatch()
	if e, ok := err.(*Error); !ok || e.Object != 5 || e.Message != "bad request" {
		t.Errorf("Dispatch = %v, want the protocol error", err)
	}
}

func TestEventsInPieces(t *testing.T) {
	// Events may arrive split across reads and several in one read.
	d, f := newPair(t)
	var seen []uint32
	obj := d.NewID(func(op uint16, a *Args) error {
		seen = append(seen, a.Uint())
		return a.Err
	})
	var all []byte
	for i := range 3 {
		m := binary.NativeEndian.AppendUint32(nil, obj)
		m = binary.NativeEndian.AppendUint32(m, uint32(12)<<16)
		all = binary.NativeEndian.AppendUint32(append(all, m...), uint32(i))
	}
	f.c.Write(all[:5])
	go func() { f.c.Write(all[5:]) }()
	for len(seen) < 3 {
		if err := d.Dispatch(); err != nil {
			t.Fatal(err)
		}
	}
	if seen[0] != 0 || seen[2] != 2 {
		t.Errorf("events %v", seen)
	}
}

func TestCompositorGone(t *testing.T) {
	d, f := newPair(t)
	f.c.Close()
	if err := d.Dispatch(); err == nil {
		t.Error("Dispatch after the compositor closed returned no error")
	}
}
