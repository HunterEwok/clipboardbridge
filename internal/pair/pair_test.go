// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/third_party/cpace"
)

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// socketPair returns the two ends of a connected Unix socket, which buffers
// like TCP and needs no port.
func socketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) net.Conn {
		f := os.NewFile(uintptr(fd), "socketpair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	return conn(fds[0]), conn(fds[1])
}

// clock is the uptime clock of a test window, and its expiry timer.
type clock struct {
	mu    sync.Mutex
	up    time.Duration
	fire  func()
	timer time.Duration
}

func (c *clock) uptime() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.up
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.up += d
}

func (c *clock) afterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timer, c.fire = d, f
	return func() bool { return true }
}

type fixture struct {
	admin  *group.Identity
	window *Window
	code   string
	clock  *clock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	admin, err := group.Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{up: time.Hour}
	code := NewCode()
	w, err := Open(admin, code, Options{Now: func() time.Time { return t0 }, Uptime: clk.uptime, AfterFunc: clk.afterFunc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return &fixture{admin: admin, window: w, code: code, clock: clk}
}

func (f *fixture) failures() int {
	f.window.mu.Lock()
	defer f.window.mu.Unlock()
	return f.window.failures
}

func (f *fixture) wrongCode() string {
	if f.code == "000000" {
		return "000001"
	}
	return "000000"
}

func newJoiner(t *testing.T, os string) *Joiner {
	t.Helper()
	j, err := NewJoiner(Info{Name: "pi-" + os, OS: os})
	if err != nil {
		t.Fatal(err)
	}
	j.Now = func() time.Time { return t0 }
	return j
}

type outcome struct {
	id         *group.Identity
	joinErr    error
	serveErr   error
	savedCalls int
}

// attempt runs one pairing attempt between a joiner and the fixture's
// window over a local connection.
func (f *fixture) attempt(t *testing.T, j *Joiner, code string, save func(*group.Identity) error) outcome {
	t.Helper()
	a, b := socketPair(t)
	var out outcome
	done := make(chan struct{})
	go func() {
		defer close(done)
		out.serveErr = f.window.Serve(context.Background(), tls.Server(b, ServerTLS(f.admin)))
	}()
	if save == nil {
		save = func(*group.Identity) error { return nil }
	}
	out.id, out.joinErr = j.Join(context.Background(), a, code, func(id *group.Identity) error {
		out.savedCalls++
		return save(id)
	})
	a.Close()
	<-done
	return out
}

func closed(w *Window) bool {
	select {
	case <-w.Done():
		return true
	default:
		return false
	}
}

func TestPairMac(t *testing.T) {
	f := newFixture(t)
	j := newJoiner(t, "darwin")
	out := f.attempt(t, j, f.code, nil)
	if out.joinErr != nil || out.serveErr != nil {
		t.Fatalf("join: %v; serve: %v", out.joinErr, out.serveErr)
	}
	id := out.id
	if id.ID != j.ID || !id.Key.Equal(j.Key) || id.Admin() || id.PhoneCA != nil || id.GroupCA.Key != nil {
		t.Error("a Mac got the wrong identity, or CA keys")
	}
	if !id.GroupCA.Cert.Equal(f.admin.GroupCA.Cert) {
		t.Error("the Mac got another group CA")
	}
	if out.savedCalls != 1 {
		t.Errorf("save called %d times", out.savedCalls)
	}
	if !closed(f.window) {
		t.Fatal("the window is still open after a success")
	}
	res, err := f.window.Result()
	if err != nil || res.Device != j.ID || res.Info != j.Info || !res.Cert.Equal(id.Cert) || !res.Confirmed {
		t.Errorf("Result = %+v, %v", res, err)
	}
	assertMembers(t, id, f.admin)
	// The window admits one device only.
	if out := f.attempt(t, newJoiner(t, "darwin"), f.code, nil); !errors.Is(out.joinErr, ErrClosed) {
		t.Errorf("a second device through the same window: %v", out.joinErr)
	}
}

func TestPairLinux(t *testing.T) {
	f := newFixture(t)
	j := newJoiner(t, "linux")
	out := f.attempt(t, j, f.code[:3]+" "+f.code[3:], nil)
	if out.joinErr != nil || out.serveErr != nil {
		t.Fatalf("join: %v; serve: %v", out.joinErr, out.serveErr)
	}
	id := out.id
	if !id.Admin() || !id.GroupCA.Key.Equal(f.admin.GroupCA.Key) || !id.PhoneCA.Key.Equal(f.admin.PhoneCA.Key) {
		t.Fatal("a Linux member did not get the CA keys")
	}
	if !id.Phone.PublicKey.(*ecdsa.PublicKey).Equal(&j.Key.PublicKey) {
		t.Error("the clipbridge.local certificate is not for the device's key")
	}
	assertMembers(t, id, f.admin)
}

// assertMembers checks that a and b complete a member handshake.
func assertMembers(t *testing.T, a, b *group.Identity) {
	t.Helper()
	x, y := socketPair(t)
	now := group.TLSOptions{Now: func() time.Time { return t0 }}
	errc := make(chan error, 1)
	go func() { errc <- tls.Server(y, b.ServerTLS(now)).Handshake() }()
	cerr := tls.Client(x, a.ClientTLS(b.ID, now)).Handshake()
	if serr := <-errc; cerr != nil || serr != nil {
		t.Errorf("member handshake after pairing: client %v, server %v", cerr, serr)
	}
}

func TestWrongCode(t *testing.T) {
	f := newFixture(t)
	for i := 1; i <= MaxFailures; i++ {
		out := f.attempt(t, newJoiner(t, "linux"), f.wrongCode(), nil)
		if !errors.Is(out.joinErr, ErrWrongCode) || !errors.Is(out.serveErr, ErrWrongCode) {
			t.Fatalf("attempt %d: join %v, serve %v; want ErrWrongCode", i, out.joinErr, out.serveErr)
		}
		if out.savedCalls != 0 {
			t.Fatal("save was called after a wrong code")
		}
		if f.failures() != i {
			t.Fatalf("failures = %d after %d wrong codes", f.failures(), i)
		}
	}
	if !closed(f.window) {
		t.Fatal("the window is open after three wrong codes")
	}
	if _, err := f.window.Result(); !errors.Is(err, ErrTooMany) {
		t.Errorf("Result error %v, want ErrTooMany", err)
	}
	if out := f.attempt(t, newJoiner(t, "linux"), f.code, nil); !errors.Is(out.joinErr, ErrTooMany) {
		t.Errorf("the right code after three wrong ones: %v, want ErrTooMany", out.joinErr)
	}
}

func TestWrongCodeThenRight(t *testing.T) {
	f := newFixture(t)
	f.attempt(t, newJoiner(t, "darwin"), f.wrongCode(), nil)
	f.attempt(t, newJoiner(t, "darwin"), f.wrongCode(), nil)
	if out := f.attempt(t, newJoiner(t, "darwin"), f.code, nil); out.joinErr != nil {
		t.Errorf("the right code after two wrong ones: %v", out.joinErr)
	}
}

func TestExpiry(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(Lifetime)
	out := f.attempt(t, newJoiner(t, "darwin"), f.code, nil)
	if !errors.Is(out.joinErr, ErrExpired) || !errors.Is(out.serveErr, ErrExpired) {
		t.Errorf("join %v, serve %v; want the window expired", out.joinErr, out.serveErr)
	}
	if _, err := f.window.Result(); !errors.Is(err, ErrExpired) {
		t.Errorf("Result error %v, want ErrExpired", err)
	}
}

func TestExpiryTimer(t *testing.T) {
	// The timer closes the window after five minutes, with no attempt.
	f := newFixture(t)
	f.clock.mu.Lock()
	d, fire := f.clock.timer, f.clock.fire
	f.clock.mu.Unlock()
	if d != Lifetime || fire == nil {
		t.Fatalf("the window set a timer for %v", d)
	}
	fire()
	if !closed(f.window) {
		t.Fatal("the timer did not close the window")
	}
	if _, err := f.window.Result(); !errors.Is(err, ErrExpired) {
		t.Errorf("Result error %v, want ErrExpired", err)
	}
}

func TestExpiryDuringAnAttempt(t *testing.T) {
	// An attempt that started in time finishes, even if the window's five
	// minutes end while it runs.
	f := newFixture(t)
	out := f.attempt(t, newJoiner(t, "darwin"), f.code, func(*group.Identity) error {
		f.clock.advance(Lifetime + time.Minute)
		f.clock.fire()
		return nil
	})
	if out.joinErr != nil || out.serveErr != nil {
		t.Fatalf("join %v, serve %v", out.joinErr, out.serveErr)
	}
	if res, err := f.window.Result(); err != nil || res == nil {
		t.Errorf("Result = %v, %v; want the success", res, err)
	}
	// A failed attempt that runs past the end closes the window when it
	// ends, and the timer does not close it while it runs.
	g := newFixture(t)
	if err := g.window.acquire(func() {}); err != nil {
		t.Fatal(err)
	}
	g.clock.advance(Lifetime + time.Second)
	g.window.expire()
	if closed(g.window) {
		t.Fatal("the window closed during an attempt")
	}
	g.window.release(true)
	if _, err := g.window.Result(); !errors.Is(err, ErrExpired) {
		t.Errorf("Result error %v, want ErrExpired", err)
	}
}

func TestClose(t *testing.T) {
	f := newFixture(t)
	f.window.Close()
	out := f.attempt(t, newJoiner(t, "darwin"), f.code, nil)
	if !errors.Is(out.serveErr, ErrClosed) || !errors.Is(out.joinErr, ErrClosed) {
		t.Errorf("join %v, serve %v; want ErrClosed", out.joinErr, out.serveErr)
	}
}

func TestCloseAfterTheWelcome(t *testing.T) {
	// Once the welcome went out, the device is admitted, and Close does not
	// hide it.
	f := newFixture(t)
	out := f.attempt(t, newJoiner(t, "linux"), f.code, func(*group.Identity) error {
		f.window.Close()
		return nil
	})
	if out.joinErr != nil || out.serveErr != nil {
		t.Fatalf("join %v, serve %v", out.joinErr, out.serveErr)
	}
	res, err := f.window.Result()
	if err != nil || res == nil || !res.Confirmed {
		t.Errorf("Result = %+v, %v; want the admitted device", res, err)
	}
}

func TestSaveFailure(t *testing.T) {
	// A device that got the welcome but could not store it is still
	// recorded, unconfirmed, and the window closes: it may hold the keys.
	f := newFixture(t)
	disk := errors.New("disk full")
	out := f.attempt(t, newJoiner(t, "linux"), f.code, func(*group.Identity) error { return disk })
	if !errors.Is(out.joinErr, disk) || out.serveErr == nil {
		t.Fatalf("join %v, serve %v", out.joinErr, out.serveErr)
	}
	if !closed(f.window) {
		t.Fatal("the window stayed open after the keys went out")
	}
	res, err := f.window.Result()
	if err != nil || res == nil || res.Confirmed {
		t.Errorf("Result = %+v, %v; want an unconfirmed device", res, err)
	}
}

func TestBusy(t *testing.T) {
	f := newFixture(t)
	// A first connection that completes TLS and then stalls holds the slot.
	a, b := socketPair(t)
	served := make(chan error, 1)
	go func() { served <- f.window.Serve(context.Background(), tls.Server(b, ServerTLS(f.admin))) }()
	j := newJoiner(t, "darwin")
	cfg, err := j.clientTLSVerifiedByCPace()
	if err != nil {
		t.Fatal(err)
	}
	stall := tls.Client(a, cfg)
	if err := stall.Handshake(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.window.mu.Lock()
		busy := f.window.busy
		f.window.mu.Unlock()
		if busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first attempt never started")
		}
		time.Sleep(time.Millisecond)
	}
	out := f.attempt(t, newJoiner(t, "darwin"), f.code, nil)
	if !errors.Is(out.serveErr, ErrBusy) || !errors.Is(out.joinErr, ErrBusy) {
		t.Errorf("join %v, serve %v; want busy", out.joinErr, out.serveErr)
	}
	stall.Close()
	<-served
	// A stalled attempt that never sent a CPace message does not count, and
	// neither does a busy one.
	if f.failures() != 0 {
		t.Errorf("failures = %d", f.failures())
	}
	if out := f.attempt(t, newJoiner(t, "darwin"), f.code, nil); out.joinErr != nil {
		t.Errorf("join after the stalled attempt: %v", out.joinErr)
	}
}

// relay runs a device in the middle: it terminates the joiner's TLS session
// with toJoiner and opens its own to the member with toMember, and forwards
// every frame unchanged.
func relay(t *testing.T, f *fixture, joinerConn net.Conn, toJoiner, toMember *tls.Config) (serveErr chan error) {
	t.Helper()
	ra := joinerConn
	rb, mb := socketPair(t)
	serveErr = make(chan error, 1)
	go func() { serveErr <- f.window.Serve(context.Background(), tls.Server(mb, ServerTLS(f.admin))) }()
	go func() {
		j, m := tls.Server(ra, toJoiner), tls.Client(rb, toMember)
		if j.Handshake() != nil || m.Handshake() != nil {
			j.Close()
			m.Close()
			return
		}
		go func() {
			defer j.Close()
			for {
				fr, err := readFrame(m)
				if err != nil || writeFrame(j, fr) != nil {
					return
				}
			}
		}()
		defer m.Close()
		for {
			fr, err := readFrame(j)
			if err != nil || writeFrame(m, fr) != nil {
				return
			}
		}
	}()
	return serveErr
}

// TestRelay checks the central property: a device in the middle that
// forwards every frame unchanged makes the exchange fail, even though the
// joiner typed the right code.
func TestRelay(t *testing.T) {
	for _, realCerts := range []bool{false, true} {
		name := "own certificates"
		if realCerts {
			// The relay shows each side the certificate it expects, so
			// only the TLS exporter differs between the two sessions.
			name = "the real certificates"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			j := newJoiner(t, "linux")
			joinerCfg, err := j.clientTLSVerifiedByCPace()
			if err != nil {
				t.Fatal(err)
			}
			mitm, err := group.Create(t0)
			if err != nil {
				t.Fatal(err)
			}
			serverCert := tls.Certificate{Certificate: [][]byte{mitm.Cert.Raw}, PrivateKey: mitm.Key}
			toMember, err := (&Joiner{ID: group.NewDeviceID(), Key: mitm.Key}).clientTLSVerifiedByCPace()
			if err != nil {
				t.Fatal(err)
			}
			if realCerts {
				serverCert = tls.Certificate{Certificate: [][]byte{f.admin.Cert.Raw}, PrivateKey: f.admin.Key}
				toMember = joinerCfg
			}
			toJoiner := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
				ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{Protocol}}
			ja, ra := socketPair(t)
			served := relay(t, f, ra, toJoiner, toMember)
			saved := false
			id, err := j.Join(context.Background(), ja, f.code, func(*group.Identity) error { saved = true; return nil })
			ja.Close()
			if err == nil || id != nil || saved {
				t.Fatal("the joiner paired through a relay")
			}
			if serr := <-served; serr == nil {
				t.Fatal("the member admitted a device through a relay")
			}
			if res, _ := f.window.Result(); res != nil {
				t.Fatal("the window reports a device admitted through a relay")
			}
			if f.failures() != 1 {
				t.Errorf("failures = %d after a relay, want 1", f.failures())
			}
		})
	}
}

func TestBinding(t *testing.T) {
	// Both certificates enter the channel identifier, in order, and the
	// session identifier is the TLS exporter.
	f := newFixture(t)
	a, b := socketPair(t)
	cfg, err := newJoiner(t, "darwin").clientTLSVerifiedByCPace()
	if err != nil {
		t.Fatal(err)
	}
	go tls.Server(b, ServerTLS(f.admin)).Handshake()
	c := tls.Client(a, cfg)
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	cs := c.ConnectionState()
	ci, sid, err := binding(cs, []byte("member"), []byte("joiner"))
	if err != nil {
		t.Fatal(err)
	}
	exp, _ := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if !bytes.Equal(sid, exp) {
		t.Error("the session identifier is not the exporter")
	}
	for _, other := range [][2]string{{"other", "joiner"}, {"member", "other"}, {"joiner", "member"}} {
		ci2, _, _ := binding(cs, []byte(other[0]), []byte(other[1]))
		if bytes.Equal(ci, ci2) {
			t.Errorf("the channel identifier ignores %v", other)
		}
	}
}

// fakeMember answers a joiner like a member of another group that does not
// know the code, but otherwise follows the protocol to the end.
func TestFakeMember(t *testing.T) {
	other, err := group.Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	j := newJoiner(t, "linux")
	a, b := socketPair(t)
	go func() {
		tc := tls.Server(b, ServerTLS(other))
		defer tc.Close()
		if tc.Handshake() != nil {
			return
		}
		cs := tc.ConnectionState()
		first, err := readFrame(tc)
		if err != nil {
			return
		}
		ci, sid, _ := binding(cs, other.Cert.Raw, cs.PeerCertificates[0].Raw)
		ad, _ := json.Marshal(memberAD{Device: other.ID, Group: group.Tag(other.GroupCA.Cert)})
		st, msg, _ := cpace.Start(&cpace.Config{Role: cpace.Responder, Password: []byte("999999"), ChannelID: ci, SessionID: sid, AD: ad})
		writeFrame(tc, &frame{Msg: msg, AD: ad})
		st.Finish(first.Msg, first.AD)
		readFrame(tc)
		pub := cs.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
		cert, _ := other.GroupCA.IssueMember(j.ID, pub, t0)
		w := &Window{admin: other}
		wel, _ := w.welcome(cert, true)
		writeFrame(tc, &frame{Tag: st.Tag(), Welcome: wel})
		readFrame(tc)
	}()
	saved := false
	code := "123456"
	id, err := j.Join(context.Background(), a, code, func(*group.Identity) error { saved = true; return nil })
	if err == nil || id != nil || saved {
		t.Fatalf("joined a member that does not know the code: %v", err)
	}
}

// rawJoiner drives the joiner's side frame by frame, to see exactly what the
// member sends.
type rawJoiner struct {
	t     *testing.T
	tc    *tls.Conn
	st    *cpace.State
	reply *frame
}

func startRaw(t *testing.T, f *fixture, info Info, code string) (*rawJoiner, chan error) {
	t.Helper()
	j, err := NewJoiner(Info{Name: "raw", OS: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	a, b := socketPair(t)
	served := make(chan error, 1)
	go func() { served <- f.window.Serve(context.Background(), tls.Server(b, ServerTLS(f.admin))) }()
	cfg, err := j.clientTLSVerifiedByCPace()
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(a, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	cs := tc.ConnectionState()
	ci, sid, err := binding(cs, cs.PeerCertificates[0].Raw, cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	ad, _ := json.Marshal(info)
	st, msg, err := cpace.Start(&cpace.Config{Role: cpace.Initiator, Password: []byte(code), ChannelID: ci, SessionID: sid, AD: ad})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(tc, &frame{Msg: msg, AD: ad}); err != nil {
		t.Fatal(err)
	}
	reply, err := readFrame(tc)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Msg != nil {
		if _, err := st.Finish(reply.Msg, reply.AD); err != nil {
			t.Fatal(err)
		}
	}
	return &rawJoiner{t: t, tc: tc, st: st, reply: reply}, served
}

// confirm sends the joiner's tag and returns the member's answer.
func (r *rawJoiner) confirm() *frame {
	r.t.Helper()
	if err := writeFrame(r.tc, &frame{Tag: r.st.Tag()}); err != nil {
		r.t.Fatal(err)
	}
	f, err := readFrame(r.tc)
	if err != nil {
		r.t.Fatal(err)
	}
	return f
}

func TestWhatTheMemberSends(t *testing.T) {
	t.Run("its CPace message carries no tag", func(t *testing.T) {
		f := newFixture(t)
		r, _ := startRaw(t, f, Info{Name: "x", OS: "linux"}, f.code)
		if r.reply.Tag != nil || r.reply.Welcome != nil || r.reply.Msg == nil {
			t.Errorf("second frame %+v", r.reply)
		}
	})
	t.Run("a wrong code gets only an error", func(t *testing.T) {
		f := newFixture(t)
		r, _ := startRaw(t, f, Info{Name: "x", OS: "linux"}, f.wrongCode())
		last := r.confirm()
		if last.Tag != nil || last.Welcome != nil || last.Error != "wrong-code" {
			t.Errorf("last frame %+v", last)
		}
	})
	t.Run("a Mac gets no CA keys", func(t *testing.T) {
		f := newFixture(t)
		r, _ := startRaw(t, f, Info{Name: "mac", OS: "darwin"}, f.code)
		w := r.confirm().Welcome
		if w == nil || w.GroupCAKey != nil || w.PhoneCA != nil || w.PhoneCAKey != nil {
			t.Errorf("welcome to a Mac: %+v", w)
		}
	})
	t.Run("a Linux member gets them", func(t *testing.T) {
		f := newFixture(t)
		r, _ := startRaw(t, f, Info{Name: "pi", OS: "linux"}, f.code)
		w := r.confirm().Welcome
		if w == nil || w.GroupCAKey == nil || w.PhoneCA == nil || w.PhoneCAKey == nil {
			t.Errorf("welcome to a Linux member: %+v", w)
		}
	})
	t.Run("a bad description is refused and does not count", func(t *testing.T) {
		f := newFixture(t)
		r, served := startRaw(t, f, Info{Name: "bad\nname", OS: "linux"}, f.code)
		if r.reply.Error != "refused" || r.reply.Msg != nil {
			t.Errorf("answer to a bad description: %+v", r.reply)
		}
		if err := <-served; err == nil {
			t.Error("Serve accepted a bad description")
		}
		if f.failures() != 0 || closed(f.window) {
			t.Error("a bad description counted as a failure")
		}
	})
	t.Run("Close before the welcome fails the attempt", func(t *testing.T) {
		f := newFixture(t)
		r, served := startRaw(t, f, Info{Name: "pi", OS: "linux"}, f.code)
		f.window.Close()
		if err := <-served; !errors.Is(err, ErrClosed) {
			t.Errorf("Serve after Close: %v", err)
		}
		writeFrame(r.tc, &frame{Tag: r.st.Tag()})
		if fr, err := readFrame(r.tc); err == nil && fr.Welcome != nil {
			t.Error("the welcome went out after Close")
		}
		if res, _ := f.window.Result(); res != nil {
			t.Error("a device was admitted after Close")
		}
	})
}

func TestServerTLSRejects(t *testing.T) {
	f := newFixture(t)
	j := newJoiner(t, "darwin")
	good, err := j.clientTLSVerifiedByCPace()
	if err != nil {
		t.Fatal(err)
	}
	selfSigned := func(id string, curve elliptic.Curve) *tls.Config {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: id}, NotBefore: t0, NotAfter: t0.AddDate(1, 0, 0)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cfg := good.Clone()
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
		return cfg
	}
	noCert := good.Clone()
	noCert.Certificates = nil
	memberALPN := good.Clone()
	memberALPN.NextProtos = []string{group.MemberProtocol}
	noALPN := good.Clone()
	noALPN.NextProtos = nil
	for name, cfg := range map[string]*tls.Config{
		"no certificate":            noCert,
		"the member protocol":       memberALPN,
		"no protocol":               noALPN,
		"a bad device ID":           selfSigned("not-a-device", elliptic.P256()),
		"a P-384 key":               selfSigned(string(group.NewDeviceID()), elliptic.P384()),
		"the member's own identity": selfSigned(string(f.admin.ID), elliptic.P256()),
	} {
		t.Run(name, func(t *testing.T) {
			a, b := socketPair(t)
			errc := make(chan error, 1)
			go func() { errc <- tls.Server(b, ServerTLS(f.admin)).Handshake() }()
			go func() {
				c := tls.Client(a, cfg)
				if c.Handshake() == nil {
					c.Read(make([]byte, 1))
				}
			}()
			select {
			case err := <-errc:
				if err == nil {
					t.Error("the server accepted the handshake")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the handshake hung")
			}
		})
	}
}

func TestJoinerChecksTheWelcome(t *testing.T) {
	f := newFixture(t)
	other, err := group.Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	j := newJoiner(t, "linux")
	cert, err := f.admin.GroupCA.IssueMember(j.ID, &j.Key.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	w, err := f.window.welcome(cert, true)
	if err != nil {
		t.Fatal(err)
	}
	member := memberAD{Device: f.admin.ID, Group: group.Tag(f.admin.GroupCA.Cert)}
	if _, err := j.identity(w, f.admin.Cert, member); err != nil {
		t.Fatalf("a good welcome: %v", err)
	}
	// A member certificate from the other group that names the real
	// member's device ID: only the CA differs.
	otherKey, _ := group.NewKey()
	lookalike, err := other.GroupCA.IssueMember(f.admin.ID, &otherKey.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	certForOtherKey, err := f.admin.GroupCA.IssueMember(j.ID, &otherKey.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	otherCAKey, _ := x509.MarshalPKCS8PrivateKey(other.GroupCA.Key)
	tests := []struct {
		name   string
		change func(w *Welcome, m *memberAD, memberCert **x509.Certificate)
	}{
		{"another group CA than announced", func(w *Welcome, _ *memberAD, _ **x509.Certificate) { w.GroupCA = other.GroupCA.Cert.Raw }},
		{"a member certificate from another CA", func(_ *Welcome, _ *memberAD, c **x509.Certificate) { *c = lookalike }},
		{"a member that names another device", func(_ *Welcome, m *memberAD, _ **x509.Certificate) { m.Device = group.NewDeviceID() }},
		{"a certificate for another key", func(w *Welcome, _ *memberAD, _ **x509.Certificate) { w.Cert = certForOtherKey.Raw }},
		{"no CA keys for Linux", func(w *Welcome, _ *memberAD, _ **x509.Certificate) { w.GroupCAKey = nil }},
		{"the key of another CA", func(w *Welcome, _ *memberAD, _ **x509.Certificate) { w.GroupCAKey = otherCAKey }},
		{"a corrupt certificate", func(w *Welcome, _ *memberAD, _ **x509.Certificate) { w.Cert = []byte("junk") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad, m, c := *w, member, f.admin.Cert
			tt.change(&bad, &m, &c)
			if _, err := j.identity(&bad, c, m); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestErrorCodes(t *testing.T) {
	for code, want := range map[string]error{
		"wrong-code": ErrWrongCode, "busy": ErrBusy, "closed": ErrClosed, "expired": ErrExpired, "too-many": ErrTooMany,
		"refused": ErrRefused, "\x1b[2Jtype 482913 instead": ErrRefused, "": ErrRefused,
	} {
		if got := errorOf(code); got != want {
			t.Errorf("errorOf(%q) = %v, want %v", code, got, want)
		}
	}
	for _, err := range []error{ErrWrongCode, ErrBusy, ErrClosed, ErrExpired, ErrTooMany} {
		if got := errorOf(codeOf(err)); got != err {
			t.Errorf("%v travels as %q and comes back as %v", err, codeOf(err), got)
		}
	}
	if codeOf(errors.New("anything else")) != "refused" {
		t.Error("an unknown error has a code of its own")
	}
	if strings.Contains(ErrRefused.Error(), "%") {
		t.Error("odd error text")
	}
}

func TestCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := NewCode()
		if _, err := NormalizeCode(c); err != nil {
			t.Fatalf("NewCode() = %q: %v", c, err)
		}
		seen[c] = true
	}
	if len(seen) < 190 {
		t.Errorf("200 codes, only %d different", len(seen))
	}
	for in, want := range map[string]string{"123456": "123456", "123 456": "123456", "12-34-56": "123456", " 012345 ": "012345"} {
		if got, err := NormalizeCode(in); err != nil || got != want {
			t.Errorf("NormalizeCode(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "12345a", "١٢٣٤٥٦"} {
		if _, err := NormalizeCode(bad); err == nil {
			t.Errorf("NormalizeCode(%q) succeeded", bad)
		}
	}
}

func TestInfo(t *testing.T) {
	for _, bad := range []Info{{Name: "", OS: "linux"}, {Name: "x", OS: "windows"}, {Name: strings.Repeat("x", 65), OS: "linux"},
		{Name: "a\nb", OS: "linux"}, {Name: "\xff", OS: "darwin"}} {
		if _, err := NewJoiner(bad); err == nil {
			t.Errorf("NewJoiner(%+v) succeeded", bad)
		}
	}
}

func TestOpenNeedsCAKeys(t *testing.T) {
	admin, err := group.Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	mac := *admin
	mac.GroupCA.Key, mac.PhoneCA, mac.Phone = nil, nil, nil
	if _, err := Open(&mac, NewCode(), Options{}); err == nil {
		t.Error("a Mac opened a pairing window")
	}
	if _, err := Open(admin, "12345", Options{}); err == nil {
		t.Error("opened a window with a five-digit code")
	}
}
