// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"hash/crc32"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/phone"
)

// publishLite puts a lite member on the fake network, as the real one
// publishes itself: TXT r=lite, at 127.0.0.1 and port.
func publishLite(h *hub, id, tag string, port int) {
	h.mu.Lock()
	if h.ghosts == nil {
		h.ghosts = map[string]mdns.Peer{}
	}
	h.ghosts[id] = mdns.Peer{ID: id, Port: uint16(port), TXT: []string{"v=1", "g=" + tag, "r=lite"},
		Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	h.mu.Unlock()
	h.update()
}

// TestLiteNotDialed: the full members, a Mac too, leave a lite member they
// find to dial them, whatever the device IDs.
func TestLiteNotDialed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var dialed atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			c.Close()
		}
	}()
	var h hub
	pi := startService(t, &h, "pi")
	mac := startRole(t, &h, "mac", group.OSMacOS)
	pairWith(t, pi, mac) // the group exists from here
	// The greatest device ID: a full member would dial a full member with it.
	publishLite(&h, strings.Repeat("f", 32), pi.status(t).Group, ln.Addr().(*net.TCPAddr).Port)
	time.Sleep(2 * time.Second)
	if n := dialed.Load(); n != 0 {
		t.Fatalf("the full members dialed the lite member %d times", n)
	}
}

// startLite runs the lite member (Rust, lite/) with the state in
// dir; it is stopped by stop or at the end of the test.
func startLite(t *testing.T, bin, dir string, args ...string) *testService {
	t.Helper()
	s := &testService{name: "lite", dir: dir, socket: filepath.Join(dir, "c.sock")}
	cmd := exec.Command(bin, append([]string{"-state", dir, "-socket", s.socket, "-debug", "run"}, args...)...)
	cmd.Stdout, cmd.Stderr = testWriter{t, "lite: "}, testWriter{t, "lite: "}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.done = make(chan error, 1)
	go func() { s.done <- cmd.Wait() }()
	s.cancel = func() {
		cmd.Process.Signal(os.Interrupt)
		time.AfterFunc(5*time.Second, func() { cmd.Process.Kill() })
	}
	t.Cleanup(s.stop)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := control.Dial(s.socket); err == nil {
			c.Close()
			return s
		}
		select {
		case err := <-s.done:
			s.cancel = nil
			t.Fatalf("the lite member ended at the start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the control socket of the lite member never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// testWriter logs what a child process writes.
type testWriter struct {
	t      *testing.T
	prefix string
}

func (w testWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		w.t.Log(w.prefix + line)
	}
	return len(p), nil
}

// TestEmbassyJoiner: the ESP32 firmware's pairing code (lite/embassy),
// built for Linux as esp32-on-linux, joins by the phone over embassy-net on a
// TAP interface, as the board does over Wi-Fi. CBB_ESP32_ON_LINUX names the
// binary; the interface tap0 must be up as 192.168.69.1/24, and the device
// takes 192.168.69.2.
func TestEmbassyJoiner(t *testing.T) {
	bin := os.Getenv("CBB_ESP32_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_ESP32_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), "identity.json")
	join := exec.Command(bin, "-debug", "-tap", "tap0", "-addr", "192.168.69.2/24", "-name", "board", "-identity", file)
	join.Stderr = testWriter{t, "esp32-on-linux: "}
	out, err := join.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := join.Start(); err != nil {
		t.Fatal(err)
	}
	defer join.Process.Kill()
	const prefix = "Or paste this into the app: "
	var qr string
	sc := bufio.NewScanner(out)
	for qr == "" && sc.Scan() {
		if line, ok := strings.CutPrefix(sc.Text(), prefix); ok {
			qr = line
		}
	}
	if !strings.Contains(qr, "192.168.69.2%3A8764") && !strings.Contains(qr, "192.168.69.2:8764") {
		t.Fatalf("esp32-on-linux showed %q, not a QR code with its address", qr)
	}
	res := dialJoiner(t, pi.dir, qr)
	if res.Info.Name != "board" || res.Info.Role != pair.RoleLite || !res.Confirmed {
		t.Fatalf("the board joined as %+v", res)
	}
	var rest strings.Builder
	for sc.Scan() {
		rest.WriteString(sc.Text() + "\n")
	}
	if err := join.Wait(); err != nil || !strings.Contains(rest.String(), "Joined the group "+pi.status(t).Group) {
		t.Fatalf("esp32-on-linux: %v; %s", err, rest.String())
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "_key") {
		t.Error("the board saved a CA key")
	}
}

// dialJoiner plays the phone that scanned a listening joiner's QR code: it
// opens a window with the identity in dir, dials the addresses in the QR
// code and admits the device with the certificate it names. The service no
// longer dials for the shortcut, so the test does it as the phone kits do.
func dialJoiner(t *testing.T, dir, qr string) *pair.Result {
	t.Helper()
	jc, ok := phone.ParseJoinQR(qr)
	if !ok || len(jc.Addrs) == 0 || jc.Fingerprint == "" {
		t.Fatalf("not a QR code of a listening joiner: %q", qr)
	}
	id, err := group.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pair.Open(id, jc.Code, pair.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), joinTimeout)
	defer cancel()
	var lastErr error
	for _, addr := range jc.Addrs {
		raw, err := net.DialTimeout("tcp", addr, handshakeTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		if lastErr = w.Dial(ctx, raw, jc.Fingerprint); lastErr == nil {
			break
		}
	}
	select {
	case <-w.Done():
	default:
		t.Fatalf("dialing the joiner: %v", lastErr)
	}
	res, err := w.Result()
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// joinLite has the lite member join pi's group: cbb pair on pi shows a
// code, and cbb join -code on the lite member reads it from standard input
// and joins at pi's address. It returns the lite member's state directory.
func joinLite(t *testing.T, bin string, pi *testService) string {
	t.Helper()
	c, code := openWindow(t, pi)
	defer c.Close()
	pa, _ := pi.addrs()
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "-debug", "join", "-name", "lite", "-code", pa)
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "lite join: "}
	out, err := join.Output()
	if err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb join: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "lite" {
		t.Fatalf("pair on pi ended with %+v, %v", m, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "_key") {
		t.Error("the lite member saved a CA key")
	}
	return dir
}

// TestLiteMember runs the lite member among Go members: it joins with the
// code of cbb pair, gets no CA keys, is listed as a lite device and syncs
// both ways. (Joining by the phone's QR code, where the phone dials the
// lite member, is covered by the phone kits' tests.) CBB_LITE names the
// lite member's binary (cargo build in lite/).
func TestLiteMember(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	laptop := startService(t, &h, "laptop")
	pairWith(t, pi, laptop)

	dir := joinLite(t, bin, pi)
	pa, _ := pi.addrs()

	// The lite member dials the computers, a Mac too, and syncs with them.
	mac := startRole(t, &h, "mac", group.OSMacOS)
	pairWith(t, pi, mac)
	la, _ := laptop.addrs()
	ma, _ := mac.addrs()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	lite := startLite(t, bin, dir, "-no-mdns", "-port", strconv.Itoa(port), "-peer", pa, "-peer", la, "-peer", ma)
	// The control socket answers while the service still loads its identity.
	waitFor(t, "the lite member in the group", func() bool {
		_, err := lite.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil
	})
	st := lite.status(t)
	if st.Group != pi.status(t).Group || st.Role != "lite" {
		t.Fatalf("lite status %+v, want the group %s", st, pi.status(t).Group)
	}
	waitFor(t, "the lite member connected", func() bool { return len(lite.status(t).Peers) == 3 })
	if _, err := lite.do(t, control.Header{Op: control.OpCopy}, "from the lite member"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{pi, laptop, mac} {
		waitFor(t, s.name+" has the lite text", func() bool { return s.paste(t) == "from the lite member" })
	}
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "from the laptop"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member has the laptop text", func() bool { return lite.paste(t) == "from the laptop" })

	// The ZX Spectrum Next's front end: texts in the Spectrum character set,
	// with their length and CRC-32 (lite/README.md, "ZX Spectrum Next").
	zx := []byte("ZX \x605\rnext")
	next := exec.Command(bin, "-socket", lite.socket, "next", "copy", strconv.Itoa(len(zx)), fmt.Sprintf("%08x", crc32.ChecksumIEEE(zx)))
	next.Stdin = bytes.NewReader(zx)
	if out, err := next.Output(); err != nil || string(out) != "CBBGO\rCBBOK\r" {
		t.Fatalf("cbb next copy: %v; %q", err, out)
	}
	waitFor(t, "the laptop has the Next's text", func() bool { return laptop.paste(t) == "ZX £5\nnext" })
	// .cbb text -s: a secret from the Next arrives as a secret.
	pw := []byte("hunter2")
	next = exec.Command(bin, "-socket", lite.socket, "next", "copy", "-secret", strconv.Itoa(len(pw)), fmt.Sprintf("%08x", crc32.ChecksumIEEE(pw)))
	next.Stdin = bytes.NewReader(pw)
	if out, err := next.Output(); err != nil || string(out) != "CBBGO\rCBBOK\r" {
		t.Fatalf("cbb next copy -secret: %v; %q", err, out)
	}
	waitFor(t, "the laptop has the Next's secret", func() bool {
		m, err := laptop.do(t, control.Header{Op: control.OpPaste}, "")
		return err == nil && string(m.Payload) == "hunter2" && m.Kind == control.KindSecret
	})
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "to the `Next` £\nαβγδ"); err != nil {
		t.Fatal(err)
	}
	want := []byte("to the ?Next? \x60\r????")
	waitFor(t, "the lite member has the laptop text for the Next", func() bool { return strings.HasPrefix(lite.paste(t), "to the") })
	zxOut, err := exec.Command(bin, "-socket", lite.socket, "next", "paste").Output()
	if wantOut := fmt.Sprintf("CBB1 %d %08x\r%s\rCBBOK\r", len(want), crc32.ChecksumIEEE(want), want); err != nil || string(zxOut) != wantOut {
		t.Fatalf("cbb next paste: %v; %q, want %q", err, zxOut, wantOut)
	}

	// Every member lists it as a lite device, not an admin.
	for _, s := range []*testService{pi, laptop, lite} {
		waitFor(t, s.name+" lists the lite member", func() bool {
			for _, d := range s.devices(t) {
				if d.ID == st.Device {
					return d.Role == group.RoleLite && !d.Admin && d.Name == "lite"
				}
			}
			return false
		})
	}

	// The lite member dials a Mac as it dials every full member; with the
	// other computers off the two still sync.
	publishLite(&h, st.Device, st.Group, port)
	waitFor(t, "the Mac connected to all three", func() bool { return len(mac.status(t).Peers) == 3 })
	pi.stop()
	laptop.stop()
	waitFor(t, "the Mac and the lite member alone", func() bool {
		return len(mac.status(t).Peers) == 1 && len(lite.status(t).Peers) == 1
	})
	if _, err := mac.do(t, control.Header{Op: control.OpCopy}, "from the Mac"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member has the Mac text", func() bool { return lite.paste(t) == "from the Mac" })
	if _, err := lite.do(t, control.Header{Op: control.OpCopy}, "back from the lite member"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Mac has the lite text", func() bool { return mac.paste(t) == "back from the lite member" })
}

// TestLiteMemberAway: once sync away from home is on, the lite member
// offers its tunnel key to the group's hub at home and keeps the hub's
// offer; away from home it reaches the hub only through the WireGuard
// tunnel (GotaTun and smoltcp in the lite member, the Go hub's netstack),
// and syncs there.
func TestLiteMemberAway(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinLite(t, bin, pi)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	piID := pi.status(t).Device

	// At home: off until the user agrees, then the hub's offer comes.
	pa, _ := pi.addrs()
	home := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pa)
	waitFor(t, "the lite member at home", func() bool {
		st, err := home.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(st.Status.Peers) == 1
	})
	if a := home.status(t).Away; a != nil {
		t.Fatalf("sync away from home is on before it was turned on: %+v", a)
	}
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on"}, ""); err == nil || !strings.Contains(err.Error(), "consent") {
		t.Errorf("turning it on without consent: %v", err)
	}
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member keeps the hub's offer", func() bool {
		a := home.status(t).Away
		return a != nil && a.HubDevice == piID && !a.Through
	})
	home.stop()

	// Away: no address of the hub but its tunnel's.
	away := startLite(t, bin, dir, "-no-mdns", "-no-listen")
	waitUpTo(t, 30*time.Second, "the lite member reaches the hub through the tunnel", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through && len(m.Status.Peers) == 1
	})
	if _, err := away.do(t, control.Header{Op: control.OpCopy}, "from the lite member, away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub has it", func() bool { return pi.paste(t) == "from the lite member, away" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the lite member, away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member has it", func() bool { return away.paste(t) == "to the lite member, away" })

	// Off: the key is gone, and so is the connection through the tunnel.
	if _, err := away.do(t, control.Header{Op: control.OpAway, Name: "off"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tunnel.json")); !os.IsNotExist(err) {
		t.Errorf("tunnel.json after cbb global off: %v", err)
	}
	waitFor(t, "the lite member syncs at home only", func() bool {
		st := away.status(t)
		return st.Away == nil && len(st.Peers) == 0
	})
}
