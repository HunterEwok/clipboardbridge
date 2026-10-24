// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
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
// dir; it is stopped at the end of the test.
func startLite(t *testing.T, bin, dir string, args ...string) *testService {
	t.Helper()
	s := &testService{name: "lite", dir: dir, socket: filepath.Join(dir, "c.sock")}
	cmd := exec.Command(bin, append([]string{"-state", dir, "-socket", s.socket, "-debug", "run"}, args...)...)
	cmd.Stdout, cmd.Stderr = testWriter{t, "lite: "}, testWriter{t, "lite: "}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-exited
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := control.Dial(s.socket); err == nil {
			c.Close()
			return s
		}
		select {
		case err := <-exited:
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
	admit, token := shortcutPhone(t, pi)

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
	if rep := admit(token, qr); rep["direction"] != "none" {
		t.Fatalf("admit: %v", rep)
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
	waitFor(t, "pi lists the board", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "board" {
				return d.Role == group.RoleLite && !d.Admin
			}
		}
		return false
	})
}

// TestLiteMember runs the lite member among Go members: it joins through
// the phone by its QR code, gets no CA keys, is listed as a lite device and
// syncs both ways. CBB_LITE names the lite member's binary (cargo build in lite/).
func TestLiteMember(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	admit, token := shortcutPhone(t, pi)
	laptop := startService(t, &h, "laptop")
	pairWith(t, pi, laptop)

	// cbb join on the lite member listens and shows its QR code; the phone scans it and
	// asks pi to admit the device.
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "-debug", "join", "-name", "lite", "-port", "0", "-addr", "127.0.0.1")
	join.Stderr = testWriter{t, "lite join: "}
	out, err := join.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := join.Start(); err != nil {
		t.Fatal(err)
	}
	const prefix = "Or paste this into the app: "
	var qr string
	sc := bufio.NewScanner(out)
	for qr == "" && sc.Scan() {
		if line, ok := strings.CutPrefix(sc.Text(), prefix); ok {
			qr = line
		}
	}
	if qr == "" {
		join.Process.Kill()
		join.Wait()
		t.Fatal("cbb join showed no QR code")
	}
	if rep := admit(token, qr); rep["direction"] != "none" {
		join.Process.Kill()
		join.Wait()
		t.Fatalf("admit: %v", rep)
	}
	var rest strings.Builder
	for sc.Scan() {
		rest.WriteString(sc.Text() + "\n")
	}
	if err := join.Wait(); err != nil || !strings.Contains(rest.String(), "Joined the group") {
		t.Fatalf("cbb join: %v; %s", err, rest.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "_key") {
		t.Error("the lite member saved a CA key")
	}

	// The lite member dials the computers, a Mac too, and syncs with them.
	mac := startRole(t, &h, "mac", group.OSMacOS)
	pairWith(t, pi, mac)
	pa, _ := pi.addrs()
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
