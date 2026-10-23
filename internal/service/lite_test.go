// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// startLite runs cbb-lite (the Rust lite member, lite/) with the state in
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
			t.Fatalf("cbb-lite ended at the start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the control socket of cbb-lite never appeared")
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

// TestLiteMember runs the lite member among Go members: it joins through
// the phone by its QR code, gets no CA keys, is listed as a lite device and
// syncs both ways. CBB_LITE names the cbb-lite binary (cargo build in lite/).
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

	// cbb-lite join listens and shows its QR code; the phone scans it and
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
		t.Fatal("cbb-lite join showed no QR code")
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
		t.Fatalf("cbb-lite join: %v; %s", err, rest.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "_key") {
		t.Error("the lite member saved a CA key")
	}

	// The lite member dials both computers and syncs with them.
	pa, _ := pi.addrs()
	la, _ := laptop.addrs()
	lite := startLite(t, bin, dir, "-no-mdns", "-peer", pa, "-peer", la)
	st := lite.status(t)
	if st.Group != pi.status(t).Group || st.Role != "lite" {
		t.Fatalf("lite status %+v, want the group %s", st, pi.status(t).Group)
	}
	waitFor(t, "the lite member connected", func() bool { return len(lite.status(t).Peers) == 2 })
	if _, err := lite.do(t, control.Header{Op: control.OpCopy}, "from the lite member"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{pi, laptop} {
		waitFor(t, s.name+" has the lite text", func() bool { return s.paste(t) == "from the lite member" })
	}
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "from the laptop"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member has the laptop text", func() bool { return lite.paste(t) == "from the laptop" })

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
}
