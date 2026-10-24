// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// TestSwiftMemberTLS runs the phone app's member code against this node
// over real TLS: clipboardbridge-interop (apps/ios/ClipboardBridgeKit), named by
// CBB_SWIFT_INTEROP_TLS on macOS, makes a key in the keychain, gets
// a member certificate for it, dials, sends a text, and waits for one.
func TestSwiftMemberTLS(t *testing.T) {
	tool := os.Getenv("CBB_SWIFT_INTEROP_TLS")
	if tool == "" {
		t.Skip("CBB_SWIFT_INTEROP_TLS names no clipboardbridge-interop binary")
	}
	server := newMember(t, Full)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, "member-tls", "127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), string(server.id.ID))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errOut strings.Builder
	cmd.Stderr = &errOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	lines := bufio.NewScanner(stdout)
	fail := func(format string, args ...any) {
		t.Helper()
		cmd.Process.Kill()
		t.Fatalf("%s; the tool said: %s", fmt.Sprintf(format, args...), errOut.String())
	}

	// The tool's key, and a certificate for it.
	if !lines.Scan() || !strings.HasPrefix(lines.Text(), "key ") {
		fail("no key line")
	}
	spki, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(lines.Text(), "key "))
	if err != nil {
		fail("the key: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		fail("the key: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		fail("the key is not ECDSA")
	}
	phoneID := group.NewDeviceID()
	cert, err := admin.GroupCA.IssueMember(phoneID, ecPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(stdin, "cert %s\nca %s\n", base64.StdEncoding.EncodeToString(cert.Raw), base64.StdEncoding.EncodeToString(admin.GroupCA.Cert.Raw))

	ln.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
	raw, err := ln.Accept()
	if err != nil {
		fail("the tool did not connect: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(context.Background(), tls.Server(raw, server.ServerTLS())) }()

	waitWrite(t, server, "from swift")
	if p := server.Peers(); len(p) != 1 || p[0].ID != phoneID || p[0].Role != Phone || (p[0].Name != "iPhone" && p[0].Name != "Android") {
		fail("peers %+v, want the phone", p)
	}
	if err := server.Send("from go", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	if !lines.Scan() || lines.Text() != "ok" {
		fail("the tool did not get the text (%q)", lines.Text())
	}
	if err := wait(t, served, "the connection to end"); err != nil {
		t.Errorf("the connection ended with %v, want a goodbye", err)
	}
}
