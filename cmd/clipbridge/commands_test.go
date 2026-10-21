// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/clipbridge/internal/control"
)

// fakeService answers every request on a control socket with answer and
// records the requests.
func fakeService(t *testing.T, answer control.Message) chan *control.Message {
	t.Helper()
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	t.Setenv("CLIPBRIDGE_SOCKET", socket)
	got := make(chan *control.Message, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			m, err := control.NewReader(c).Read()
			if err == nil {
				got <- m
				a := answer
				a.Op = control.OpReply
				control.Write(c, &a)
			}
			c.Close()
		}
	}()
	return got
}

func request(t *testing.T, got chan *control.Message) *control.Message {
	t.Helper()
	select {
	case m := <-got:
		return m
	default:
		t.Fatal("the command sent no request")
		return nil
	}
}

func TestCopy(t *testing.T) {
	got := fakeService(t, control.Message{Header: control.Header{Done: true}})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"copy", "-secret"}, strings.NewReader("hunter2"), &stdout, &stderr); code != 0 {
		t.Fatalf("copy -secret: %d, %s", code, stderr.String())
	}
	if m := request(t, got); m.Op != control.OpCopy || m.Kind != control.KindSecret || string(m.Payload) != "hunter2" {
		t.Errorf("copy -secret sent %+v %q", m.Header, m.Payload)
	}
	if code := run([]string{"copy"}, strings.NewReader("plain"), &stdout, &stderr); code != 0 {
		t.Fatalf("copy: %d", code)
	}
	if m := request(t, got); m.Kind != control.KindText {
		t.Errorf("copy sent kind %q", m.Kind)
	}
	stderr.Reset()
	if code := run([]string{"copy", "hello"}, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "standard input") {
		t.Errorf("copy with an argument: %d, %q", code, stderr.String())
	}
}

func TestJoin(t *testing.T) {
	got := fakeService(t, control.Message{Header: control.Header{Done: true}})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"join", "-code", "192.168.1.5:4000"}, strings.NewReader("123 456\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("join: %d, %s", code, stderr.String())
	}
	if m := request(t, got); m.Op != control.OpJoin || m.Code != "123456" || m.Address != "192.168.1.5:4000" {
		t.Errorf("join sent %+v", m.Header)
	}
	// The code is never taken from the command line.
	for _, args := range [][]string{{"join", "-code", "123456"}, {"join", "-code", "123", "456"}, {"join", "192.168.1.5:4000"}} {
		stderr.Reset()
		if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "usage") {
			t.Errorf("%v: %d, %q", args, code, stderr.String())
		}
	}
	// A bad code fails before the service is asked.
	stderr.Reset()
	if code := run([]string{"join", "-code"}, strings.NewReader("12345\n"), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "six digits") {
		t.Errorf("join with five digits: %d, %q", code, stderr.String())
	}
	select {
	case m := <-got:
		t.Errorf("a bad code reached the service: %+v", m.Header)
	default:
	}
}

func TestStatus(t *testing.T) {
	for _, tt := range []struct {
		st   control.Status
		want string
	}{
		{control.Status{Role: "linux"}, "Run clipbridge pair here to start one"},
		{control.Status{Role: "mac"}, "Run clipbridge pair on a Linux member"},
		{control.Status{Role: "linux", Device: "d1", Group: "g1", Holder: true, Peers: []control.Device{{ID: "p1", Role: "linux", SkewMS: 9000}}}, "off by 9s"},
	} {
		st := tt.st
		fakeService(t, control.Message{Header: control.Header{Status: &st, Done: true}})
		var stdout, stderr bytes.Buffer
		if code := run([]string{"status"}, strings.NewReader(""), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), tt.want) {
			t.Errorf("status of %+v: %d, %q", tt.st, code, stdout.String())
		}
	}
}

// brokenWriter fails every write, like a full disk.
type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

func TestPasteWriteError(t *testing.T) {
	fakeService(t, control.Message{Header: control.Header{Done: true}, Payload: []byte("text")})
	var stderr bytes.Buffer
	if code := run([]string{"paste"}, strings.NewReader(""), brokenWriter{}, &stderr); code != 1 || !strings.Contains(stderr.String(), "no space") {
		t.Errorf("paste to a full disk: %d, %q", code, stderr.String())
	}
}

func TestJoinWithThePhone(t *testing.T) {
	// By default join shows a QR code with its own code and asks the
	// service to wait for the window the phone opens.
	got := fakeService(t, control.Message{Header: control.Header{Done: true}})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"join"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("join: %d, %s", code, stderr.String())
	}
	m := request(t, got)
	if m.Op != control.OpJoin || len(m.Code) != 6 || m.Expires != 300 || m.Address != "" {
		t.Errorf("join sent %+v", m.Header)
	}
	if !strings.Contains(stdout.String(), "add a computer") || !strings.Contains(stdout.String(), "\x1b[") {
		t.Errorf("join printed:\n%s", stdout.String())
	}
}
