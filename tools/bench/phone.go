// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The phone suite (docs/testbench.md, "The phone on an emulator"): the
// Android app on an emulator in a group with members of the fleet. The
// emulator runs already (adb sees it); the suite starts a member in a
// container with its member port published on this computer's loopback,
// which the emulator reaches as 10.0.2.2, and a helper on the loopback
// through which the app's instrumented tests (apps/android/app/src/androidTest)
// drive the fleet: run cbb on a member, copy there, wait for a text, add
// another member. Then it runs the tests with Gradle and records each
// test's result as a case.

// emulatorHost is this computer's loopback as the Android emulator sees it.
const emulatorHost = "10.0.2.2"

// phoneTask is the Gradle task that runs the instrumented tests on the
// emulator, from apps/android.
var phoneTask = ":app:connectedFullDebugAndroidTest"

// Phone runs the phone suite with the static Linux cbb under test and the
// Android project in android (apps/android).
func Phone(ctx context.Context, r *Report, cbb, android string, timeout time.Duration) {
	f, err := NewFleet(ctx, cbb)
	if err != nil {
		r.Do("phone/fleet", func() error { return err })
		return
	}
	defer f.Close(ctx)
	h := &phoneHelper{f: f, timeout: timeout, jobs: map[string]*phoneJob{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.Do("phone/helper", func() error { return err })
		return
	}
	defer ln.Close()
	go h.serve(ctx, ln)
	if r.Do("phone/member", func() error {
		_, err := h.add(ctx)
		return err
	}) != nil {
		return
	}
	port := ln.Addr().(*net.TCPAddr).Port
	results := filepath.Join(android, "app", "build", "outputs", "androidTest-results", "connected")
	os.RemoveAll(results)
	var out strings.Builder
	runErr := r.Do("phone/gradle", func() error {
		c := exec.CommandContext(ctx, "./gradlew", "--no-daemon", phoneTask,
			fmt.Sprintf("-Pandroid.testInstrumentationRunnerArguments.helper=%s:%d", emulatorHost, port))
		c.Dir = android
		c.Stdout = io.MultiWriter(&out, r.out)
		c.Stderr = c.Stdout
		if err := c.Run(); err != nil {
			return &RunError{Device: "controller", Cmd: phoneTask, Err: err, Output: tail(out.String(), 60)}
		}
		return nil
	})
	n, err := phoneResults(r, results)
	if err != nil || n == 0 && runErr == nil {
		r.Do("phone/results", func() error {
			if err == nil {
				err = errors.New("no instrumented test ran")
			}
			return err
		})
	}
}

// tail is the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// phoneResults records every test case of the JUnit files under dir as a
// case named phone/Class/test, and returns how many there were.
func phoneResults(r *Report, dir string) (int, error) {
	type testcase struct {
		Class   string `xml:"classname,attr"`
		Name    string `xml:"name,attr"`
		Time    string `xml:"time,attr"`
		Failure *struct {
			Message string `xml:"message,attr"`
			Text    string `xml:",chardata"`
		} `xml:"failure"`
		Skipped *struct{} `xml:"skipped"`
	}
	type suite struct {
		Cases []testcase `xml:"testcase"`
	}
	n := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".xml") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var s suite
		if err := xml.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, c := range s.Cases {
			n++
			class := c.Class[strings.LastIndex(c.Class, ".")+1:]
			name := "phone/" + class + "/" + c.Name
			var d time.Duration
			if secs, err := time.ParseDuration(c.Time + "s"); err == nil {
				d = secs
			}
			switch {
			case c.Skipped != nil:
				r.add(Case{Name: name, Skipped: "skipped on the emulator", Duration: d})
			case c.Failure != nil:
				msg := strings.TrimSpace(c.Failure.Message)
				if msg == "" {
					msg = strings.SplitN(strings.TrimSpace(c.Failure.Text), "\n", 2)[0]
				}
				r.add(Case{Name: name, Failure: msg, Details: c.Failure.Text, Duration: d})
			default:
				r.add(Case{Name: name, Duration: d})
			}
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return n, err
}

// phoneHelper answers the instrumented tests: one JSON request a line, one
// JSON answer a line, on a connection of their own. It listens only on the
// loopback, and only runs commands in the run's own containers.
type phoneHelper struct {
	f       *Fleet
	timeout time.Duration

	mu      sync.Mutex
	members []*Device
	addrs   map[string]string // a member's port as the emulator dials it
	jobs    map[string]*phoneJob
	nextJob int
}

// phoneRequest is what a test asks: op is add, run, copy, arrives, start,
// output or stop.
type phoneRequest struct {
	Op      string `json:"op"`
	Dev     string `json:"dev,omitempty"`
	Cmd     string `json:"cmd,omitempty"`
	Text    string `json:"text,omitempty"`
	ID      string `json:"id,omitempty"`
	Seconds int    `json:"seconds,omitempty"`
}

type phoneAnswer struct {
	Dev   string `json:"dev,omitempty"`
	Addr  string `json:"addr,omitempty"`
	Out   string `json:"out,omitempty"`
	ID    string `json:"id,omitempty"`
	Done  bool   `json:"done,omitempty"`
	Error string `json:"error,omitempty"`
}

// phoneJob is a command that runs on while the test goes on, such as
// cbb pair, which waits for the phone.
type phoneJob struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	out  strings.Builder
	done bool
}

func (j *phoneJob) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.out.Write(p)
}

func (h *phoneHelper) serve(ctx context.Context, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go h.conn(ctx, c)
	}
}

func (h *phoneHelper) conn(ctx context.Context, c net.Conn) {
	defer c.Close()
	in := bufio.NewScanner(c)
	in.Buffer(make([]byte, 64<<10), 4<<20)
	enc := json.NewEncoder(c)
	for in.Scan() {
		var req phoneRequest
		a := phoneAnswer{}
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			a.Error = err.Error()
		} else if err := h.do(ctx, req, &a); err != nil {
			a.Error = err.Error()
			var re interface{ Details() string }
			if errors.As(err, &re) {
				a.Out = re.Details()
			}
		}
		if enc.Encode(a) != nil {
			return
		}
	}
}

// member is the run's member named name.
func (h *phoneHelper) member(name string) (*Device, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, d := range h.members {
		if d.Name == name {
			return d, nil
		}
	}
	return nil, fmt.Errorf("no member named %q in this run", name)
}

// add starts a member in no group with its member port on the loopback.
func (h *phoneHelper) add(ctx context.Context) (*Device, error) {
	d, err := h.f.AddWith(ctx, h.f.net, []string{"-p", "127.0.0.1::8764"})
	if err != nil {
		return nil, err
	}
	out, err := docker(ctx, "port", d.Container, "8764/tcp")
	if err != nil {
		return nil, err
	}
	first := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	_, port, err := net.SplitHostPort(first)
	if err != nil {
		return nil, fmt.Errorf("docker port %s gave %q: %w", d.Container, out, err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.addrs == nil {
		h.addrs = map[string]string{}
	}
	h.members = append(h.members, d)
	h.addrs[d.Name] = net.JoinHostPort(emulatorHost, port)
	return d, nil
}

func (h *phoneHelper) do(ctx context.Context, req phoneRequest, a *phoneAnswer) error {
	timeout := h.timeout
	if req.Seconds > 0 {
		timeout = time.Duration(req.Seconds) * time.Second
	}
	switch req.Op {
	case "add":
		d, err := h.add(ctx)
		if err != nil {
			return err
		}
		a.Dev = d.Name
		h.mu.Lock()
		a.Addr = h.addrs[d.Name]
		h.mu.Unlock()
		return nil
	case "start", "output", "stop":
		return h.job(req, a)
	}
	d, err := h.member(req.Dev)
	if err != nil {
		return err
	}
	switch req.Op {
	case "addr":
		h.mu.Lock()
		a.Addr = h.addrs[d.Name]
		h.mu.Unlock()
		return nil
	case "run":
		a.Out, err = RunFor(ctx, d, req.Cmd, req.Text, timeout)
		return err
	case "copy":
		return Copy(ctx, d, req.Text)
	case "arrives":
		return arrives(ctx, d, req.Text, timeout)
	}
	return fmt.Errorf("no op %q", req.Op)
}

// job starts a command on a member that runs on, reads what it printed so
// far, or stops it.
func (h *phoneHelper) job(req phoneRequest, a *phoneAnswer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch req.Op {
	case "start":
		var d *Device
		for _, m := range h.members {
			if m.Name == req.Dev {
				d = m
			}
		}
		if d == nil {
			return fmt.Errorf("no member named %q in this run", req.Dev)
		}
		h.nextJob++
		id := fmt.Sprint(h.nextJob)
		j := &phoneJob{cmd: exec.Command("docker", "exec", "-i", d.Container, "sh", "-c", req.Cmd)}
		j.cmd.Stdout, j.cmd.Stderr = j, j
		if err := j.cmd.Start(); err != nil {
			return err
		}
		go func() {
			j.cmd.Wait()
			j.mu.Lock()
			j.done = true
			j.mu.Unlock()
		}()
		h.jobs[id] = j
		a.ID = id
		return nil
	}
	j := h.jobs[req.ID]
	if j == nil {
		return fmt.Errorf("no job %q", req.ID)
	}
	if req.Op == "stop" && j.cmd.Process != nil {
		j.cmd.Process.Kill()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	a.Out, a.Done = j.out.String(), j.done
	return nil
}
