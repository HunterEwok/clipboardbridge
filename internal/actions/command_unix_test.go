// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build unix

package actions

import (
	"context"
	"strings"
	"testing"
)

// TestRunCommand: the exit status comes back, and nothing else.
func TestRunCommand(t *testing.T) {
	sh := "/bin/sh"
	if err := RunCommand(context.Background(), []string{sh, "-c", "exit 0"}); err != nil {
		t.Errorf("exit 0: %v", err)
	}
	if err := RunCommand(context.Background(), []string{sh, "-c", "echo out; exit 3"}); err == nil || err.Error() != "exit status 3" {
		t.Errorf("exit 3: %v", err)
	}
	if err := RunCommand(context.Background(), []string{"/nonexistent/program"}); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("a missing program: %v", err)
	}
}

func TestCheckOwn(t *testing.T) {
	for _, c := range []struct {
		name    string
		command []string
		ok      bool
	}{
		{"backup", []string{"/usr/bin/backup"}, true},
		{"reboot", []string{"/sbin/reboot"}, false},
		{"backup", []string{"backup"}, false},
		{"backup", nil, false},
		{"-backup", []string{"/usr/bin/backup"}, false},
	} {
		if err := CheckOwn(c.name, c.command); (err == nil) != c.ok {
			t.Errorf("%s %v: %v", c.name, c.command, err)
		}
	}
}
