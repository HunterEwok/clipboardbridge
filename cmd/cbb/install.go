// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// cmdInstall runs the installer that came with this copy of cbb, for a copy
// that a package manager unpacked without installing the service: winget
// puts the release's zip in its own folder and only cbb.exe on PATH
// (packaging/winget). The arguments go to install.ps1 as they are.
func cmdInstall(args []string, stdout, stderr io.Writer) int {
	if runtime.GOOS != "windows" {
		fmt.Fprintln(stderr, "cbb: cbb install is for Windows; on Linux and macOS run packaging/<os>/install.sh from the release archive, or use Homebrew")
		return 2
	}
	script, err := installScript()
	if err != nil {
		return fail(stderr, err)
	}
	cmd := exec.Command("powershell.exe", append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		return fail(stderr, fmt.Errorf("running %s: %w", script, err))
	}
	return 0
}

// installScript finds packaging\windows\install.ps1 beside the program,
// following the link that winget puts on PATH.
func installScript() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	script := filepath.Join(filepath.Dir(exe), "packaging", "windows", "install.ps1")
	if _, err := os.Stat(script); err != nil {
		return "", fmt.Errorf("this copy of cbb has no installer beside it (%s); install from the release's zip: %w", script, err)
	}
	return script, nil
}
