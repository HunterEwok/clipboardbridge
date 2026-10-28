// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
)

const deniedText = "No permission to use the service: add your user to the clipboardbridge group and log in again."

// runAdmin runs cbb through pkexec, which asks for the password in the
// desktop's own dialog; pkexec passes the arguments as they are, without a
// shell, and clears the environment, so CBB_DEBUG goes through env.
func runAdmin(args []string, yes, details bool) error {
	pkexec, err := exec.LookPath("pkexec")
	if err != nil {
		return &adminError{msg: "pkexec is not installed: run sudo cbb " + strings.Join(args, " ") + " in a terminal instead.", detail: err.Error()}
	}
	cmd := exec.Command(pkexec, pkexecArgs(cbbPath(), args, details)...)
	if yes {
		cmd.Stdin = strings.NewReader("yes\n")
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &exit) && exit.ExitCode() == 126:
		// pkexec: the user dismissed the dialog.
		return errCancelled
	case errors.As(err, &exit) && exit.ExitCode() == 127 && out.Len() == 0:
		return &adminError{msg: "Not authorized to run cbb as the administrator.", detail: err.Error()}
	}
	return cbbFailed(out.String(), err.Error())
}

func pkexecArgs(cbb string, args []string, details bool) []string {
	var a []string
	if details {
		a = append(a, "/usr/bin/env", "CBB_DEBUG=1")
	}
	return append(append(a, cbb), args...)
}

// cbbPath is where the installer puts cbb (/opt/clipboardbridge on
// SteamOS), or else cbb on PATH; pkexec needs the full path.
func cbbPath() string {
	for _, p := range []string{"/usr/local/bin/cbb", "/opt/clipboardbridge/bin/cbb"} {
		if p, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("cbb"); err == nil {
		return p
	}
	return "/usr/local/bin/cbb"
}
