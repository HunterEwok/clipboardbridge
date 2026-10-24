// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// EnvFile is where the Linux installer keeps the settings it was given,
// such as CBB_PORT; systemd passes them to the service, and the
// command line reads them from here.
var EnvFile = "/etc/clipboardbridge/clipboardbridge.env"

// Port returns the member port, which a listening join uses too: a
// device that joins is in no group yet, so nothing else holds it.
// MemberPort, or N when CBB_PORT, from the environment or else from
// EnvFile, names a port N. The iPhone shortcut names MemberPort, so it
// works only with that one.
func Port() (int, error) {
	v, ok := os.LookupEnv("CBB_PORT")
	if !ok {
		var err error
		if v, err = envFileValue(EnvFile, "CBB_PORT"); err != nil {
			return 0, err
		}
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return MemberPort, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1024 || n > 65535 {
		return 0, fmt.Errorf("CBB_PORT=%q: want a port from 1024 to 65535", v)
	}
	return n, nil
}

// HomeCGNAT reports whether CBB_HOME_CGNAT, from the environment or else
// from EnvFile, counts the carrier-grade NAT range 100.64.0.0/10 as the
// home network: "1" does, "" or "0" does not. A home network on that range
// is rare, and the same range carries networks that are not home, so it
// is outside unless the installer was told otherwise (--home-cgnat on).
func HomeCGNAT() (bool, error) {
	v, ok := os.LookupEnv("CBB_HOME_CGNAT")
	if !ok {
		var err error
		if v, err = envFileValue(EnvFile, "CBB_HOME_CGNAT"); err != nil {
			return false, err
		}
	}
	switch strings.TrimSpace(v) {
	case "", "0":
		return false, nil
	case "1":
		return true, nil
	}
	return false, fmt.Errorf("CBB_HOME_CGNAT=%q: want 1 or 0", v)
}

// envFileValue returns key's value in a file of KEY=value lines, the
// format of systemd's EnvironmentFile, or "" if the file or the key is
// missing.
func envFileValue(path, key string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	value := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		value = v // the last one wins, as in systemd
	}
	return value, sc.Err()
}
