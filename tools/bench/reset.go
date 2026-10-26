// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// macHelper is the root helper that tools/bench/setup-mac.sh installs on a
// Mac, the one program there besides cbb that the bench runs with sudo.
const macHelper = "/usr/local/libexec/cbbbench/cbbbench-root"

// stateBase is where the bench keeps the builds it copied to a device, one
// directory per archive's checksum, so that a second reset with the same
// build copies nothing.
const stateBase = "$HOME/.cache/cbbbench"

// Build is the build under test: the release archives in a directory, as
// the release workflow and CI make them (packaging/archive.sh,
// lite/packaging/archive.sh), checked against its SHA256SUMS.
type Build struct {
	dir    string
	sums   map[string]string // archive name to its SHA-256
	signed bool              // SHA256SUMS.sig is there, for a Mac's helper
}

// LoadBuild reads the archives of dir and checks each one that SHA256SUMS
// names.
func LoadBuild(dir string) (*Build, error) {
	b := &Build{dir: dir, sums: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read the build: %w", err)
	}
	want := map[string]string{}
	if f, err := os.Open(filepath.Join(dir, "SHA256SUMS")); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			if sum, name, ok := strings.Cut(strings.TrimSpace(s.Text()), "  "); ok {
				want[strings.TrimPrefix(name, "*")] = sum
			}
		}
		f.Close()
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		sum, err := fileSum(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if w, ok := want[e.Name()]; ok && w != sum {
			return nil, fmt.Errorf("%s does not match SHA256SUMS", e.Name())
		}
		b.sums[e.Name()] = sum
	}
	if len(b.sums) == 0 {
		return nil, fmt.Errorf("the build %s has no .tar.gz archives", dir)
	}
	_, err = os.Stat(filepath.Join(dir, "SHA256SUMS.sig"))
	b.signed = err == nil
	return b, nil
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// archiveFor names the archive a device installs, for the CPU uname -m
// reports.
func archiveFor(d *Device, machine string) (string, error) {
	arch := map[string]string{"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "armv7", "armv6l": "armv6"}[machine]
	if arch == "" {
		return "", fmt.Errorf("%s: no build for the CPU %q", d.Name, machine)
	}
	switch d.OS {
	case "linux", "docker":
		return "clipboardbridge-linux-" + arch + ".tar.gz", nil
	case "linux-lite":
		return "clipboardbridge-lite-linux-" + arch + ".tar.gz", nil
	case "darwin":
		return "clipboardbridge-darwin-" + arch + ".tar.gz", nil
	}
	return "", fmt.Errorf("%s: the bench does not reset os %s yet", d.Name, d.OS)
}

// Reset (R1) puts every device in no group with the build under test, all
// at once: the archive goes to each device once per build, the old install
// is removed with its keys, the new one installed, and the bench waits until
// the service answers in no group. With quick and no build, each device
// keeps its install and only loses its state: the same build, a clean
// group, without checking the installer again.
func Reset(ctx context.Context, r *Report, devices []*Device, b *Build, quick bool) {
	if b == nil && !quick {
		r.Do("reset/setup", func() error { return errors.New("reset needs -build DIR with the release archives, or -quick") })
		return
	}
	var wg sync.WaitGroup
	for _, d := range devices {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.Do("reset/"+d.Name, func() error { return resetDevice(ctx, r, d, b, quick) }) != nil {
				return
			}
			r.Do("reset/"+d.Name+"/no-group", func() error {
				return eventually(ctx, 30*time.Second, func() error {
					tag, err := groupOf(ctx, d)
					if err == nil && tag != "" {
						err = fmt.Errorf("%s is still in group %s", d.Name, tag)
					}
					return err
				})
			})
		}()
	}
	wg.Wait()
}

func resetDevice(ctx context.Context, r *Report, d *Device, b *Build, quick bool) error {
	switch d.OS {
	case "linux", "linux-lite":
		if quick {
			_, err := Run(ctx, d, "sudo -n sh -c 'systemctl stop clipboardbridge && rm -rf /var/lib/clipboardbridge/* /etc/systemd/system/clipboardbridge.service.d && systemctl daemon-reload && systemctl start clipboardbridge'", "")
			if err != nil {
				return noSudo(d, err)
			}
			return nil
		}
		if d.Firewall != "yes" && d.Firewall != "no" {
			return fmt.Errorf("%s: set firewall = \"yes\" (the installer opens the member port) or \"no\" (it leaves the firewall alone) in the inventory", d.Name)
		}
		dir, err := stage(ctx, d, b)
		if err != nil {
			return err
		}
		if _, err := RunFor(ctx, d, "[ ! -f /usr/local/share/clipboardbridge/uninstall.sh ] || sudo -n sh /usr/local/share/clipboardbridge/uninstall.sh --purge", "", 2*time.Minute); err != nil {
			return noSudo(d, err)
		}
		r.Do("reset/"+d.Name+"/L10-clean", func() error { return uninstalled(ctx, d) })
		opt := "--express"
		if d.Firewall == "no" {
			opt = "--no-firewall"
		}
		if _, err := RunFor(ctx, d, "sudo -n env CBB_FIREWALL= sh "+dir+"/packaging/linux/install.sh "+opt+" "+dir+"/cbb", "", 2*time.Minute); err != nil {
			return err
		}
		return agentRuns(ctx, r, d)
	case "darwin":
		// Only the helper runs as root here; it installs only an archive
		// whose checksum is signed by the bench's key or trusted (setup-mac.sh).
		dir, err := stage(ctx, d, b)
		if err != nil {
			return err
		}
		install := macHelper + " install " + dir + "/archive.tar.gz"
		if b.signed {
			// The build's sums and their signature by the bench's key, so
			// a new build needs no password on the Mac.
			for _, f := range []string{"SHA256SUMS", "SHA256SUMS.sig"} {
				data, err := os.ReadFile(filepath.Join(b.dir, f))
				if err != nil {
					return err
				}
				if _, err := Run(ctx, d, "cat > "+dir+"/"+f, string(data)); err != nil {
					return err
				}
			}
			install += " " + dir + "/SHA256SUMS " + dir + "/SHA256SUMS.sig"
		}
		if _, err := RunFor(ctx, d, "sudo -n "+macHelper+" purge && sudo -n "+install, "", 2*time.Minute); err != nil {
			return noSudo(d, err)
		}
		return nil
	case "docker":
		if quick {
			out, err := Run(ctx, d, "docker inspect -f '"+composeLabels+"' "+d.Container, "")
			if err != nil {
				return err
			}
			compose := composeCmd(strings.TrimSpace(out))
			if compose == "" {
				return errors.New("docker compose did not start the container")
			}
			// The volume goes with the container, and with it the state.
			_, err = RunFor(ctx, d, compose+" down -v && "+compose+" up -d", "", 2*time.Minute)
			return err
		}
		if d.Setup == "" {
			return fmt.Errorf("%s: set setup to the path of tools/bench/setup-docker.sh on its host in the inventory", d.Name)
		}
		dir, err := stage(ctx, d, b)
		if err != nil {
			return err
		}
		_, err = RunFor(ctx, d, "sh "+d.Setup+" up "+dir+"/cbb", "", 5*time.Minute)
		return err
	}
	return Skipped("the bench does not reset os " + d.OS + " yet; reset it by hand (docs/testbench-cases.md, R1)")
}

// stage copies the device's archive of the build to it, unless it is
// there from an earlier reset, and returns the directory that holds cbb
// and packaging/ (on a Mac, archive.tar.gz for the helper).
func stage(ctx context.Context, d *Device, b *Build) (string, error) {
	out, err := Run(ctx, d, "uname -m", "")
	if err != nil {
		return "", err
	}
	name, err := archiveFor(d, strings.TrimSpace(out))
	if err != nil {
		return "", err
	}
	sum, ok := b.sums[name]
	if !ok {
		return "", fmt.Errorf("the build has no %s for %s", name, d.Name)
	}
	dir := stateBase + "/" + sum[:16]
	unpack := "tar -xzf - -C " + dir
	if d.OS == "darwin" {
		unpack = "cat > " + dir + "/archive.tar.gz"
	}
	if _, err := Run(ctx, d, "test -f "+dir+"/ok", ""); err != nil {
		data, err := os.ReadFile(filepath.Join(b.dir, name))
		if err != nil {
			return "", err
		}
		// Keep the newest three builds on the device.
		cmd := "mkdir -p " + dir + " && " + unpack + " && touch " + dir + "/ok && cd " + stateBase + " && ls -1t | tail -n +4 | xargs rm -rf"
		if _, err := RunFor(ctx, d, cmd, string(data), 10*time.Minute); err != nil {
			return "", err
		}
	}
	if d.OS == "darwin" {
		return dir, nil
	}
	// The archive holds one directory, clipboardbridge or
	// clipboardbridge-lite.
	out, err = Run(ctx, d, "ls -d "+dir+"/*/", "")
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSpace(firstLine(out)), "/"), nil
}

// uninstalled (L10) checks that uninstall.sh --purge left nothing behind.
func uninstalled(ctx context.Context, d *Device) error {
	out, err := Run(ctx, d, "ls -d /var/lib/clipboardbridge /etc/clipboardbridge /usr/local/bin/cbb /usr/local/share/clipboardbridge /etc/systemd/system/clipboardbridge.service /etc/systemd/system/clipboardbridge.service.d /etc/xdg/autostart/clipboardbridge-desktop.desktop 2>/dev/null; sudo -n ufw status 2>/dev/null | grep -i clipboardbridge; true", "")
	if err != nil {
		return err
	}
	if left := strings.TrimSpace(out); left != "" {
		return fmt.Errorf("uninstall --purge left %s", strings.ReplaceAll(left, "\n", ", "))
	}
	return nil
}

// agentRuns checks that the installer started the desktop agent in the
// signed-in session, so that nobody has to sign out and in after an install;
// when it did not, the case fails and the bench starts the agent itself, so
// the run can go on.
func agentRuns(ctx context.Context, r *Report, d *Device) error {
	if d.OS != "linux" || (d.Clipboard != "x11" && d.Clipboard != "wayland") {
		return nil
	}
	if r.Do("reset/"+d.Name+"/agent", func() error {
		return eventually(ctx, 10*time.Second, func() error {
			_, err := Run(ctx, d, `pgrep -x -u "$(id -u)" cbb >/dev/null`, "")
			if err != nil {
				return errors.New("the installer did not start the desktop agent in the signed-in session")
			}
			return nil
		})
	}) == nil {
		return nil
	}
	return restartAgent(ctx, d)
}

// restartAgent starts the desktop agent in the signed-in session. The SSH
// session has the clipboardbridge group that the installer gave the user.
func restartAgent(ctx context.Context, d *Device) error {
	_, err := Run(ctx, d, `id -nG | grep -qw clipboardbridge || { echo "the user is not in the clipboardbridge group; sign in again" >&2; exit 1; }
pkill -x -u "$(id -u)" cbb; sleep 0.5
env=$(systemctl --user show-environment | grep -E '^(DISPLAY|WAYLAND_DISPLAY|XDG_RUNTIME_DIR|DBUS_SESSION_BUS_ADDRESS|XAUTHORITY|XDG_SESSION_TYPE|XDG_CURRENT_DESKTOP)=')
echo "$env" | grep -q '^DISPLAY=\|^WAYLAND_DISPLAY=' || { echo "nobody is signed in on the desktop" >&2; exit 1; }
env $env setsid -f /usr/local/bin/cbb agent </dev/null >/dev/null 2>&1
sleep 1; pgrep -x -u "$(id -u)" cbb >/dev/null || { echo "the agent did not start" >&2; exit 1; }`, "")
	return err
}
