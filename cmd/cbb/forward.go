// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/forward"
)

// cmdForward runs a forwarder: a server that holds no keys and passes the
// encrypted WireGuard packets of hubs that their clients cannot reach
// directly (docs/design.md, "The forwarder"). It runs in the foreground, for
// systemd or a terminal.
func cmdForward(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("forward", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8764", "the address to listen on, UDP and TCP")
	keyFile := fs.String("key", defaultForwarderKey(), "the forwarder's key, made on the first run")
	showKey := fs.Bool("show-key", false, "print the key for cbb away hub -forwarder-key and stop")
	vlessSite := fs.String("vless-site", "", "take VLESS with REALITY too, borrowing the TLS of this well-known site, such as www.example.com")
	vlessListen := fs.String("vless-listen", ":443", "the TCP address to listen on for VLESS")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "cbb: forward takes only flags")
		return 2
	}
	cert, err := forward.LoadCert(*keyFile)
	if err != nil {
		return fail(stderr, err)
	}
	pin := forward.Pin(cert.Leaf)
	if *showKey {
		fmt.Fprintln(stdout, pin)
		return 0
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	cfg := forward.Config{Listen: *listen, Cert: cert, Logf: logf}
	if *vlessSite != "" {
		key, err := forward.LoadRealityKey(*keyFile)
		if err != nil {
			return fail(stderr, err)
		}
		cfg.VLESS = &forward.VLESSConfig{Listen: *vlessListen, Site: *vlessSite, Key: key}
	}
	f, err := forward.Listen(cfg)
	if err != nil {
		return fail(stderr, err)
	}
	logf("cbb forward: listening on UDP and TCP port %d; its key, for cbb away hub -forwarder-key: %s", f.Addr().Port(), pin)
	if cfg.VLESS != nil {
		logf("cbb forward: VLESS on TCP %s, with the TLS of %s; hubs ask for it with cbb away hub -vless", *vlessListen, *vlessSite)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Getenv("CBB_DEBUG") == "1" {
		// Counts only: the forwarder logs nothing about a group or a device.
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					st := f.Stats()
					logf("cbb forward: %d hubs, %d sessions, %d handshakes waiting", st.Groups, st.Sessions, st.Waiting)
				}
			}
		}()
	}
	if err := f.Serve(ctx); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// defaultForwarderKey is where the forwarder keeps its key: in systemd's
// state directory for it, or next to the service's state.
func defaultForwarderKey() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return filepath.Join(d, "forwarder.pem")
	}
	return filepath.Join(defaultStateDir(), "forwarder.pem")
}
