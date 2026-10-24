// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/tls"
	"strings"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/forward"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// registerForwarderLocked keeps the running hub registered with its
// forwarder, if it has one, until ctx is done: the clients that cannot
// reach the hub directly come through the forwarder (docs/design.md, "The
// forwarder").
func (s *Service) registerForwarderLocked(ctx context.Context, h *tunnel.Hub, st *tunnel.State) {
	fw := st.Forwarder
	if fw == nil {
		s.tunFwd = nil
		return
	}
	s.tunFwd = &control.Forwarder{Endpoint: fw.Endpoint.String()}
	cfg := forward.HubConfig{
		Link:        forward.Link{Endpoint: fw.Endpoint, Pin: fw.Pin},
		Key:         st.Key,
		Obfuscation: st.Obfuscation,
		Cert: func() tls.Certificate {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.id == nil {
				return tls.Certificate{}
			}
			return s.id.ForwarderCertificate()
		},
		Send: h.Send,
		Report: func(r forward.Report) {
			s.tunMu.Lock()
			defer s.tunMu.Unlock()
			if s.tunRun == nil || s.tunRun.hub != h {
				return
			}
			f := &control.Forwarder{Endpoint: fw.Endpoint.String(), Registered: r.Registered}
			if r.Seen.IsValid() {
				f.Seen = r.Seen.String()
			}
			if r.Err != nil {
				f.Error, f.Detail = forwarderProblem(r.Err), r.Err.Error()
				if s.tunFwd == nil || s.tunFwd.Detail != f.Detail {
					s.logf("cbb: sync away from home: the forwarder at %v: %v", fw.Endpoint, r.Err)
				}
			} else if f.Seen != "" && (s.tunFwd == nil || s.tunFwd.Seen != f.Seen) {
				s.logf("cbb: sync away from home: registered with the forwarder at %v, which reaches this hub at %s", fw.Endpoint, f.Seen)
			}
			s.tunFwd = f
		},
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		forward.Register(ctx, cfg)
	}()
}

// forwarderProblem is a short message for status of why the hub is not
// registered; the whole error goes to the log and to the detail.
func forwarderProblem(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refused the registration"):
		return msg
	case strings.Contains(msg, "not the one given"):
		return "the forwarder's key is not the one given with -forwarder-key"
	case strings.HasPrefix(msg, "reaching the forwarder"):
		return "the forwarder could not be reached"
	}
	return "the registration with the forwarder failed"
}
