// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build unix && !linux && !darwin && !freebsd

package service

import "net"

// connPeer knows no peer here, so no watcher takes remote pastes.
func connPeer(net.Conn) peer { return peer{} }

func (peer) privileged() bool { return false }

func atScreen(peer, string) verdict { return refused }
