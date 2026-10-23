// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import "golang.org/x/sys/windows"

// controlMessages tells that the system reports the interface of each
// packet. Windows does not through golang.org/x/net, so a packet's
// interface is found from its source address, and a multicast goes out on
// the interface set on the socket before it is sent.
const controlMessages = false

// reuse lets the socket share port 5353 with the DNS Client service, which
// answers mDNS for Windows itself.
func reuse(fd uintptr) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
}
