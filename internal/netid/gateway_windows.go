// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package netid

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var sendARP = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SendARP")

// gateways reads the default routes with GetIpForwardTable2 and the
// gateways' addresses with SendARP, which answers from the ARP cache.
func gateways() (map[int]string, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	out := map[int]string{}
	for _, r := range table.Rows() {
		if r.DestinationPrefix.PrefixLength != 0 || r.NextHop.Family != windows.AF_INET {
			continue
		}
		idx := int(r.InterfaceIndex)
		if _, seen := out[idx]; seen {
			continue
		}
		sa := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.NextHop))
		if sa.Addr == [4]byte{} {
			continue
		}
		var mac [8]byte
		n := uint32(len(mac))
		dest := binary.LittleEndian.Uint32(sa.Addr[:]) // IPAddr is in network order in memory
		if rc, _, _ := sendARP.Call(uintptr(dest), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&n))); rc != 0 || n != 6 {
			continue
		}
		out[idx] = net.HardwareAddr(mac[:6]).String()
	}
	return out, nil
}
