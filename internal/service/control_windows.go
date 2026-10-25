// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// listenControl listens on the control socket. Windows checks a client's
// right to write the socket file when it connects, and the file takes its
// access list from its directory, so the directory gets a protected list
// first: full access for the system, administrators and the service's own
// account, read and write for the clipboardbridge group. Nobody else can
// connect, and the list is in place before the socket exists. The admin
// socket's directory lets in only the system, administrators and the
// service's account.
func listenControl(path string, admin bool) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	sddl, err := controlSDDL(admin)
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("the access list of the control socket: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, fmt.Errorf("the access list of the control socket: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return nil, fmt.Errorf("narrowing %s: %w", dir, err)
	}
	// A socket left by a service that did not stop cleanly blocks the name.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	return &controlListener{UnixListener: ul, path: path}, nil
}

// controlSDDL describes the access list of the socket's directory, which
// its files inherit. A user's sign-in token lists only the groups the user
// was in at sign-in, so the list also names each member of the
// clipboardbridge group as the service finds it at start: a user that
// install.ps1 just added may connect before signing in again. Without the
// group, as when the service runs by hand on a machine where nothing was
// installed, only administrators and the service's account may connect.
func controlSDDL(admin bool) (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("the service's account: %w", err)
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + tu.User.Sid.String() + ")"
	if admin {
		return sddl, nil
	}
	sid, _, typ, err := windows.LookupSID("", control.Group)
	if err != nil || typ != windows.SidTypeAlias {
		return sddl, nil
	}
	sddl += "(A;OICI;GRGW;;;" + sid.String() + ")"
	members, err := groupMembers(control.Group)
	if err != nil {
		return "", fmt.Errorf("the members of the %s group: %w", control.Group, err)
	}
	for _, m := range members {
		sddl += "(A;OICI;GRGW;;;" + m + ")"
	}
	return sddl, nil
}

var procNetLocalGroupGetMembers = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetLocalGroupGetMembers")

// groupMembers returns the SIDs of the members of a local group.
func groupMembers(name string) ([]string, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var buf *byte
	var read, total uint32
	r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(n)), 0,
		uintptr(unsafe.Pointer(&buf)), 0xFFFFFFFF, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), 0)
	if r != 0 {
		return nil, windows.Errno(r)
	}
	defer windows.NetApiBufferFree(buf)
	// LOCALGROUP_MEMBERS_INFO_0 holds only the member's SID.
	infos := unsafe.Slice((**windows.SID)(unsafe.Pointer(buf)), read)
	out := make([]string, 0, read)
	for _, sid := range infos {
		if sid != nil && sid.IsValid() {
			out = append(out, sid.String())
		}
	}
	return out, nil
}

// controlListener removes the socket when it is closed.
type controlListener struct {
	*net.UnixListener
	path string
	once sync.Once
}

func (l *controlListener) Close() error {
	err := l.UnixListener.Close()
	l.once.Do(func() { os.Remove(l.path) })
	return err
}
