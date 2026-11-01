// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// letServiceQuery lets the service's account look up this agent's session
// and user. The service runs as NT SERVICE\clipboardbridge, which may not
// open another user's process; without this it names the agent's user
// nobody, and gives it no remote pastes and no quick actions.
func letServiceQuery() error {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+serviceName)
	if err != nil {
		return fmt.Errorf("the service's account: %w", err)
	}
	self := windows.CurrentProcess()
	sd, err := windows.GetSecurityInfo(self, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("this process's access list: %w", err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("this process's access list: %w", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.PROCESS_QUERY_LIMITED_INFORMATION,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, old)
	if err != nil {
		return fmt.Errorf("the service's entry: %w", err)
	}
	if err := windows.SetSecurityInfo(self, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("this process's access list: %w", err)
	}
	return nil
}
