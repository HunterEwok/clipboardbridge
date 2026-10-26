// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/tpmkey/tpmtest"
)

// useTPM points the package at the TPM that tpmtest started, for one test.
func useTPM(t *testing.T) {
	tpmtest.Start(t)
	reset := func() {
		if tpm != nil {
			tpm.Close()
		}
		tpmOnce, tpm, tpmErr = sync.Once{}, nil, nil
	}
	reset()
	t.Cleanup(reset)
}

// TestKeysInTPM checks that a new identity's member key and a computer's
// admin key go into the TPM, are saved as blobs, load again, and that
// CBB_TPM=off keeps new keys in the file.
func TestKeysInTPM(t *testing.T) {
	useTPM(t)
	id, err := Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if KeyStoreOf(id.Key) != StoreHardware {
		t.Fatal("the member key is not in the TPM")
	}
	dir := t.TempDir()
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, FileName))
	if !strings.Contains(string(data), `"key_tpm"`) || strings.Contains(string(data), `"key":`) {
		t.Errorf("the identity file keeps the member key as %s", data)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if KeyStoreOf(got.Key) != StoreHardware || !SameKey(got.Key, id.Key.Public()) {
		t.Fatal("the loaded member key is not the TPM's")
	}
	// The root's member certificate renews with the key in the TPM.
	if _, _, err := got.Renew(time.Now().AddDate(1, 6, 0)); err != nil {
		t.Fatal(err)
	}

	pg := newPhoneGroup(t)
	pending, err := adminIdentity(t, pg, nil).WithAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	if KeyStoreOf(pending.AdminKey) != StoreHardware {
		t.Error("the admin key is not in the TPM")
	}
	if err := pending.Save(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(dir); err != nil || KeyStoreOf(got.AdminKey) != StoreHardware {
		t.Errorf("the admin key did not load from the TPM: %v", err)
	}

	t.Setenv(TPMEnv, "off")
	k, err := NewDeviceKey()
	if err != nil || KeyStoreOf(k) != StoreFile {
		t.Errorf("CBB_TPM=off made a key in the %s", KeyStoreOf(k))
	}
}
