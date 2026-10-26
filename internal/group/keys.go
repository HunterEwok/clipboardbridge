// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/HunterEwok/clipboardbridge/internal/tpmkey"
)

// TPMEnv set to "off" keeps new member and admin keys out of the TPM; a
// key already in it stays there.
const TPMEnv = "CBB_TPM"

var (
	tpmOnce sync.Once
	tpm     *tpmkey.TPM
	tpmErr  error
)

// theTPM opens the machine's TPM once; every key of the process uses it.
func theTPM() (*tpmkey.TPM, error) {
	tpmOnce.Do(func() { tpm, tpmErr = tpmkey.Open() })
	return tpm, tpmErr
}

// NewDeviceKey makes a member or admin key: in the TPM when the machine has
// one that this program may use (docs/protocol.md, section 17), and in
// memory, to be saved in the identity file, otherwise.
func NewDeviceKey() (crypto.Signer, error) {
	if os.Getenv(TPMEnv) != "off" {
		if t, err := theTPM(); err == nil {
			k, err := t.NewKey()
			if err == nil {
				return k, nil
			}
			// A TPM that opens but cannot make keys (full, or refusing
			// the template) leaves the key in a file.
		}
	}
	return NewKey()
}

// KeyStoreOf returns where k lives: StoreHardware for a key in the TPM,
// StoreFile otherwise.
func KeyStoreOf(k crypto.Signer) string {
	if _, ok := k.(*tpmkey.Key); ok {
		return StoreHardware
	}
	return StoreFile
}

// keyBlob returns the TPM blob of k, nil for a key in a file.
func keyBlob(k crypto.Signer) *tpmkey.Blob {
	if t, ok := k.(*tpmkey.Key); ok {
		b := t.Blob()
		return &b
	}
	return nil
}

// loadTPMKey loads a key that the identity file keeps as a TPM blob.
func loadTPMKey(b *tpmkey.Blob) (crypto.Signer, error) {
	t, err := theTPM()
	if errors.Is(err, tpmkey.ErrNoTPM) {
		return nil, fmt.Errorf("group: this device's key is in a TPM that is not there (%s); was the identity copied from another machine?", tpmkey.Device)
	}
	if err != nil {
		return nil, fmt.Errorf("group: opening the TPM that holds this device's key: %w", err)
	}
	return t.LoadKey(*b)
}

// Sealer seals secrets, as the WireGuard key, with the TPM that would
// hold new device keys; where new keys go into a file, Seal returns nil,
// nil and the secret stays in its file too.
type Sealer struct{}

// Seal seals secret, or returns nil, nil without a TPM to use.
func (Sealer) Seal(secret []byte) (*tpmkey.Blob, error) {
	if os.Getenv(TPMEnv) == "off" {
		return nil, nil
	}
	t, err := theTPM()
	if err != nil {
		return nil, nil
	}
	b, err := t.Seal(secret)
	if err != nil {
		return nil, nil // as NewDeviceKey: a TPM that cannot seal leaves the file
	}
	return &b, nil
}

// Unseal returns what Seal sealed in b.
func (Sealer) Unseal(b *tpmkey.Blob) ([]byte, error) {
	t, err := theTPM()
	if errors.Is(err, tpmkey.ErrNoTPM) {
		return nil, fmt.Errorf("the key is sealed by a TPM that is not there (%s); was the state copied from another machine?", tpmkey.Device)
	}
	if err != nil {
		return nil, fmt.Errorf("opening the TPM that sealed the key: %w", err)
	}
	return t.Unseal(*b)
}
