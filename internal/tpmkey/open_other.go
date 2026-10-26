// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package tpmkey

import "github.com/google/go-tpm/tpm2/transport"

// openDevice finds no TPM: the service uses one only on Linux so far
// (Windows waits for a real PC to test on).
func openDevice() (transport.TPMCloser, error) { return nil, ErrNoTPM }
