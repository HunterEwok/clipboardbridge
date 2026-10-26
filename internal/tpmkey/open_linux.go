// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tpmkey

import (
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func openDevice() (transport.TPMCloser, error) {
	if _, err := os.Stat(Device); err != nil {
		return nil, ErrNoTPM
	}
	t, err := linuxtpm.Open(Device)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: %w", err)
	}
	return t, nil
}
