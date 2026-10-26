// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package attest

import (
	"crypto/x509"
	_ "embed"
)

// tpmRootsPEM is the TPM makers' roots and intermediates that releases
// ship (tpmroots/README.md says where they come from).
//
//go:embed tpmroots/roots.pem
var tpmRootsPEM []byte

// TPMRoots are the certificates EK certificates must lead to.
var TPMRoots = func() []*x509.Certificate {
	r, err := ParseTPMRoots(tpmRootsPEM)
	if err != nil {
		panic("attest: tpmroots/roots.pem: " + err.Error())
	}
	return r
}()
