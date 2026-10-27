// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// siteBody is what the bench's stand-in for a well-known site serves, so
// that a visitor who is no client of the forwarder's VLESS can tell it got
// the borrowed site (W34).
const siteBody = "cbb-bench borrowed site"

// runSite serves HTTPS with TLS 1.3 on listen as the site name, with a
// certificate of its own: what a forwarder's VLESS with REALITY borrows,
// in a fleet that has no well-known site to reach.
func runSite(listen, name string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: listen, ReadHeaderTimeout: 10 * time.Second,
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, siteBody) }),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	return srv.ListenAndServeTLS("", "")
}
