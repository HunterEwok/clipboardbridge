// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// MemberProtocol is the ALPN protocol of connections between members.
const MemberProtocol = "clipbridge/1"

// TLSOptions adjust the TLS configuration of member connections.
type TLSOptions struct {
	// Allow, if set, is called with the peer's device ID and the
	// certificates it presented (leaf first) once they are verified; an
	// error rejects the peer, for example a revoked device.
	Allow func(DeviceID, []*x509.Certificate) error

	// Now returns the current time; time.Now if nil.
	Now func() time.Time
}

func (o TLSOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// ServerTLS returns the TLS configuration for accepting connections from
// members: TLS 1.3 only, and a client certificate from the group CA is
// required.
func (id *Identity) ServerTLS(opt TLSOptions) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.memberTLSCert()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    id.groupPool(),
		NextProtos:   []string{MemberProtocol},
		Time:         id.verifyClock(opt),
		// Member connections last; without resumption every connection
		// checks the full chain.
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := id.checkPeer(cs, opt)
			return err
		},
	}
}

// ClientTLS returns the TLS configuration for connecting to the member
// peer, whose device ID came from discovery: TLS 1.3 only, and the server
// must present the member certificate of that device from the group CA.
func (id *Identity) ClientTLS(peer DeviceID, opt TLSOptions) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.memberTLSCert()},
		RootCAs:      id.groupPool(),
		ServerName:   peer.HostName(),
		NextProtos:   []string{MemberProtocol},
		Time:         id.verifyClock(opt),
		VerifyConnection: func(cs tls.ConnectionState) error {
			got, err := id.checkPeer(cs, opt)
			if err == nil && got != peer {
				err = fmt.Errorf("group: reached %s instead of %s", got, peer)
			}
			return err
		},
	}
}

// PhoneTLS returns the TLS configuration for the iPhone port, with the
// clipbridge.local certificate. It returns nil on a device without one.
func (id *Identity) PhoneTLS() *tls.Config {
	cert := id.PhoneCertificate()
	if cert == nil {
		return nil
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
	}
}

// PhoneCertificate returns the clipbridge.local certificate with its CA, for
// the iPhone port, or nil on a device without one.
func (id *Identity) PhoneCertificate() *tls.Certificate {
	if id.Phone == nil {
		return nil
	}
	cert := id.tlsCert(id.Phone)
	cert.Certificate = append(cert.Certificate, id.PhoneCA.Cert.Raw)
	return &cert
}

// PeerID returns the device ID of the member at the other end of a
// connection that completed its handshake with ServerTLS or ClientTLS.
func PeerID(cs tls.ConnectionState) (DeviceID, error) {
	if len(cs.PeerCertificates) == 0 {
		return "", errors.New("group: the peer sent no certificate")
	}
	return DeviceOf(cs.PeerCertificates[0])
}

// checkPeer runs after crypto/tls verified the peer's certificate chain to
// the group CA: it checks the protocol and the device ID and asks Allow.
func (id *Identity) checkPeer(cs tls.ConnectionState, opt TLSOptions) (DeviceID, error) {
	if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != MemberProtocol {
		return "", errors.New("group: the peer does not speak the member protocol")
	}
	peer, err := PeerID(cs)
	if err != nil {
		return "", err
	}
	if opt.Allow != nil {
		if err := opt.Allow(peer, cs.PeerCertificates); err != nil {
			return "", err
		}
	}
	return peer, nil
}

// memberTLSCert is the member certificate for member connections, with its
// admin CA when one issued it, so that the peer can build the chain to the
// group CA.
func (id *Identity) memberTLSCert() tls.Certificate {
	cert := id.tlsCert(id.Cert)
	if id.Issuer != nil {
		cert.Certificate = append(cert.Certificate, id.Issuer.Raw)
	}
	return cert
}

func (id *Identity) tlsCert(leaf *x509.Certificate) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: id.Key, Leaf: leaf}
}

func (id *Identity) groupPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(id.GroupCA.Cert)
	return pool
}

// verifyClock returns the clock crypto/tls checks member certificates
// with; see verifyTime.
func (id *Identity) verifyClock(opt TLSOptions) func() time.Time {
	ca := id.GroupCA.Cert
	return func() time.Time { return verifyTime(ca, opt.now()) }
}
