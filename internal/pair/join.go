// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/third_party/cpace"
)

// A Joiner is a device that joins a group: its new device ID and key.
type Joiner struct {
	ID   group.DeviceID
	Key  *ecdsa.PrivateKey
	Info Info
	Now  func() time.Time // time.Now if nil
}

// NewJoiner returns a joiner with a new device ID and key.
func NewJoiner(info Info) (*Joiner, error) {
	if err := info.check(); err != nil {
		return nil, err
	}
	key, err := group.NewKey()
	if err != nil {
		return nil, err
	}
	return &Joiner{ID: group.NewDeviceID(), Key: key, Info: info}, nil
}

func (j *Joiner) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

// clientTLSVerifiedByCPace returns the joiner's TLS configuration. The
// joiner cannot check the member's certificate during the handshake, since
// it does not know the group CA yet: the CPace exchange, bound to this TLS
// session and to the member's certificate, authenticates the member, and
// Join checks the certificate against the group CA it receives.
func (j *Joiner) clientTLSVerifiedByCPace() (*tls.Config, error) {
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: string(j.ID)},
		NotBefore: time.Unix(0, 0),
		NotAfter:  time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &j.Key.PublicKey, j.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: j.Key}},
		InsecureSkipVerify: true,
		NextProtos:         []string{Protocol},
	}, nil
}

// Join runs the joining side of a pairing over conn, a connection to the
// member's port, with the code the user typed. It checks what the member
// sends, builds the device's new identity, calls save with it, and tells
// the member whether that worked.
func (j *Joiner) Join(ctx context.Context, conn net.Conn, code string, save func(*group.Identity) error) (*group.Identity, error) {
	code, err := NormalizeCode(code)
	if err != nil {
		conn.Close()
		return nil, err
	}
	cfg, err := j.clientTLSVerifiedByCPace()
	if err != nil {
		conn.Close()
		return nil, err
	}
	tc := tls.Client(conn, cfg)
	defer tc.Close()
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { tc.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	cs := tc.ConnectionState()
	if cs.NegotiatedProtocol != Protocol || len(cs.PeerCertificates) == 0 {
		return nil, errors.New("pair: the device does not offer pairing")
	}
	memberCert := cs.PeerCertificates[0]
	ci, sid, err := binding(cs, memberCert.Raw, cfg.Certificates[0].Certificate[0])
	if err != nil {
		return nil, err
	}
	ad, err := json.Marshal(j.Info)
	if err != nil {
		return nil, err
	}
	st, msg, err := cpace.Start(&cpace.Config{Role: cpace.Initiator, Password: []byte(code), ChannelID: ci, SessionID: sid, AD: ad})
	if err != nil {
		return nil, err
	}
	if err := writeFrame(tc, &frame{Msg: msg, AD: ad}); err != nil {
		return nil, err
	}
	reply, err := readFrame(tc)
	if err != nil {
		return nil, err
	}
	if reply.Error != "" {
		return nil, errorOf(reply.Error)
	}
	if _, err := st.Finish(reply.Msg, reply.AD); err != nil {
		return nil, err
	}
	var member memberAD
	if err := json.Unmarshal(reply.AD, &member); err != nil {
		return nil, err
	}
	// From here on the other side can check a guess of the code.
	if err := writeFrame(tc, &frame{Tag: st.Tag()}); err != nil {
		return nil, &spentError{err}
	}
	final, err := readFrame(tc)
	if err != nil {
		return nil, &spentError{err}
	}
	if final.Error != "" {
		return nil, &spentError{errorOf(final.Error)}
	}
	if err := st.Verify(final.Tag); err != nil || final.Welcome == nil {
		return nil, &spentError{errors.New("pair: the other device did not prove that it knows the code")}
	}
	id, err := j.identity(final.Welcome, memberCert, member)
	if err == nil {
		err = save(id)
	}
	if err != nil {
		writeFrame(tc, &frame{Error: "refused"})
		return nil, &spentError{err}
	}
	// The identity is stored, and the member admitted the device when it
	// sent the welcome, whether or not it hears this.
	writeFrame(tc, &frame{OK: true})
	return id, nil
}

// identity checks what the member sent and builds the new identity.
func (j *Joiner) identity(w *Welcome, memberCert *x509.Certificate, member memberAD) (*group.Identity, error) {
	var err error
	id := &group.Identity{ID: j.ID, Key: j.Key}
	if id.Cert, err = x509.ParseCertificate(w.Cert); err != nil {
		return nil, err
	}
	if id.GroupCA.Cert, err = x509.ParseCertificate(w.GroupCA); err != nil {
		return nil, err
	}
	if group.Tag(id.GroupCA.Cert) != member.Group {
		return nil, errors.New("pair: the member sent another group CA than it announced")
	}
	// The member's own certificate is from the same group CA and names the
	// device it announced.
	if err := memberCert.CheckSignatureFrom(id.GroupCA.Cert); err != nil {
		return nil, fmt.Errorf("pair: the member's certificate is not from the group CA: %w", err)
	}
	if dev, err := group.DeviceOf(memberCert); err != nil || dev != member.Device {
		return nil, errors.New("pair: the member's certificate does not name the member")
	}
	if j.Info.OS == "linux" {
		if w.GroupCAKey == nil || w.PhoneCA == nil || w.PhoneCAKey == nil {
			return nil, errors.New("pair: the member did not send the CA keys")
		}
		if id.GroupCA.Key, err = parseKey(w.GroupCAKey); err != nil {
			return nil, err
		}
		phoneCA := &group.CA{}
		if phoneCA.Cert, err = x509.ParseCertificate(w.PhoneCA); err != nil {
			return nil, err
		}
		if phoneCA.Key, err = parseKey(w.PhoneCAKey); err != nil {
			return nil, err
		}
		id.PhoneCA = phoneCA
		if id.Phone, err = phoneCA.IssuePhone(&j.Key.PublicKey, j.now()); err != nil {
			return nil, err
		}
	}
	if err := id.Check(); err != nil {
		return nil, err
	}
	return id, nil
}

func parseKey(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("pair: a CA key is not a P-256 key")
	}
	return key, nil
}
