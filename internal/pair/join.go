// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
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

	certOnce sync.Once
	certDER  []byte // the self-signed certificate for Key, made once
	certErr  error
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

// cert returns the joiner's self-signed certificate for its key, the same
// on every call: it is what the QR code's fingerprint names.
func (j *Joiner) cert() ([]byte, error) {
	j.certOnce.Do(func() {
		tmpl := &x509.Certificate{
			Subject:   pkix.Name{CommonName: string(j.ID)},
			NotBefore: time.Unix(0, 0),
			NotAfter:  time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		}
		j.certDER, j.certErr = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &j.Key.PublicKey, j.Key)
	})
	return j.certDER, j.certErr
}

// tlsConfigVerifiedByCPace returns the joiner's TLS configuration, for
// either end of the connection. The joiner cannot check the member's
// certificate during the handshake, since it does not know the group CA
// yet: the CPace exchange, bound to this TLS session and to the member's
// certificate, authenticates the member, and the joiner checks the
// certificate against the group CA it receives.
func (j *Joiner) tlsConfigVerifiedByCPace() (*tls.Config, error) {
	der, err := j.cert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: j.Key}},
		InsecureSkipVerify:     true,
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{Protocol},
		SessionTicketsDisabled: true,
	}, nil
}

// Fingerprint returns the fingerprint of the joiner's certificate that a
// member dialing the joiner checks: SHA-256 over the DER, in base64url
// without padding.
func (j *Joiner) Fingerprint() (string, error) {
	der, err := j.cert()
	if err != nil {
		return "", err
	}
	return CertFingerprint(der), nil
}

// CertFingerprint returns the fingerprint of a certificate in the form a
// join QR code carries: SHA-256 over the DER, in base64url without padding.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Join runs the joining side of a pairing over conn, a connection the
// joiner dialed to the member's port, with the code the user typed. It
// checks what the member sends, builds the device's new identity, calls
// save with it, and tells the member whether that worked.
func (j *Joiner) Join(ctx context.Context, conn net.Conn, code string, save func(*group.Identity) error) (*group.Identity, error) {
	cfg, err := j.tlsConfigVerifiedByCPace()
	if err != nil {
		conn.Close()
		return nil, err
	}
	return j.join(ctx, tls.Client(conn, cfg), code, false, save)
}

// Accept runs the joining side of a pairing over conn, a connection that a
// member dialed to the joiner, which listens and showed its address and
// Fingerprint in the QR code. The member, which dialed, confirms the key
// first, so the joiner reveals nothing to a device that does not know the
// code: a failed attempt is never Spent, and the joiner may take another.
func (j *Joiner) Accept(ctx context.Context, conn net.Conn, code string, save func(*group.Identity) error) (*group.Identity, error) {
	cfg, err := j.tlsConfigVerifiedByCPace()
	if err != nil {
		conn.Close()
		return nil, err
	}
	return j.join(ctx, tls.Server(conn, cfg), code, true, save)
}

// join runs the exchange. With memberFirst the member confirms the key
// before the joiner does.
func (j *Joiner) join(ctx context.Context, tc *tls.Conn, code string, memberFirst bool, save func(*group.Identity) error) (*group.Identity, error) {
	defer tc.Close()
	code, err := NormalizeCode(code)
	if err != nil {
		return nil, err
	}
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
	own, err := j.cert()
	if err != nil {
		return nil, err
	}
	ci, sid, err := binding(cs, memberCert.Raw, own)
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
	// spent marks an error after the joiner's tag went out, from which on
	// the other side can check a guess of the code; when the member
	// confirmed first, it already proved that it knows the code.
	spent := func(err error) error { return &spentError{err} }
	if memberFirst {
		if err := st.Verify(reply.Tag); err != nil {
			writeFrame(tc, &frame{Error: codeOf(ErrWrongCode)})
			return nil, ErrWrongCode
		}
		spent = func(err error) error { return err }
	}
	if err := writeFrame(tc, &frame{Tag: st.Tag()}); err != nil {
		return nil, spent(err)
	}
	final, err := readFrame(tc)
	if err != nil {
		return nil, spent(err)
	}
	if final.Error != "" {
		return nil, spent(errorOf(final.Error))
	}
	if !memberFirst && st.Verify(final.Tag) != nil || final.Welcome == nil {
		return nil, spent(errors.New("pair: the other device did not prove that it knows the code"))
	}
	id, err := j.identity(final.Welcome, memberCert, member)
	if err == nil {
		err = save(id)
	}
	if err != nil {
		writeFrame(tc, &frame{Error: "refused"})
		return nil, spent(err)
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
