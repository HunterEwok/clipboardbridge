// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// bufConn is a connection that reads from a buffer.
type bufConn struct {
	net.Conn
	r *bytes.Reader
}

func (c bufConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c bufConn) SetReadDeadline(time.Time) error  { return nil }
func (c bufConn) SetWriteDeadline(time.Time) error { return nil }

// FuzzRelayWire reads the frames a registration and a member's connection
// start with, as anyone may send them: readLine never reads past its frame,
// which the member protocol follows, nor takes one over the limit.
func FuzzRelayWire(f *testing.F) {
	for _, s := range []string{
		`{"key":"AAAA","proof":"AAAA","records":[{"body":"e30=","sig":"AA=="}]}`,
		`{"watch":true}`,
		`{"dial":"00112233445566778899aabbccddeeff"}`,
		`{"answer":"x"}`,
		`{"e":"AAAA","roots":true}`,
		`{"key":"AAAA","credentials":[{"body":"e30=","sig":"AA==","key":"AA=="}],"roots":["AA=="]}`,
	} {
		f.Add(append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s+"TLS"...))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, v := range []any{&claim{}, &request{}, &challenge{}, &welcome{}, &note{}} {
			r := bytes.NewReader(data)
			err := readLine(bufConn{r: r}, v, time.Second)
			rest, _ := io.ReadAll(r)
			if len(data) < 4 {
				if err == nil {
					t.Fatal("took a frame without its length")
				}
				continue
			}
			n := int(binary.BigEndian.Uint32(data))
			switch {
			case n > maxLine || n == 0:
				if err == nil {
					t.Fatalf("took a frame of %d bytes", n)
				}
			case len(data) < 4+n:
				if err == nil {
					t.Fatal("took a frame cut short")
				}
			case !bytes.Equal(rest, data[4+n:]):
				t.Fatalf("read %d bytes past the frame", len(data)-4-n-len(rest))
			}
		}
	})
}
