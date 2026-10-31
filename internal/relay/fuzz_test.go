// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"bytes"
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

// FuzzRelayWire reads the lines a registration and a member's connection
// start with, as anyone may send them: readLine never reads past its line,
// which the member protocol follows, nor takes one over the limit.
func FuzzRelayWire(f *testing.F) {
	for _, s := range []string{
		`{"key":"AAAA","proof":"AAAA","records":[{"body":"e30=","sig":"AA=="}]}` + "\n",
		`{"watch":true}` + "\nTLS",
		`{"dial":"00112233445566778899aabbccddeeff"}` + "\n",
		`{"answer":"x"}` + "\n",
		`{"e":"AAAA","roots":true}` + "\n",
		`{"key":"AAAA","credentials":[{"body":"e30=","sig":"AA==","key":"AA=="}],"roots":["AA=="]}` + "\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, v := range []any{&claim{}, &request{}, &challenge{}, &welcome{}, &note{}} {
			r := bytes.NewReader(data)
			err := readLine(bufConn{r: r}, v, time.Second)
			i := bytes.IndexByte(data, '\n')
			rest, _ := io.ReadAll(r)
			switch {
			case i < 0:
				if err == nil {
					t.Fatal("took a line without its end")
				}
			case i > maxLine:
				if err == nil {
					t.Fatalf("took a line of %d bytes", i)
				}
			case !bytes.Equal(rest, data[i+1:]):
				t.Fatalf("read %d bytes past the line", len(data)-i-1-len(rest))
			}
		}
	})
}
