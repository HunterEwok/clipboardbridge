// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package frame

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRoundTripAndLimits(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, map[string]string{"a": "<&>"}, 64); err != nil {
		t.Fatal(err)
	}
	if got := b.String()[4:]; got != `{"a":"<&>"}` {
		t.Fatalf("frame %q", got)
	}
	b.WriteString("rest")
	var v map[string]string
	if err := Read(&b, &v, 64); err != nil || v["a"] != "<&>" || b.String() != "rest" {
		t.Fatalf("read %v, %v, left %q", v, err, b.String())
	}
	if err := Write(&b, map[string]string{"a": "0123456789"}, 8); err == nil {
		t.Error("wrote a frame over the limit")
	}
	for name, data := range map[string][]byte{
		"over the limit": binary.BigEndian.AppendUint32(nil, 65),
		"empty":          binary.BigEndian.AppendUint32(nil, 0),
		"not an object":  append(binary.BigEndian.AppendUint32(nil, 2), "[]"...),
		"cut short":      append(binary.BigEndian.AppendUint32(nil, 9), "{}"...),
	} {
		if _, err := ReadBytes(bytes.NewReader(data), 64); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}
