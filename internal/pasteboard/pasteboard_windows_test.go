// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"os"
	"testing"
)

// Windows has no private clipboards, so these tests use the session's own
// and run only when CBB_TEST_CLIPBOARD=1 says that it may be overwritten.
func private(t *testing.T) *Board {
	t.Helper()
	if os.Getenv("CBB_TEST_CLIPBOARD") != "1" {
		t.Skip("set CBB_TEST_CLIPBOARD=1 to let the test overwrite the clipboard")
	}
	return General()
}

func TestWriteRead(t *testing.T) {
	b := private(t)
	before := b.ChangeCount()
	text := "hello привет \U0001F600\nsecond line"
	change, err := b.Write(text, false)
	if err != nil {
		t.Fatal(err)
	}
	if change <= before || b.ChangeCount() != change {
		t.Errorf("change counter %d -> %d (now %d)", before, change, b.ChangeCount())
	}
	it, ok, err := b.Read()
	if err != nil || !ok {
		t.Fatalf("Read = %v, %v", ok, err)
	}
	if it.Text != text || it.Secret || it.Remote || it.Change != change {
		t.Errorf("Read = %+v", it)
	}
}

func TestLineEndsAndNUL(t *testing.T) {
	b := private(t)
	if _, err := b.Write("a\r\nb\nc\x00after a NUL", false); err != nil {
		t.Fatal(err)
	}
	h := readRaw(t)
	if h != "a\r\nb\r\nc" {
		t.Errorf("the clipboard holds %q, want CR LF line ends and nothing after the NUL", h)
	}
	if it, _, _ := b.Read(); it.Text != "a\nb\nc" {
		t.Errorf("Read = %q", it.Text)
	}
}

// readRaw returns the clipboard's text as Windows apps see it.
func readRaw(t *testing.T) string {
	t.Helper()
	var text string
	err := onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		h, _, _ := procGetClipboardData.Call(cfUnicodeText)
		var err error
		text, err = globalText(h)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func TestSecret(t *testing.T) {
	b := private(t)
	if _, err := b.Write("hunter2", true); err != nil {
		t.Fatal(err)
	}
	it, ok, err := b.Read()
	if err != nil || !ok {
		t.Fatalf("Read = %v, %v", ok, err)
	}
	if !it.Secret || it.Text != "hunter2" {
		t.Errorf("Read of a secret = %+v", it)
	}
	var marks [4]bool
	onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		marks = [4]bool{available(cfExclude), available(cfViewerIgnore), zero(cfHistory), zero(cfCloud)}
		return nil
	})
	if marks != [4]bool{true, true, true, true} {
		t.Errorf("the secret's marks: %v", marks)
	}
	// A text written after it carries none.
	if _, err := b.Write("plain", false); err != nil {
		t.Fatal(err)
	}
	if it, _, _ := b.Read(); it.Secret {
		t.Error("a plain text after a secret is still marked")
	}
}

func TestEmptyAndClear(t *testing.T) {
	b := private(t)
	if _, err := b.Write("x", false); err != nil {
		t.Fatal(err)
	}
	b.Clear()
	if _, ok, _ := b.Read(); ok {
		t.Error("the text survived Clear")
	}
}
