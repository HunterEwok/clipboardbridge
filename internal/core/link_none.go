// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !(cbbcore && cgo) && !cbbwasm

package core

const linked = false

func abi() (int, error) { return 0, ErrUnavailable }

func call([]byte) ([]byte, error) { return nil, ErrUnavailable }
