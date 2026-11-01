// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !(cbbcore && cgo)

package core

const linked = false

func abi() int { return 0 }

func call([]byte) []byte { return nil }
