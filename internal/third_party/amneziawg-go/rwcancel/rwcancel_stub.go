// Copyright the amneziawg-go authors. The original file has no notice; LICENSE applies.
// SPDX-License-Identifier: MIT

//go:build windows || wasm

package rwcancel

type RWCancel struct{}

func (*RWCancel) Cancel() {}
