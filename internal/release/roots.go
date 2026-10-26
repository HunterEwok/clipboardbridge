// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

// Roots are the pinned root keys (SubjectPublicKeyInfos, DER) that every
// keys.json must verify under. The list stays empty until the project's
// root keys exist (docs/maintaining.md, "Signed releases"); until then
// nothing that needs them is fetched.
var Roots [][]byte
