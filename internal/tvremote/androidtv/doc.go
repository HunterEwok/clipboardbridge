// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package androidtv is the remote of an Android TV or Google TV: the
// Android TV Remote v2 protocol of the Google TV app, which the TV's
// "Android TV Remote Service" serves (docs/roadmap.md, item 25, way 2).
// Pairing runs the "polo" protocol on TCP 6467 inside TLS with a client
// certificate, and the remote runs on TCP 6466 with the same certificate.
// Both speak protobuf, each message after its length as a varint.
//
// The protocol is not documented. It is written here from its wire
// format, with tronikos/androidtvremote2 (Python, Apache-2.0) and
// Google's own pairing code in AOSP (external/google-tv-pairing-protocol,
// Apache-2.0) as the reference; the field numbers are theirs.
package androidtv
