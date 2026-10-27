// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import "errors"

// errKeyboardOS is the answer where there is no Bluetooth keyboard.
var errKeyboardOS = errors.New("only a Linux computer can be a Bluetooth keyboard: macOS and Windows let no program be one; an Android phone or the Nano ESP32 can")
