// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class StrictTest {
    private val v = Interop.read("strict.json").jsonObject

    private fun cases(kind: String): List<Triple<String, ByteArray, Boolean>> =
        v.getValue(kind).jsonArray.map {
            val o = it.jsonObject
            Triple(o.str("name"), b64(o.str("body")), o.getValue("valid").jsonPrimitive.boolean)
        }.also { assertTrue(it.isNotEmpty(), "no $kind") }

    /** testdata/interop/strict.json, from the Go tests: the kit takes exactly the record bodies the Go member does. */
    @Test
    fun records() {
        for ((name, body, valid) in cases("records")) assertEquals(valid, Records.Body.decode(body) != null, "record $name")
    }

    @Test
    fun commands() {
        for ((name, body, valid) in cases("commands")) {
            val got = runCatching { Commands.parse(body) }
            assertEquals(valid, got.isSuccess, "command $name: ${got.exceptionOrNull()?.message}")
        }
    }

    @Test
    fun manifests() {
        for ((name, body, valid) in cases("manifests")) {
            val got = runCatching { Wire.parse(body)?.let { Media.Manifest.fromJson(it) }?.isValid == true }.getOrDefault(false)
            assertEquals(valid, got, "manifest $name")
        }
    }
}
