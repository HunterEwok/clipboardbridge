// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
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

    /**
     * testdata/interop/strict-generated.json, from the tables of docs/protocol.md: the kit takes exactly the bodies the
     * tables take, and says which row it reads otherwise.
     */
    @Test
    fun generated() {
        val v = Interop.read("strict-generated.json").jsonObject
        val wrong = mutableListOf<String>()
        for (kind in listOf("records", "commands", "manifests")) {
            val cases = v.getValue(kind).jsonArray
            assertTrue(cases.isNotEmpty(), "no $kind")
            for (c in cases) {
                val o = c.jsonObject
                var body = b64(o.str("body"))
                o["pad"]?.let {
                    val at = o.getValue("pad_at").jsonPrimitive.int
                    body = body.copyOfRange(0, at) + ByteArray(it.jsonPrimitive.int) { 'a'.code.toByte() } + body.copyOfRange(at, body.size)
                }
                val got = when (kind) {
                    "records" -> runCatching { Records.Body.decode(body) != null }
                    "commands" -> runCatching { Commands.parse(body) }.map { true }
                    else -> runCatching { Wire.parse(body)?.let { Media.Manifest.fromJson(it) }?.isValid == true }
                }.getOrDefault(false)
                val valid = o.getValue("valid").jsonPrimitive.boolean
                if (got != valid) wrong += "$kind ${o.str("name")} (${o.str("rule")}): valid $valid, got $got"
            }
        }
        assertTrue(wrong.isEmpty(), "${wrong.size} vectors read otherwise:\n" + wrong.joinToString("\n"))
    }
}
