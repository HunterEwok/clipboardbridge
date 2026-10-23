// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Checks the pairing messages against the vectors that the Go tests write (go test ./internal/pair -update). */
class PairingTest {
    @Test
    fun goPairing() {
        val v = Interop.read("pairing.json").jsonObject
        assertEquals(v.str("channel_id"), Pairing.channelID(b64(v.str("member_cert")), b64(v.str("joiner_cert"))).toHex())
        assertEquals(v.str("fingerprint"), Pairing.fingerprint(b64(v.str("joiner_cert"))))
        val frames = v.getValue("frames").jsonArray
        for (goFrame in frames) {
            val f = Pairing.decode(Wire.encode(goFrame))
            // Encoding it again gives the same JSON object as Go's.
            val encoded = Pairing.encode(f)
            assertEquals(encoded.size - 4, Pairing.length(encoded.copyOf(4)))
            assertEquals<Any?>(goFrame, Wire.parse(encoded.copyOfRange(4, encoded.size)))
        }
        val first = Pairing.decode(Wire.encode(frames[0]))
        assertEquals(Pairing.Info("laptop", "linux"), Pairing.Info.decode(first.ad!!))
    }

    @Test
    fun goJoinQR() {
        val vs = Interop.read("joinqr.json").jsonArray
        assertTrue(vs.isNotEmpty())
        for (v in vs) {
            val o = v.jsonObject
            val got = JoinCode.parse(o.str("text"))
            val want = o["want"] as? JsonObject
            if (want == null) {
                assertNull(got, o.str("text"))
                continue
            }
            val addrs = (want["Addrs"] as? JsonArray)?.map { it.jsonPrimitive.content } ?: emptyList()
            assertEquals(JoinCode(want.str("Code"), addrs, want.str("Fingerprint")), got, o.str("text"))
            assertEquals(got, JoinCode.parse(got!!.qrText))
        }
    }

    @Test
    fun info() {
        assertTrue(Pairing.Info("pi", "linux").isValid)
        assertFalse(Pairing.Info("", "linux").isValid)
        assertFalse(Pairing.Info("a\u0007b", "linux").isValid)
        assertFalse(Pairing.Info("pi", "windows").isValid)
        assertTrue(Pairing.Info("Pixel", "android", SoftwareSigner().publicKeyDER).isValid)
        assertFalse(Pairing.Info("pi", "linux", SoftwareSigner().publicKeyDER).isValid)
        assertTrue(Pairing.Info("router", "linux", role = Pairing.Info.LITE).isValid)
        assertFalse(Pairing.Info("router", "linux", role = "full").isValid)
        val lite = Pairing.Info("router", "linux", role = Pairing.Info.LITE)
        assertEquals(lite, Pairing.Info.decode(lite.encode()))
        assertTrue(JoinCode.newCode().let { JoinCode(it, emptyList(), "").codeIsValid })
        assertEquals("[fd00::1]:8764", JoinCode.address("fd00::1", 8764))
    }

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content
}
