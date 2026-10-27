// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class WatchStateTest {
    @Test
    fun roundTrip() {
        val s = WatchState(
            hasGroup = true,
            devices = listOf(WatchState.Device("a1", "deck", "desktop", true), WatchState.Device("b2", "pi \"4\" ü", "board", false)),
            away = WatchState.Away.CONNECTED,
            events = listOf("deck joined the group.", "pi was removed from the group."),
            color = "ocean",
            details = true,
        )
        assertEquals(s, WatchState.decode(s.encode()))
        assertEquals(WatchState(), WatchState.decode(WatchState().encode()))
    }

    @Test
    fun certifying() {
        val r = WatchState.KeyRequest("ab".repeat(16), "Pixel Watch", byteArrayOf(1, 2, 3))
        assertEquals(r, WatchState.KeyRequest.decode(r.encode()))
        val no = WatchState.KeyRequest(refused = WatchState.NOT_PROTECTED)
        assertEquals(no, WatchState.KeyRequest.decode(no.encode()))
        val a = WatchState.Admission("ab".repeat(16), byteArrayOf(9, 8), "0123456789abcdef")
        assertEquals(a, WatchState.Admission.decode(a.encode()))
        assertNull(WatchState.Admission.decode("{}".toByteArray()))
    }

    @Test
    fun rejectsOther() {
        assertNull(WatchState.decode("not json".toByteArray()))
        assertNull(WatchState.decode(null))
        // An away state of a later phone app reads as none.
        assertNull(WatchState.decode("""{"hasGroup":true,"away":"later"}""".toByteArray())!!.away)
    }
}
