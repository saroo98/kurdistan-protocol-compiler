// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertEquals
import org.junit.Test

class UnderlyingNetworkMonitorTest {
    @Test
    fun ignoresDuplicatesAndStaleLossWhileReportingCurrentNetworkChanges() {
        val transitions = mutableListOf<NetworkTransition<String>>()
        val tracker = CurrentNetworkTracker<String>(transitions::add)

        tracker.available("wifi")
        tracker.available("wifi")
        tracker.available("cell")
        tracker.lost("wifi")
        tracker.lost("cell")

        assertEquals(
            listOf(
                NetworkTransition(null, "wifi"),
                NetworkTransition("wifi", "cell"),
                NetworkTransition("cell", null),
            ),
            transitions,
        )
    }
}
