// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.settings

import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.mutablePreferencesOf
import androidx.datastore.preferences.core.stringPreferencesKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.TunnelPreferences

class Phase13SettingsCodecTest {
    @Test
    fun corruptTunnelGroupDoesNotEraseIndependentSettings() {
        val decoded = decodePhase9Settings(
            mutablePreferencesOf(
                booleanPreferencesKey("high_contrast") to true,
                intPreferencesKey("mtu") to 7,
                booleanPreferencesKey("automatic_updates") to false,
                stringPreferencesKey("log_level") to DiagnosticLogLevel.INFO.name,
            ),
        )

        assertTrue(decoded.highContrast)
        assertEquals(TunnelPreferences(), decoded.tunnel)
        assertFalse(decoded.updates.automatic)
        assertEquals(DiagnosticLogLevel.INFO, decoded.diagnostics.level)
    }

    @Test
    fun unknownEnumsFallBackOnlyWithinTheirField() {
        val decoded = decodePhase9Settings(
            mutablePreferencesOf(
                stringPreferencesKey("ip_mode") to "ATTACKER_MODE",
                booleanPreferencesKey("reduced_motion") to true,
                intPreferencesKey("probe_timeout_seconds") to 9,
            ),
        )

        assertEquals(TunnelPreferences().ipMode, decoded.tunnel.ipMode)
        assertTrue(decoded.reducedMotion)
        assertEquals(9, decoded.probes.timeoutSeconds)
    }
}
