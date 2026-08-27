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
    @Test fun byteOnlyProjectionSerializationBindsItsImageAndReturnsIndependentOwnedBytes() = kotlinx.coroutines.runBlocking {
        val image = SettingsProjectionCodec.fromModel(org.kurdistanvpn.core.model.Phase9Settings())
        val identity = SettingsProjectionIdentity.capture("01".repeat(16), "02".repeat(32), 2, image)
        val bytes = SettingsProjectionCodec.toStoredBytes(image, identity)
        val reread = SettingsProjectionCodec.fromStoredBytes(bytes)
        org.junit.Assert.assertArrayEquals(image, reread.image())
        assertEquals(identity, reread.witness)
        bytes.fill(0)
        org.junit.Assert.assertArrayEquals(image, reread.image())
        val different = SettingsProjectionCodec.fromModel(org.kurdistanvpn.core.model.Phase9Settings(highContrast = true))
        org.junit.Assert.assertThrows(IllegalStateException::class.java) { kotlinx.coroutines.runBlocking {
            SettingsProjectionCodec.toStoredBytes(different, identity)
        } }
        image.fill(0); different.fill(0)
    }

    @Test fun explicitlyOwnedProjectionClosesBeforeIndependentDiskReadAndReopen() = kotlinx.coroutines.runBlocking {
        val directory = java.nio.file.Files.createTempDirectory("settings-owner-").toFile()
        val file = java.io.File(directory, "synthetic.preferences_pb")
        val first = Phase9SettingsStore.openOwnedProjection(file)
        val image = SettingsProjectionCodec.fromModel(org.kurdistanvpn.core.model.Phase9Settings())
        val identity = SettingsProjectionIdentity.capture("01".repeat(16), "02".repeat(32), 2, image)
        first.publishProjection(first.readProjection(), image, identity)
        first.closeOwned()
        first.closeOwned()
        org.junit.Assert.assertThrows(IllegalStateException::class.java) { kotlinx.coroutines.runBlocking { first.readProjection() } }
        val stored = file.readBytes()
        try {
            val independent = SettingsProjectionCodec.fromStoredBytes(stored)
            assertEquals(identity, independent.witness)
            org.junit.Assert.assertArrayEquals(image, independent.image())
        } finally { stored.fill(0) }
        val second = Phase9SettingsStore.openOwnedProjection(file)
        try { assertEquals(identity, second.readProjection().witness) }
        finally { second.closeOwned(); image.fill(0) }
    }

    @Test fun projectionOwnerDoesNotCreateMissingParentOrAcceptRelativePath() {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            Phase9SettingsStore.openOwnedProjection(java.io.File("relative.preferences_pb"))
        }
        val directory = java.nio.file.Files.createTempDirectory("settings-parent-").toFile()
        val missing = java.io.File(directory, "absent")
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            Phase9SettingsStore.openOwnedProjection(java.io.File(missing, "synthetic.preferences_pb"))
        }
        assertFalse(missing.exists())
    }

    @Test fun independentDiskParserReadsLiteralPreferencesWithoutOpeningADataStore() = kotlinx.coroutines.runBlocking {
        // Preferences protobuf: map entry "allow_lan" -> boolean false, calculated independently.
        val raw = "0a0f0a09616c6c6f775f6c616e12020800".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val projection = SettingsProjectionCodec.fromStoredBytes(raw)
        assertFalse(SettingsProjectionCodec.toModel(projection.image()).connection.allowLan)
        assertEquals(null, projection.witness)
        org.junit.Assert.assertThrows(Exception::class.java) { kotlinx.coroutines.runBlocking {
            SettingsProjectionCodec.fromStoredBytes(raw.copyOf(raw.size - 1))
        } }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { kotlinx.coroutines.runBlocking {
            SettingsProjectionCodec.fromStoredBytes(ByteArray(65537))
        } }
        Unit
    }

    @Test fun immutableModelProjectionRejectsNormalizationAndOwnsNestedValues() {
        val favorites = linkedSetOf("profile-one")
        val input = org.kurdistanvpn.core.model.Phase9Settings(
            profiles = org.kurdistanvpn.core.model.ProfilePreferences("profile-one", favorites))
        val encoded = SettingsProjectionCodec.fromModel(input)
        favorites.clear()
        assertEquals(setOf("profile-one"), SettingsProjectionCodec.toModel(encoded).profiles.favoriteLocalRecordIds)
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionCodec.fromModel(input.copy(tunnel = TunnelPreferences(mtu = 7)))
        }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionCodec.fromModel(input.copy(probes = input.probes.copy(testUrl = "  ")))
        }
    }

    @Test fun checkpointSettingsHaveAnIndependentGoldenAndRejectNoncanonicalInput() {
        val value = mutablePreferencesOf(booleanPreferencesKey("allow_lan") to false)
        val encoded = SettingsProjectionCodec.encode(value)
        assertEquals("4b53503101000109616c6c6f775f6c616e0100", encoded.joinToString("") { "%02x".format(it) })
        org.junit.Assert.assertArrayEquals(encoded, SettingsProjectionCodec.encode(SettingsProjectionCodec.decode(encoded)))
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SettingsProjectionCodec.decode(encoded + 0) }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionCodec.encode(mutablePreferencesOf(stringPreferencesKey("unexpected") to "value"))
        }
    }

    @Test fun projectionRejectsImplicitNormalizationAndWrongTypes() {
        for (invalid in listOf(
            mutablePreferencesOf(intPreferencesKey("mtu") to 7),
            mutablePreferencesOf(stringPreferencesKey("ip_mode") to "UNKNOWN"),
            mutablePreferencesOf(stringPreferencesKey("allow_lan") to "true"),
        )) org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SettingsProjectionCodec.encode(invalid) }
    }

    @Test fun projectionWitnessIsBoundToTheOwnedExactImage() {
        val encoded = SettingsProjectionCodec.encode(mutablePreferencesOf(booleanPreferencesKey("allow_lan") to false))
        val witness = SettingsProjectionIdentity.capture("01".repeat(16), "02".repeat(32), 2, encoded)
        assertTrue(witness.matches(encoded))
        encoded[encoded.lastIndex] = 1
        assertFalse(witness.matches(encoded))
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionIdentity.capture("01".repeat(16), "02".repeat(32), 3, encoded)
        }
    }

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
