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

class ProductSettingsCodecTest {
    @Test fun rawModelUsesMigrationDisplayDefaultsWithoutChangingCapturedValues() {
        val values = mutablePreferencesOf(stringPreferencesKey("theme") to "INVALID",
            stringPreferencesKey("high_contrast") to "wrong-type",
            intPreferencesKey("reduced_motion") to 7)
        val raw = RawLegacySettingsImage.capture(values)
        val original = raw.clone()
        val model = SettingsProjectionCodec.toModel(raw)
        assertEquals(org.kurdistanvpn.core.model.ThemePreference.SYSTEM, model.theme)
        assertFalse(model.highContrast)
        assertFalse(model.reducedMotion)
        assertEquals(model, (SettingsMigration.planLegacyImage(raw, null, emptySet(), true) as SettingsMigration.Ready).requested)
        org.junit.Assert.assertArrayEquals(original, raw)
        assertEquals("wrong-type", RawLegacySettingsImage.decode(raw)[stringPreferencesKey("high_contrast")])
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SettingsProjectionCodec.encode(values) }
    }
    @org.junit.Test fun rawMigrationCodecRetainsStrictBoundsAndCanonicalStructure() {
        val raw = RawLegacySettingsImage.capture(androidx.datastore.preferences.core.mutablePreferencesOf(
            androidx.datastore.preferences.core.stringPreferencesKey("theme") to "INVALID"))
        val invalid = listOf(raw.copyOf(raw.size - 1), raw + byteArrayOf(0), raw.clone().also { it[4] = 2 },
            raw.clone().also { it[5] = 0; it[6] = 49 }, ByteArray(65537))
        for (bytes in invalid) org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { RawLegacySettingsImage.decode(bytes) }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            RawLegacySettingsImage.capture(androidx.datastore.preferences.core.mutablePreferencesOf(
                androidx.datastore.preferences.core.intPreferencesKey("mtu") to 0))
        }
    }
    @org.junit.Test fun witnessedRawFormatRoundTripsWithoutBecomingStrictKsp1() = kotlinx.coroutines.runBlocking {
        val raw = RawLegacySettingsImage.capture(androidx.datastore.preferences.core.mutablePreferencesOf(
            androidx.datastore.preferences.core.stringPreferencesKey("theme") to "SYSTEM"))
        val identity = SettingsProjectionIdentity.capture("01".repeat(16), "02".repeat(32), 2, raw)
        val stored = SettingsProjectionCodec.toStoredBytes(raw, identity)
        org.junit.Assert.assertArrayEquals(raw, SettingsProjectionCodec.fromStoredBytes(stored).image())
    }
    @org.junit.Test fun rawMigrationCannotReinterpretMalformedCommittedKsp1OrAuthorityDefaults() = kotlinx.coroutines.runBlocking {
        val values = androidx.datastore.preferences.core.mutablePreferencesOf(
            androidx.datastore.preferences.core.stringPreferencesKey("theme") to "INVALID")
        val raw = RawLegacySettingsImage.capture(values)
        val masquerade = raw.clone().also { java.nio.ByteBuffer.wrap(it).putInt(0x4b535031) }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SettingsProjectionCodec.decode(raw) }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SettingsProjectionCodec.decode(masquerade) }
        val identity = SettingsProjectionIdentity.capture("01".repeat(16), "02".repeat(32), 2,
            SettingsProjectionCodec.fromModel(org.kurdistanvpn.core.model.ProductSettings()))
        identity.writeTo(values)
        val output = java.io.ByteArrayOutputStream()
        androidx.datastore.preferences.core.PreferencesFileSerializer.writeTo(values, output)
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { kotlinx.coroutines.runBlocking {
            SettingsProjectionCodec.captureLegacyStoredBytes(output.toByteArray())
        } }
        val unsafe = androidx.datastore.preferences.core.mutablePreferencesOf(
            androidx.datastore.preferences.core.stringPreferencesKey("dns_mode") to "INVALID")
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { RawLegacySettingsImage.capture(unsafe) }
        Unit
    }
    @org.junit.Test fun projectionOwnerExposesNoUnjournaledPreferenceSettersOrReset() {
        val names = ProductSettingsStore::class.java.methods.map { it.name }
        org.junit.Assert.assertFalse(names.any { it.startsWith("set") || it.startsWith("reset") || it == "clearLegacyRoutingPackages" })
    }
    @Test fun retiredPlatformFlagsRemainOnlyExplicitLegacyResidueAndNeverEnterProductImage() {
        val original = SettingsProjectionCodec.encode(mutablePreferencesOf(
            booleanPreferencesKey("auto_connect_boot") to true,
            booleanPreferencesKey("kill_switch_requested") to true))
        val model = SettingsProjectionCodec.toModel(original)
        val restored = SettingsProjectionCodec.decode(SettingsProjectionCodec.fromModel(model,
            SettingsProjectionCodec.legacyResidue(original)))
        assertEquals(true, restored[booleanPreferencesKey("auto_connect_boot")])
        assertEquals(true, restored[booleanPreferencesKey("kill_switch_requested")])
        val product = ProductSettingsImage.create(model, 1).encode()
        assertFalse(product.toString(Charsets.UTF_8).contains("auto_connect_boot"))
        assertFalse(product.toString(Charsets.UTF_8).contains("kill_switch_requested"))
    }
    @Test fun legacyManualSelectionWithoutIdentityRoundTripsWithoutBecomingAutomatic() {
        val requested = org.kurdistanvpn.core.model.ProductSettings(connection = org.kurdistanvpn.core.model.ConnectionPreferences(
            selectionMode = org.kurdistanvpn.core.model.SelectionMode.MANUAL_STRATEGY))
        val original = SettingsProjectionCodec.fromModel(requested)
        val decoded = SettingsProjectionCodec.toModel(original)
        assertEquals("MANUAL_STRATEGY", SettingsProjectionCodec.decode(original)[stringPreferencesKey("selection_mode")])
        assertEquals(org.kurdistanvpn.core.model.ManualSelectionAvailability.UNAVAILABLE, decoded.connection.manualSelectionAvailability)
        org.junit.Assert.assertArrayEquals(original, SettingsProjectionCodec.fromModel(decoded))
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { decoded.connection.effectiveStrategy(emptySet(), emptySet()) }
    }
    @Test fun inactiveLegacyProbeResidueStillRequiresTheExistingCanonicalWireSyntax() {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionCodec.encode(mutablePreferencesOf(stringPreferencesKey("test_url") to "  "))
        }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionCodec.encode(mutablePreferencesOf(stringPreferencesKey("probe_method") to "HTTP_GET",
                stringPreferencesKey("test_url") to "not-a-url"))
        }
    }
    @Test fun legacyCodecRejectsNewPreferenceValuesRatherThanSilentlyDiscardingThem() {
        val defaults = org.kurdistanvpn.core.model.ProductSettings()
        listOf(
            defaults.copy(privacy = defaults.privacy.copy(collectUsageAggregates = true)),
            defaults.copy(automation = defaults.automation.copy(enabled = true)),
            defaults.copy(localProxy = defaults.localProxy.copy(socksPort = 12000)),
            defaults.copy(tunnelMode = org.kurdistanvpn.core.model.TunnelMode.TUN_PLUS_PROXY),
            defaults.copy(pausePolicy = org.kurdistanvpn.core.model.PausePolicy.UNTIL_RESUMED),
            defaults.copy(connection = defaults.connection.copy(reconnectMaximum = 4)),
            defaults.copy(networkTrust = org.kurdistanvpn.core.model.NetworkTrustPreferences(true)),
        ).forEach { value ->
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SettingsProjectionCodec.fromModel(value) }
        }
    }
    @Test fun legacyProbeResidueStaysInactiveAndSurvivesUnrelatedPreferenceChanges() {
        val values = mutablePreferencesOf(
            stringPreferencesKey("test_url") to "https://example.invalid/legacy-private-path",
            stringPreferencesKey("probe_method") to "HTTP_GET",
            booleanPreferencesKey("high_contrast") to false,
            intPreferencesKey("mtu") to 1400,
        )
        val original = SettingsProjectionCodec.encode(values)
        val model = SettingsProjectionCodec.toModel(original)
        val residue = SettingsProjectionCodec.legacyResidue(original)
        assertEquals(null, model.probes.signedTargetId)
        assertFalse(model.toString().contains("example.invalid"))
        assertFalse(residue.toString().contains("example.invalid"))
        val replacement = SettingsProjectionCodec.fromModel(model.copy(highContrast = true), residue)
        val decoded = SettingsProjectionCodec.decode(replacement)
        assertEquals("https://example.invalid/legacy-private-path", decoded[stringPreferencesKey("test_url")])
        assertEquals("HTTP_GET", decoded[stringPreferencesKey("probe_method")])
        assertEquals(1400, decoded[intPreferencesKey("mtu")])
        assertEquals(true, decoded[booleanPreferencesKey("high_contrast")])
        val merged = SettingsProjectionCodec.preserveLegacyResidue(original, SettingsProjectionCodec.fromModel(model.copy(highContrast = true)))
        org.junit.Assert.assertArrayEquals(replacement, merged)
    }

    @Test fun legacyResolverCategoriesRoundTripWithoutBrandModelsOrChangedBytes() {
        listOf("INTERNAL_TUN", "CLOUDFLARE_GOOGLE", "GOOGLE", "CLOUDFLARE", "QUAD9", "CUSTOM").forEach { legacy ->
            val values = mutablePreferencesOf(stringPreferencesKey("dns_mode") to legacy)
            if (legacy == "CUSTOM") values[stringPreferencesKey("custom_dns")] = "192.0.2.1"
            val model = decodeLegacySettings(values)
            val decoded = SettingsProjectionCodec.decode(SettingsProjectionCodec.fromModel(model))
            assertEquals(legacy, decoded[stringPreferencesKey("dns_mode")])
        }
    }

    @Test fun unrepresentableResolverConfigurationIsRejectedInsteadOfDropped() {
        val defaults = org.kurdistanvpn.core.model.ProductSettings()
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionCodec.fromModel(defaults.copy(tunnel = TunnelPreferences(dnsMode = org.kurdistanvpn.core.model.ResolverPolicy.PROFILE_DEFINED)))
        }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionCodec.fromModel(defaults.copy(tunnel = TunnelPreferences(dnsMode = org.kurdistanvpn.core.model.ResolverPolicy.CUSTOM, customDns = "192.0.2.1", secondaryCustomDns = "192.0.2.2")))
        }
    }

    @Test fun missingRoutePreferenceDoesNotActivateSuggestions() {
        assertTrue(decodeLegacySettings(mutablePreferencesOf()).routing.excludedCidrs.isEmpty())
    }

    @Test fun byteOnlyProjectionSerializationBindsItsImageAndReturnsIndependentOwnedBytes() = kotlinx.coroutines.runBlocking {
        val image = SettingsProjectionCodec.fromModel(org.kurdistanvpn.core.model.ProductSettings())
        val identity = SettingsProjectionIdentity.capture("01".repeat(16), "02".repeat(32), 2, image)
        val bytes = SettingsProjectionCodec.toStoredBytes(image, identity)
        val reread = SettingsProjectionCodec.fromStoredBytes(bytes)
        org.junit.Assert.assertArrayEquals(image, reread.image())
        assertEquals(identity, reread.witness)
        bytes.fill(0)
        org.junit.Assert.assertArrayEquals(image, reread.image())
        val different = SettingsProjectionCodec.fromModel(org.kurdistanvpn.core.model.ProductSettings(highContrast = true))
        org.junit.Assert.assertThrows(IllegalStateException::class.java) { kotlinx.coroutines.runBlocking {
            SettingsProjectionCodec.toStoredBytes(different, identity)
        } }
        image.fill(0); different.fill(0)
    }

    @Test fun explicitlyOwnedProjectionClosesBeforeIndependentDiskReadAndReopen() = kotlinx.coroutines.runBlocking {
        val directory = java.nio.file.Files.createTempDirectory("settings-owner-").toFile().canonicalFile
        val file = java.io.File(directory, "synthetic.preferences_pb")
        val first = ProductSettingsStore.openOwnedProjection(file)
        val image = SettingsProjectionCodec.fromModel(org.kurdistanvpn.core.model.ProductSettings())
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
        val second = ProductSettingsStore.openOwnedProjection(file)
        try { assertEquals(identity, second.readProjection().witness) }
        finally { second.closeOwned(); image.fill(0) }
    }

    @Test fun projectionOwnerDoesNotCreateMissingParentOrAcceptRelativePath() {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            ProductSettingsStore.openOwnedProjection(java.io.File("relative.preferences_pb"))
        }
        val directory = java.nio.file.Files.createTempDirectory("settings-parent-").toFile().canonicalFile
        val missing = java.io.File(directory, "absent")
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            ProductSettingsStore.openOwnedProjection(java.io.File(missing, "synthetic.preferences_pb"))
        }
        assertFalse(missing.exists())
    }

    @Test fun projectionOwnerRejectsAnExistingNoncanonicalParentWithoutCreatingAProjection() {
        val directory = java.nio.file.Files.createTempDirectory("settings-alias-").toFile().canonicalFile
        assertRejectedAlias(java.io.File(directory, "."))
    }

    @Test fun projectionOwnerRejectsActualNtfsShortNameTemporaryRootWhenSupplied() {
        val supplied = java.io.File(checkNotNull(System.getProperty("java.io.tmpdir"))).absoluteFile
        org.junit.Assume.assumeTrue("Requires a real NTFS short-name temp root",
            checkNotNull(System.getProperty("os.name")).startsWith("Windows") &&
                '~' in supplied.path && supplied != supplied.canonicalFile)
        val directory = java.nio.file.Files.createTempDirectory(supplied.toPath(), "settings-short-").toFile()
        assertRejectedAlias(directory)
    }

    private fun assertRejectedAlias(directory: java.io.File) {
        assertTrue(directory.isDirectory)
        assertFalse(directory.absoluteFile == directory.canonicalFile)
        val file = java.io.File(directory, "rejected.preferences_pb")
        var unexpectedOwner: ProductSettingsStore? = null
        try {
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                unexpectedOwner = ProductSettingsStore.openOwnedProjection(file)
            }
        } finally { kotlinx.coroutines.runBlocking { unexpectedOwner?.closeOwned() } }
        assertFalse(file.exists())
        assertFalse(file.canonicalFile.exists())
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
        val input = org.kurdistanvpn.core.model.ProductSettings(
            profiles = org.kurdistanvpn.core.model.ProfilePreferences("profile-one", favorites))
        val encoded = SettingsProjectionCodec.fromModel(input)
        favorites.clear()
        assertEquals(setOf("profile-one"), SettingsProjectionCodec.toModel(encoded).profiles.favoriteLocalRecordIds)
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionCodec.fromModel(input.copy(tunnel = TunnelPreferences(mtu = 7)))
        }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            SettingsProjectionCodec.fromModel(input.copy(probes = input.probes.copy(signedTargetId = org.kurdistanvpn.core.model.CatalogId("probe-1"))))
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
        val decoded = decodeLegacySettings(
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
        val decoded = decodeLegacySettings(
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
