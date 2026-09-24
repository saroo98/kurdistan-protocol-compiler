// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.settings

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import androidx.datastore.preferences.core.*
import kotlinx.coroutines.runBlocking

class SettingsMigrationTest {
    @Test fun malformedAuthorityGroupsCannotEnterPhysicalMigrationOrUseDisplayFallback() = runBlocking {
        val invalid = listOf(
            mutablePreferencesOf(stringPreferencesKey("dns_mode") to "CUSTOM"),
            mutablePreferencesOf(stringPreferencesKey("dns_mode") to "CUSTOM", stringPreferencesKey("custom_dns") to ""),
            mutablePreferencesOf(stringPreferencesKey("dns_mode") to "CUSTOM", stringPreferencesKey("custom_dns") to "invalid"),
            mutablePreferencesOf(stringPreferencesKey("dns_mode") to "INTERNAL_TUN", stringPreferencesKey("custom_dns") to "1.1.1.1"),
            mutablePreferencesOf(stringPreferencesKey("custom_dns") to "1.1.1.1"),
            mutablePreferencesOf(stringPreferencesKey("dns_mode") to "GOOGLE", stringPreferencesKey("custom_dns") to "1.1.1.1"),
            mutablePreferencesOf(stringPreferencesKey("ip_mode") to "INVALID"),
            mutablePreferencesOf(booleanPreferencesKey("ip_mode") to true),
            mutablePreferencesOf(stringPreferencesKey("metered") to "true"),
            mutablePreferencesOf(stringPreferencesKey("dns_mode") to "CUSTOM", stringPreferencesKey("ip_mode") to "IPV6_ONLY", booleanPreferencesKey("metered") to true),
            mutablePreferencesOf(stringPreferencesKey("routing_mode") to "INCLUDE_ONLY", stringSetPreferencesKey("routing_packages") to setOf("bad")),
            mutablePreferencesOf(stringPreferencesKey("routing_mode") to "EXCLUDE_SELECTED", stringSetPreferencesKey("routing_packages") to setOf("bad")),
            mutablePreferencesOf(stringPreferencesKey("routing_mode") to "INVALID"),
            mutablePreferencesOf(booleanPreferencesKey("routing_mode") to true),
            mutablePreferencesOf(stringPreferencesKey("routing_packages") to "private.package"),
            mutablePreferencesOf(stringPreferencesKey("routing_mode") to "ALL_APPS", stringSetPreferencesKey("routing_packages") to setOf("private.package")),
            mutablePreferencesOf(stringSetPreferencesKey("routing_packages") to setOf("private.package")),
            mutablePreferencesOf(stringPreferencesKey("routing_mode") to "INCLUDE_ONLY", stringSetPreferencesKey("routing_packages") to setOf("private.package"),
                stringSetPreferencesKey("excluded_cidrs") to setOf("invalid")),
        )
        for ((index, fields) in invalid.withIndex()) {
            fields[stringPreferencesKey("active_profile")] = "p"
            fields[stringPreferencesKey("theme")] = "SYSTEM"
            assertTrue("planner/$index", SettingsMigration.planLegacy(fields, "p", emptySet(), true) is SettingsMigration.Required)
            assertThrows("strict/$index", IllegalArgumentException::class.java) { SettingsProjectionCodec.encode(fields) }
            val output = java.io.ByteArrayOutputStream(); PreferencesFileSerializer.writeTo(fields, output)
            val source = output.toByteArray(); val original = source.clone()
            assertThrows("physical/$index", IllegalArgumentException::class.java) { runBlocking {
                SettingsProjectionCodec.captureLegacyStoredBytes(source)
            } }
            assertArrayEquals(original, source)
        }
    }

    @Test fun validAuthorityGroupsPreserveExactPolicyAndDocumentedMissingDefaults() {
        assertEquals(ProductSettings(), (SettingsMigration.planLegacy(mutablePreferencesOf(), null, emptySet(), true) as SettingsMigration.Ready).requested)
        for (ip in IpMode.entries) for (metered in listOf(false, true)) {
            val fields = mutablePreferencesOf(stringPreferencesKey("active_profile") to "p", stringPreferencesKey("dns_mode") to "CUSTOM",
                stringPreferencesKey("custom_dns") to "1.1.1.1", stringPreferencesKey("ip_mode") to ip.name,
                booleanPreferencesKey("metered") to metered, stringPreferencesKey("routing_mode") to "INCLUDE_ONLY",
                stringSetPreferencesKey("routing_packages") to setOf("private.package"), stringSetPreferencesKey("excluded_cidrs") to SAFE_EXCLUDED_ROUTES.toSet())
            val ready = SettingsMigration.planLegacy(fields, "p", emptySet(), true) as SettingsMigration.Ready
            assertEquals(ip, ready.requested.tunnel.ipMode); assertEquals(metered, ready.requested.tunnel.metered)
            assertEquals(ResolverPolicy.CUSTOM, ready.requested.tunnel.dnsMode); assertEquals("1.1.1.1", ready.requested.tunnel.customDns)
            assertEquals(PerAppSelectionMode.INCLUDE_ONLY, ready.requested.routing.mode)
            assertEquals(setOf("private.package"), ready.requested.routing.packages)
            assertTrue(ready.requested.routing.excludedCidrs.isEmpty())
        }
        assertTrue(SettingsMigration.planLegacy(mutablePreferencesOf(stringPreferencesKey("routing_mode") to "INCLUDE_ONLY"), null, emptySet(), true) is SettingsMigration.Required)
    }
    @Test fun explicitRawPhysicalMigrationDefaultsDisplayAndRollbackRestoresExactInvalidOwnedValues() = runBlocking {
        val values = mutablePreferencesOf(stringPreferencesKey("theme") to "PRIVATE_INVALID_THEME",
            intPreferencesKey("update_interval_hours") to -9, stringPreferencesKey("high_contrast") to "wrong-type",
            doublePreferencesKey("unrelated-double") to 3.25)
        val output = java.io.ByteArrayOutputStream(); PreferencesFileSerializer.writeTo(values, output)
        val original = output.toByteArray()
        assertThrows(IllegalArgumentException::class.java) { runBlocking { SettingsProjectionCodec.fromStoredBytes(original) } }
        val captured = SettingsProjectionCodec.captureLegacyStoredBytes(original)
        assertTrue(RawLegacySettingsImage.isRaw(captured.image()))
        assertArrayEquals(original, output.toByteArray())
        val decision = SettingsMigration.planLegacyImage(captured.image(), null, emptySet(), true) as SettingsMigration.Ready
        assertEquals(ProductSettings().theme, decision.requested.theme)
        assertEquals(ProductSettings().updates.intervalHours, decision.requested.updates.intervalHours)
        assertFalse(decision.requested.highContrast)
        val file = java.io.File(java.nio.file.Files.createTempDirectory("raw-migration").toFile().canonicalFile, "test.preferences_pb")
        file.writeBytes(original)
        val owner = ProductSettingsStore.openOwnedProjection(file)
        val raw = captured.image()
        try {
            val observed = owner.readLegacyMigrationProjection()
            assertArrayEquals(raw, observed.image())
            val product = ProductSettingsImage.create(decision.requested, 1).encode()
            owner.publishProjection(observed, product, SettingsProjectionIdentity.capture("01".repeat(16), "03".repeat(32), 4, product))
            owner.publishProjection(owner.readProjection(), raw, SettingsProjectionIdentity.capture("01".repeat(16), "04".repeat(32), 6, raw))
        } finally { owner.closeOwned() }
        val restored = file.inputStream().use { PreferencesFileSerializer.readFrom(it) }
        assertEquals(values[stringPreferencesKey("theme")], restored[stringPreferencesKey("theme")])
        assertEquals(-9, restored[intPreferencesKey("update_interval_hours")])
        assertEquals("wrong-type", restored[stringPreferencesKey("high_contrast")])
        assertEquals(3.25, restored[doublePreferencesKey("unrelated-double")]!!, 0.0)
        assertArrayEquals(raw, SettingsProjectionCodec.fromStoredBytes(file.readBytes()).image())
    }
    @Test fun typedSameOperationRecoveryCanRestoreAndRepeatButCannotRebindAnotherOperation() = runBlocking {
        val image = ProductSettingsImage.create(ProductSettings(highContrast = true), 2).encode()
        val identity = SettingsProjectionIdentity.capture("01".repeat(16), "03".repeat(32), 4, image)
        val file = java.io.File(java.nio.file.Files.createTempDirectory("settings-recover").toFile().canonicalFile, "test.preferences_pb")
        file.writeBytes(SettingsProjectionCodec.toStoredBytes(image, identity))
        val restored = ProductSettingsImage.create(ProductSettings(), 1).encode()
        val target = SettingsProjectionIdentity.capture("01".repeat(16), "03".repeat(32), 4, restored)
        val store = ProductSettingsStore.openOwnedProjection(file)
        try {
            assertThrows(IllegalArgumentException::class.java) { runBlocking {
                store.recoverProjection(store.readProjection(), restored,
                    SettingsProjectionIdentity.capture("01".repeat(16), "09".repeat(32), 4, restored))
            } }
            store.recoverProjection(store.readProjection(), restored, target)
            store.recoverProjection(store.readProjection(), restored, target)
        } finally { store.closeOwned() }
        val actual = SettingsProjectionCodec.fromStoredBytes(file.readBytes())
        assertEquals(target, actual.witness); assertArrayEquals(restored, actual.image())
    }
    @Test fun physicalLegacyToProductAndRollbackPreserveUnrelatedDataWhileMovingAllOwnedKeys() = runBlocking {
        val legacy = SettingsProjectionCodec.fromModel(ProductSettings(profiles = ProfilePreferences("private-canary")))
        val preferences = SettingsProjectionCodec.decode(legacy).toMutablePreferences().also {
            it[doublePreferencesKey("unrelated-double")] = 3.25
            SettingsProjectionIdentity.capture("01".repeat(16), "02".repeat(32), 2, legacy).writeTo(it)
        }
        val output = java.io.ByteArrayOutputStream(); PreferencesFileSerializer.writeTo(preferences, output)
        val file = java.io.File(java.nio.file.Files.createTempDirectory("settings-migrate").toFile().canonicalFile, "test.preferences_pb")
        file.writeBytes(output.toByteArray())
        val store = ProductSettingsStore.openOwnedProjection(file)
        val product = ProductSettingsImage.create(ProductSettings(highContrast = true), 1).encode()
        try {
            store.publishProjection(store.readProjection(), product, SettingsProjectionIdentity.capture("01".repeat(16), "03".repeat(32), 4, product))
        } finally { store.closeOwned() }
        val moved = file.inputStream().use { PreferencesFileSerializer.readFrom(it) }
        assertEquals(3.25, moved[doublePreferencesKey("unrelated-double")]!!, 0.0)
        assertFalse(String(file.readBytes(), Charsets.ISO_8859_1).contains("private-canary"))
        val reopened = ProductSettingsStore.openOwnedProjection(file)
        try { reopened.publishProjection(reopened.readProjection(), legacy,
            SettingsProjectionIdentity.capture("01".repeat(16), "04".repeat(32), 6, legacy)) }
        finally { reopened.closeOwned() }
        val restored = file.inputStream().use { PreferencesFileSerializer.readFrom(it) }
        assertEquals(3.25, restored[doublePreferencesKey("unrelated-double")]!!, 0.0)
        assertEquals("private-canary", restored[stringPreferencesKey("active_profile")])
        assertNull(restored[ProductSettingsImage.SCHEMA])
        assertArrayEquals(legacy, SettingsProjectionCodec.fromStoredBytes(file.readBytes()).image())
    }
    @Test fun migrationRequiresAppliedProofAndNeverDropsActiveOwnerOrUnknownAppliedNetworkPolicy() {
        val active = mutablePreferencesOf(stringPreferencesKey("active_profile") to "private-profile",
            stringSetPreferencesKey("favorite_profiles") to setOf("private-profile"))
        assertTrue(SettingsMigration.planLegacy(active, "private-profile", emptySet(), false) is SettingsMigration.Required)
        assertTrue(SettingsMigration.planLegacy(active, null, emptySet(), true) is SettingsMigration.Required)
        for ((key, value) in listOf("selection_mode" to "UNKNOWN", "dns_mode" to "GOOGLE", "ip_mode" to "UNKNOWN")) {
            val values = active.toMutablePreferences().also { it[stringPreferencesKey(key)] = value }
            assertTrue(SettingsMigration.planLegacy(values, "private-profile", emptySet(), true) is SettingsMigration.Required)
        }
        active[stringSetPreferencesKey("excluded_cidrs")] = setOf("10.0.0.0/8")
        assertTrue(SettingsMigration.planLegacy(active, "private-profile", emptySet(), true) is SettingsMigration.Required)
    }

    @Test fun migrationPreservesProtectedPreferencesAndNormalizesOnlyProvenInactiveRouteMarker() {
        val values = mutablePreferencesOf(stringPreferencesKey("active_profile") to "private-profile",
            stringSetPreferencesKey("favorite_profiles") to setOf("private-profile"),
            stringSetPreferencesKey("excluded_cidrs") to SAFE_EXCLUDED_ROUTES.toSet(),
            stringPreferencesKey("routing_mode") to "INCLUDE_ONLY")
        val result = SettingsMigration.planLegacy(values, "private-profile", setOf("private.package"), true) as SettingsMigration.Ready
        assertEquals("private-profile", result.requested.profiles.activeLocalRecordId)
        assertEquals(setOf("private-profile"), result.requested.profiles.favoriteLocalRecordIds)
        assertEquals(setOf("private.package"), result.requested.routing.packages)
        assertEquals(PerAppSelectionMode.INCLUDE_ONLY, result.requested.routing.mode)
        assertTrue(result.requested.routing.excludedCidrs.isEmpty())
        assertEquals(SAFE_EXCLUDED_ROUTES.toSet(), values[stringSetPreferencesKey("excluded_cidrs")])
    }

    @Test fun migrationSafelyDefaultsMalformedDisplayValuesButRetainsEveryValidLegacyEnum() {
        val choices = mapOf("theme" to ThemePreference.entries.map { it.name }, "selection_mode" to SelectionMode.entries.map { it.name },
            "ip_mode" to IpMode.entries.map { it.name }, "routing_mode" to PerAppSelectionMode.entries.map { it.name },
            "probe_method" to ProbeMethod.entries.map { it.name }, "probe_display" to ProbeDisplay.entries.map { it.name },
            "log_level" to DiagnosticLogLevel.entries.map { it.name }, "log_retention" to DiagnosticRetention.entries.map { it.name })
        for ((name, values) in choices) for (value in values) {
            val input = mutablePreferencesOf(stringPreferencesKey(name) to value)
            if (name == "routing_mode" && value != "ALL_APPS") input[stringSetPreferencesKey("routing_packages")] = setOf("private.package")
            val result = SettingsMigration.planLegacy(input, null, emptySet(), true)
            assertTrue("$name/$value", result is SettingsMigration.Ready)
            val requested = (result as SettingsMigration.Ready).requested
            val actual = when (name) {
                "theme" -> requested.theme.name
                "selection_mode" -> requested.connection.selectionMode.name
                "ip_mode" -> requested.tunnel.ipMode.name
                "routing_mode" -> requested.routing.mode.name
                "probe_method" -> requested.probes.method.name
                "probe_display" -> requested.probes.display.name
                "log_level" -> requested.diagnostics.level.name
                else -> requested.diagnostics.retention.name
            }
            assertEquals("$name/$value", value, actual)
        }
        val bad = mutablePreferencesOf(stringPreferencesKey("theme") to "CANARY", stringPreferencesKey("high_contrast") to "CANARY",
            intPreferencesKey("update_interval_hours") to -1)
        val result = SettingsMigration.planLegacy(bad, null, emptySet(), true) as SettingsMigration.Ready
        assertEquals(ThemePreference.SYSTEM, result.requested.theme); assertFalse(result.requested.highContrast)
        assertEquals(UpdatePreferences(), result.requested.updates)
        assertTrue(SettingsMigration.planLegacy(mutablePreferencesOf(), null, emptySet(), true) is SettingsMigration.Ready)
    }
    @Test fun legacyModelEntryPointCannotDefaultAProductImageOrInventMissingReferences() {
        val plain = ProductSettings(highContrast = true)
        assertEquals(plain, SettingsProjectionCodec.toModel(ProductSettingsImage.create(plain, 2).encode()))
        val referenced = ProductSettings(probes = ProbePreferences(signedTargetId = CatalogId("protected-target")))
        val bytes = ProductSettingsImage.create(referenced, 2).encode()
        assertThrows(IllegalArgumentException::class.java) { SettingsProjectionCodec.toModel(bytes) }
    }
    @Test fun actualStoredVersionTwoImagePreservesUnrelatedPreferencesAndExcludesProtectedCanaries() = runBlocking {
        val request = ProductSettings(connection = ConnectionPreferences(SelectionMode.MANUAL_STRATEGY,
            manualStrategyId = CatalogId("secret-strategy-canary")),
            probes = ProbePreferences(signedTargetId = CatalogId("secret-probe-canary")))
        val first = ProductSettingsImage.create(request, 1)
        val image = first.encode()
        val witness = SettingsProjectionIdentity.capture("01".repeat(16), "02".repeat(32), 2, image)
        val preferences = first.preferences().toMutablePreferences().also {
            it[stringPreferencesKey("unrelated_user_preference")] = "preserve-me"
            it[doublePreferencesKey("unrelated_double")] = 1.25
            witness.writeTo(it)
        }
        val out = java.io.ByteArrayOutputStream()
        PreferencesFileSerializer.writeTo(preferences, out)
        val file = java.io.File(java.nio.file.Files.createTempDirectory("settings-image").toFile().canonicalFile, "test.preferences_pb")
        file.writeBytes(out.toByteArray())
        val store = ProductSettingsStore.openOwnedProjection(file)
        try {
            val previous = store.readProjection()
            assertArrayEquals(image, previous.image())
            val replacement = ProductSettingsImage.create(request.copy(highContrast = true), 2).encode()
            val next = SettingsProjectionIdentity.capture("01".repeat(16), "03".repeat(32), 4, replacement)
            store.publishProjection(previous, replacement, next)
        } finally { store.closeOwned() }
        val actual = file.inputStream().use { PreferencesFileSerializer.readFrom(it) }
        assertEquals("preserve-me", actual[stringPreferencesKey("unrelated_user_preference")])
        assertEquals(1.25, actual[doublePreferencesKey("unrelated_double")]!!, 0.0)
        assertFalse(String(file.readBytes(), Charsets.ISO_8859_1).contains("canary"))
        val restored = SettingsProjectionCodec.fromStoredBytes(file.readBytes())
        assertEquals(4L, restored.witness!!.revision)
        val settings = ProductSettingsImage.decode(restored.image())
        assertEquals(2L, settings.revision)
        assertTrue(settings.resolve(SettingsIdentifiers.from(request)).highContrast)
    }
    @Test fun versionTwoRoundTripsCompleteNonsecretRequestAndSemanticRevision() {
        val request = ProductSettings(theme = ThemePreference.DARK, highContrast = true,
            connection = ConnectionPreferences(selectionMode = SelectionMode.MANUAL_STRATEGY,
                manualStrategyId = CatalogId("signed-strategy"), reconnectOnFailure = true, reconnectMaximum = 9),
            tunnel = TunnelPreferences(dnsMode = ResolverPolicy.CUSTOM, customDns = "192.0.2.1",
                secondaryCustomDns = "2001:db8::1", mtu = 1400),
            routing = RoutingPreferences(excludedCidrs = listOf("10.0.0.0/8")),
            updates = UpdatePreferences(intervalHours = 168),
            probes = ProbePreferences(signedTargetId = CatalogId("signed-target"), timeoutSeconds = 30),
            tunnelMode = TunnelMode.TUN_PLUS_PROXY, networkMeteredPolicy = NetworkMeteredPolicy.WAIT_FOR_UNMETERED,
            pausePolicy = PausePolicy.UNTIL_RESUMED, localProxy = LocalProxyPreferences(socksPort = 12000,
                limits = ProxyLimits(memoryMiB = 32)),
            privacy = PrivacyPreferences(collectUsageAggregates = true),
            notifications = NotificationPreferences(showSpeed = true), automation = AutomationPreferences(true))
        val encoded = ProductSettingsImage.create(request, 7).encode()
        val restored = ProductSettingsImage.decode(encoded)
        assertEquals(7L, restored.revision)
        assertEquals(request, restored.resolve(SettingsIdentifiers.from(request)))
        assertArrayEquals(encoded, restored.encode())
        assertEquals(0x4b535032, java.nio.ByteBuffer.wrap(encoded).int)
    }

    @Test fun partialNonsecretProjectionRequiresExactProtectedReferencesAndLeaksNoIds() {
        val request = ProductSettings(connection = ConnectionPreferences(SelectionMode.MANUAL_STRATEGY,
            manualStrategyId = CatalogId("secret-strategy-canary")),
            tunnel = TunnelPreferences(dnsMode = ResolverPolicy.PRESET, resolverCatalogId = CatalogId("secret-resolver-canary")),
            probes = ProbePreferences(signedTargetId = CatalogId("secret-probe-canary")))
        val encoded = ProductSettingsImage.create(request, 3).encode()
        assertFalse(String(encoded, Charsets.ISO_8859_1).contains("canary"))
        val partial = ProductSettingsImage.decode(encoded)
        assertThrows(IllegalArgumentException::class.java) { partial.resolve(SettingsIdentifiers()) }
        assertEquals(request, partial.resolve(SettingsIdentifiers.from(request)))
        assertThrows(IllegalArgumentException::class.java) {
            ProductSettingsImage.decode(ProductSettingsImage.create(ProductSettings(), 1).encode())
                .resolve(SettingsIdentifiers(manualStrategy = CatalogId("unexpected-canary")))
        }
    }

    @Test fun malformedEnumExceptionsAreCategoricalWithoutInputOrCause() {
        val encoded = ProductSettingsImage.create(ProductSettings(), 1).encode()
        val marker = "SYSTEM".toByteArray()
        val index = encoded.indices.first { start -> start + marker.size <= encoded.size &&
            encoded.copyOfRange(start, start + marker.size).contentEquals(marker) }
        "CANARY".toByteArray().copyInto(encoded, index)
        val error = assertThrows(IllegalArgumentException::class.java) { ProductSettingsImage.decode(encoded) }
        assertEquals("MALFORMED_SETTINGS_IMAGE", error.message)
        assertNull(error.cause)
    }

    @Test fun protectedIdentitiesAndRetiredFlagsNeverEnterNonsecretImage() {
        for (request in listOf(
            ProductSettings(profiles = ProfilePreferences(activeLocalRecordId = "private-canary")),
            ProductSettings(profiles = ProfilePreferences(favoriteLocalRecordIds = setOf("private-canary"))),
            ProductSettings(routing = RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY, setOf("private.canary"))),
            ProductSettings(networkTrust = NetworkTrustPreferences(true, setOf(CatalogId("private-canary")))),
        )) assertThrows(IllegalArgumentException::class.java) { ProductSettingsImage.create(request, 1) }
    }

    @Test fun versionTwoRejectsTruncationTrailingBytesWrongVersionAndNonpositiveRevision() {
        val encoded = ProductSettingsImage.create(ProductSettings(), 1).encode()
        for (end in encoded.indices) assertThrows(IllegalArgumentException::class.java) {
            ProductSettingsImage.decode(encoded.copyOf(end))
        }
        assertThrows(IllegalArgumentException::class.java) { ProductSettingsImage.decode(encoded + 0) }
        assertThrows(IllegalArgumentException::class.java) { ProductSettingsImage.decode(encoded.clone().also { it[4] = 3 }) }
        assertThrows(IllegalArgumentException::class.java) { ProductSettingsImage.create(ProductSettings(), 0) }
    }
}
