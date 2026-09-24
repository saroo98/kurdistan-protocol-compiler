// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ProductSettingsTest {
    @Test fun legacyManualRequestIsExplicitlyUnavailableWithoutAnIdentityAndNeverAutomatic() {
        val requested = ConnectionPreferences(selectionMode = SelectionMode.MANUAL_STRATEGY)
        assertEquals(ManualSelectionAvailability.UNAVAILABLE, requested.manualSelectionAvailability)
        assertThrows(IllegalArgumentException::class.java) { requested.effectiveStrategy(emptySet(), emptySet()) }
        assertEquals(SelectionMode.MANUAL_STRATEGY, requested.selectionMode)
    }
    @Test fun uiCollectionsOwnImmutableSnapshotsAndEnrollmentSummariesAreBoundedAndRedacted() {
        val profile = ProfileSummary("local-id", "Private", ProfileTrust.UNAVAILABLE, 1uL, 1)
        val profiles = mutableListOf(profile)
        val ready = AppState.Ready(profiles)
        profiles.clear()
        assertEquals(listOf(profile), ready.profiles)
        assertThrows(UnsupportedOperationException::class.java) { (ready.profiles as MutableList).clear() }
        val key = EnrollmentKeySummary("local-key", "private-fingerprint", 1, 2, 0)
        val keys = mutableListOf(key)
        val request = EnrollmentUiState.RequestReady(keys)
        val awaiting = EnrollmentUiState.AwaitingProfile(keys)
        val verified = EnrollmentUiState.ProfileVerified(keys)
        keys.clear()
        listOf(request.keys, awaiting.keys, verified.keys).forEach {
            assertEquals(listOf(key), it)
            assertThrows(UnsupportedOperationException::class.java) { (it as MutableList).clear() }
        }
        assertEquals(request, request.copy())
        assertEquals(awaiting, awaiting.copy())
        assertEquals(verified, verified.copy())
        assertFalse(key.toString().contains("private"))
        assertThrows(IllegalArgumentException::class.java) { key.copy(localRecordId = "x".repeat(65)) }
        assertThrows(IllegalArgumentException::class.java) { key.copy(requestFingerprint = "x".repeat(257)) }
        assertThrows(IllegalArgumentException::class.java) { key.copy(createdAtEpochSeconds = -1) }
        assertThrows(IllegalArgumentException::class.java) { key.copy(expiresAtEpochSeconds = 0) }
        assertThrows(IllegalArgumentException::class.java) { key.copy(boundProfileCount = -1) }
        assertThrows(IllegalArgumentException::class.java) { key.copy(boundProfileCount = 65) }
        assertThrows(IllegalArgumentException::class.java) { EnrollmentUiState.RequestReady(List(33) { key }) }
        assertThrows(IllegalArgumentException::class.java) { EnrollmentUiState.AwaitingProfile(List(33) { key }) }
        assertThrows(IllegalArgumentException::class.java) { EnrollmentUiState.ProfileVerified(List(33) { key }) }
        assertThrows(IllegalArgumentException::class.java) { AppState.Ready(List(1025) { profile }) }
    }
    @Test fun retainedCompatibilityProjectionsDoNotStringifySensitiveValues() {
        val profile = ProfileSummary("local-id", "private-alias", ProfileTrust.VERIFIED_PRODUCTION, 1uL, 1)
        assertFalse(profile.toString().contains("private-alias"))
        val preview = RedactedProfilePreview("sealed-device", "device", "private-fingerprint", "private-lineage", 1uL, 1, true,
            updateSource = RedactedFieldPresence.PROVIDED_REDACTED)
        assertFalse(preview.toString().contains("private"))
        listOf("private.example", "scheme:value", "path/value", "bad value").forEach { unsafe ->
            assertThrows(IllegalArgumentException::class.java) { preview.copy(artifactClass = unsafe) }
            assertThrows(IllegalArgumentException::class.java) { preview.copy(audienceClass = unsafe) }
            assertThrows(IllegalArgumentException::class.java) { preview.copy(contentFingerprint = unsafe) }
            assertThrows(IllegalArgumentException::class.java) { preview.copy(lineageFingerprint = unsafe) }
            assertThrows(IllegalArgumentException::class.java) { preview.copy(deploymentFingerprint = unsafe) }
        }
        val modules = BooleanArray(21 * 21)
        val qr = QrDisplayMatrix(21, modules)
        modules[0] = true
        assertFalse(qr.modules[0])
        qr.modules[0] = true
        assertFalse(qr.modules[0])
        assertEquals(qr, qr.copy())
        val event = DiagnosticEvent(1, DiagnosticLogLevel.INFO, DiagnosticComponent.APP, "SAFE_EVENT", sessionAlias = "private-session")
        assertFalse(event.toString().contains("private-session"))
    }
    @Test fun connectionRequestsNeverWidenSignedStrategyOrReconnectAuthority() {
        val id = CatalogId("strategy-1")
        val request = ConnectionPreferences(selectionMode = SelectionMode.MANUAL_STRATEGY,
            manualStrategyId = id, reconnectOnFailure = true, reconnectMaximum = 8)
        assertEquals(StrategySelection.Manual(id), request.effectiveStrategy(setOf(id), setOf(id)))
        assertThrows(IllegalArgumentException::class.java) { request.effectiveStrategy(setOf(id), emptySet()) }
        assertEquals(2, request.reconnectPolicy.effectiveMaximum(3, 2))
        assertThrows(IllegalArgumentException::class.java) { request.copy(reconnectMaximum = 11) }
    }
    @Test fun authoritativeConstructorsRejectInvalidBoundsAndRoutingAuthorityIsNarrowed() {
        assertThrows(IllegalArgumentException::class.java) { TunnelPreferences(mtu = 1) }
        assertThrows(IllegalArgumentException::class.java) { UpdatePreferences(intervalHours = 169) }
        assertThrows(IllegalArgumentException::class.java) { ExpertPreferences(idleTimeoutSeconds = 29) }
        assertThrows(IllegalArgumentException::class.java) { RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY).validated() }
        val desired = RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY, setOf("org.example.app"))
        assertThrows(IllegalArgumentException::class.java) { desired.effective(256, emptySet(), emptySet()) }
        assertThrows(IllegalArgumentException::class.java) { desired.effective(0, desired.packages, emptySet()) }
        assertEquals(desired, desired.effective(1, desired.packages, emptySet()))
    }
    @Test fun collectionInputsAndCopiesCannotMutateSettingsOrExposeIdentifiers() {
        val packages = mutableSetOf("org.example.app")
        val routes = mutableListOf("10.0.0.0/8")
        val routing = RoutingPreferences(PerAppSelectionMode.EXCLUDE_SELECTED, packages, routes)
        packages.clear(); routes.clear()
        assertEquals(setOf("org.example.app"), routing.packages)
        assertEquals(listOf("10.0.0.0/8"), routing.excludedCidrs)
        assertThrows(UnsupportedOperationException::class.java) { (routing.packages as MutableSet).clear() }
        assertThrows(UnsupportedOperationException::class.java) { (routing.excludedCidrs as MutableList).clear() }
        assertEquals(routing, routing.copy())
        assertFalse(routing.toString().contains("org.example"))
        val favorites = mutableSetOf("private-profile")
        val profiles = ProfilePreferences("private-profile", favorites)
        favorites.clear()
        assertEquals(setOf("private-profile"), profiles.favoriteLocalRecordIds)
        assertThrows(UnsupportedOperationException::class.java) { (profiles.favoriteLocalRecordIds as MutableSet).clear() }
        assertEquals(profiles, profiles.copy())
        assertFalse(profiles.toString().contains("private-profile"))
    }
    @Test
    fun protectedStateMigrationNeedsCurrentExplicitConfirmation() {
        val initial = ProtectedStateMigrationConfirmation.UNCONFIRMED
        assertEquals(false, initial.permitsMigration(available = true))
        assertEquals(initial, initial.prepare(available = false))
        val prepared = initial.prepare(available = true)
        assertEquals(ProtectedStateMigrationConfirmation.PREPARED, prepared)
        assertEquals(false, prepared.permitsMigration(available = false))
        assertEquals(true, prepared.permitsMigration(available = true))
        // UI consumes/cancels the prompt before invoking the mutation callback.
        assertEquals(false, prepared.cancel().permitsMigration(available = true))
        assertEquals(initial, prepared.cancel())
    }

    @Test
    fun protectedRecoveryExposesOnlyTheBrokerBackedPresentationAction() {
        val recoverable = ProtectedRecoveryPresentation.Required(
            reason = ProtectedRecoveryReason.RECOVERY_REQUIRED,
            action = ProtectedRecoveryAction.RECOVER_PRESENTATION,
        )
        assertEquals(true, recoverable.canRecoverPresentation)

        listOf(
            ProtectedRecoveryReason.QUARANTINED,
            ProtectedRecoveryReason.INCONSISTENT,
            ProtectedRecoveryReason.CLEANUP_UNPROVEN,
            ProtectedRecoveryReason.MUTATION_UNPROVEN,
        ).forEach { reason ->
            val status = ProtectedRecoveryPresentation.Required(reason)
            assertEquals(false, status.canRecoverPresentation)
            assertThrows(IllegalArgumentException::class.java) {
                ProtectedRecoveryPresentation.Required(reason, ProtectedRecoveryAction.RECOVER_PRESENTATION)
            }
        }
    }

    @Test
    fun protectedRecoveryConfirmationIsCurrentExplicitAndCancellable() {
        val unavailable = ProtectedRecoveryPresentation.Required(ProtectedRecoveryReason.QUARANTINED)
        val available = ProtectedRecoveryPresentation.Required(
            ProtectedRecoveryReason.RECOVERY_REQUIRED,
            ProtectedRecoveryAction.RECOVER_PRESENTATION,
        )
        val initial = ProtectedRecoveryConfirmation.UNCONFIRMED
        assertEquals(initial, initial.prepare(unavailable))
        val prepared = initial.prepare(available)
        assertEquals(ProtectedRecoveryConfirmation.PREPARED, prepared)
        assertEquals(true, prepared.permits(available))
        assertEquals(false, prepared.permits(unavailable))
        assertEquals(initial, prepared.cancel())
    }

    @Test
    fun pendingCredentialResetIsSeparateAndPreservesExistingScopeIdentities() {
        assertEquals(listOf("SETTINGS", "PROFILES_AND_TRUST", "ROUTING", "DIAGNOSTICS", "EVERYTHING"),
            ResetScope.entries.take(5).map { it.name })
        assertEquals("PENDING_CREDENTIALS", ResetScope.PENDING_CREDENTIALS.name)
        assertEquals(ResetScope.PENDING_CREDENTIALS, ResetScope.valueOf("PENDING_CREDENTIALS"))
        assertEquals(7, ResetScope.entries.size)
        assertEquals(OperationError.AUTHORITY_UNAVAILABLE, ResetScope.LOCAL_CREDENTIALS.unavailableReason)
        assertEquals(null, ResetScope.PENDING_CREDENTIALS.unavailableReason)
        assertTrue(ResetScope.entries.filter { it.unavailableReason == null }.none { it == ResetScope.LOCAL_CREDENTIALS })
    }

    @Test
    fun defaultsAreValidAndPrivacyPreserving() {
        val value = ProductSettings().validated()
        assertEquals(ResolverPolicy.INTERNAL, value.tunnel.dnsMode)
        assertEquals(PerAppSelectionMode.ALL_APPS, value.routing.mode)
        assertEquals(false, value.updates.automatic)
        assertEquals(null, value.probes.signedTargetId)
        assertEquals(DiagnosticLogLevel.WARNING, value.diagnostics.level)
    }

    @Test
    fun routeSuggestionsHaveNoActiveEffectUntilExplicitlyChosen() {
        assertTrue(RoutingPreferences().validated().excludedCidrs.isEmpty())
        assertTrue(SAFE_EXCLUDED_ROUTES.isNotEmpty())
    }

    @Test
    fun productionPreferencesDefaultToNoUnattendedOrAuxiliaryActivity() {
        val value = ProductSettings()
        assertEquals(TunnelMode.TUN_ONLY, value.tunnelMode)
        assertEquals(NetworkMeteredPolicy.ASK, value.networkMeteredPolicy)
        assertEquals(PausePolicy.NOT_PAUSED, value.pausePolicy)
        assertEquals(false, value.privacy.collectUsageAggregates)
        assertEquals(false, value.automation.enabled)
        assertEquals(10808, value.localProxy.socksPort)
        assertEquals(false, value.notifications.showSpeed)
        assertEquals(value, value.copy())
    }

    @Test
    fun customDnsRequiresAnIpLiteral() {
        assertThrows(IllegalArgumentException::class.java) {
            TunnelPreferences(dnsMode = ResolverPolicy.CUSTOM, customDns = "resolver.example").validated()
        }
        assertEquals(
            "1.1.1.1",
            TunnelPreferences(dnsMode = ResolverPolicy.CUSTOM, customDns = " 1.1.1.1 ")
                .validated().customDns,
        )
        assertEquals(
            "2001:db8::1",
            TunnelPreferences(dnsMode = ResolverPolicy.CUSTOM, customDns = "2001:0DB8:0:0:0:0:0:1")
                .validated().customDns,
        )
        listOf("1.2.3.01", "2001:::1", "gggg::1", "fe80::1%wlan0", "[2001:db8::1]").forEach { invalid ->
            val failure = assertThrows(SettingsValidationException::class.java) {
                TunnelPreferences(dnsMode = ResolverPolicy.CUSTOM, customDns = invalid).validated()
            }
            assertEquals(SettingsField.CUSTOM_DNS, failure.field)
        }
    }

    @Test
    fun routingRejectsInvalidOrAmbiguousPolicies() {
        assertThrows(IllegalArgumentException::class.java) {
            RoutingPreferences(packages = setOf("org.example.app")).validated()
        }
        assertThrows(IllegalArgumentException::class.java) {
            RoutingPreferences(mode = PerAppSelectionMode.INCLUDE_ONLY).validated()
        }
        assertThrows(IllegalArgumentException::class.java) {
            RoutingPreferences(excludedCidrs = listOf("192.168.0.0/99")).validated()
        }
        assertEquals(
            listOf("192.168.0.0/24", "2001:db8::/32"),
            RoutingPreferences(
                excludedCidrs = listOf("192.168.0.42/24", "2001:0db8:1234::1/32"),
            ).validated().excludedCidrs,
        )
    }

    @Test
    fun unsafeResourceBoundsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            ExpertPreferences(memoryLimitMb = 20).validated()
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProbePreferences(timeoutSeconds = 0).validated()
        }
        assertThrows(IllegalArgumentException::class.java) {
            UpdatePreferences(intervalHours = 0).validated()
        }
    }

    @Test fun probesRequireSignedTargetAndIntersectMethods() {
        val id = CatalogId("probe-1")
        val value = ProbePreferences(signedTargetId = id)
        assertEquals(value, value.validatedAgainst(setOf(id), setOf(ProbeMethod.KURD_SESSION), setOf(ProbeMethod.KURD_SESSION)))
        assertThrows(IllegalArgumentException::class.java) { value.validatedAgainst(emptySet(), setOf(ProbeMethod.KURD_SESSION), setOf(ProbeMethod.KURD_SESSION)) }
        assertThrows(IllegalArgumentException::class.java) { value.validatedAgainst(setOf(id), setOf(ProbeMethod.KURD_SESSION), emptySet()) }
    }

    @Test
    fun validationFailuresIdentifyTheExactSettingsField() {
        val failure = assertThrows(SettingsValidationException::class.java) {
            RoutingPreferences(
                mode = PerAppSelectionMode.INCLUDE_ONLY,
                packages = emptySet(),
            ).validated()
        }
        assertEquals(SettingsField.ROUTING_PACKAGES, failure.field)
        assertEquals("EMPTY_INCLUDE_SET", failure.category)
        assertTrue(failure.message.orEmpty().contains("ROUTING_PACKAGES"))
    }
}
