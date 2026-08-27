// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ProductSettingsTest {
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
        assertEquals(listOf("SETTINGS", "PROFILES_PROVIDERS", "ROUTING", "DIAGNOSTICS", "EVERYTHING"),
            ResetScope.entries.take(5).map { it.name })
        assertEquals("PENDING_CREDENTIALS", ResetScope.PENDING_CREDENTIALS.name)
        assertEquals(ResetScope.PENDING_CREDENTIALS, ResetScope.valueOf("PENDING_CREDENTIALS"))
        assertEquals(6, ResetScope.entries.size)
    }

    @Test
    fun defaultsAreValidAndPrivacyPreserving() {
        val value = Phase9Settings().validated()
        assertEquals(DnsMode.INTERNAL_TUN, value.tunnel.dnsMode)
        assertEquals(PerAppSelectionMode.ALL_APPS, value.routing.mode)
        assertEquals(false, value.updates.automatic)
        assertEquals("", value.probes.testUrl)
        assertEquals(DiagnosticLogLevel.WARNING, value.diagnostics.level)
    }

    @Test
    fun customDnsRequiresAnIpLiteral() {
        assertThrows(IllegalArgumentException::class.java) {
            TunnelPreferences(dnsMode = DnsMode.CUSTOM, customDns = "resolver.example").validated()
        }
        assertEquals(
            "1.1.1.1",
            TunnelPreferences(dnsMode = DnsMode.CUSTOM, customDns = " 1.1.1.1 ")
                .validated().customDns,
        )
        assertEquals(
            "2001:db8::1",
            TunnelPreferences(dnsMode = DnsMode.CUSTOM, customDns = "2001:0DB8:0:0:0:0:0:1")
                .validated().customDns,
        )
        listOf("1.2.3.01", "2001:::1", "gggg::1", "fe80::1%wlan0", "[2001:db8::1]").forEach { invalid ->
            val failure = assertThrows(SettingsValidationException::class.java) {
                TunnelPreferences(dnsMode = DnsMode.CUSTOM, customDns = invalid).validated()
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
