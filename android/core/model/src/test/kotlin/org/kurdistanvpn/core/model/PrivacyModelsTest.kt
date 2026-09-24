// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.model

import org.junit.Assert.*
import org.junit.Test

class PrivacyModelsTest {
    @Test fun usageCollectionRequiresOptInAndBoundsRetention() {
        assertFalse(PrivacyPreferences().collectUsageAggregates)
        assertThrows(IllegalArgumentException::class.java) { PrivacyPreferences(usageRetentionDays = 0) }
        assertThrows(IllegalArgumentException::class.java) { PrivacyPreferences(usageRetentionDays = 31) }
        assertEquals(30, PrivacyPreferences(collectUsageAggregates = true).usageRetentionDays)
    }

    @Test fun appLockNeverBlocksEmergencyActionsAndCopiesAuthenticatorSet() {
        val input = mutableSetOf(AllowedAuthenticator.DEVICE_CREDENTIAL)
        val value = PrivacyPreferences(appLockEnabled = true, allowedAuthenticators = input)
        input.clear()
        assertTrue(value.requiresUnlock(SensitiveAction.APP_ENTRY))
        assertFalse(value.requiresUnlock(SensitiveAction.DISCONNECT))
        assertFalse(value.requiresUnlock(SensitiveAction.RECOVER_INTERNET))
        assertEquals(setOf(AllowedAuthenticator.DEVICE_CREDENTIAL), value.allowedAuthenticators)
        assertThrows(UnsupportedOperationException::class.java) {
            (value.allowedAuthenticators as MutableSet).clear()
        }
        assertThrows(IllegalArgumentException::class.java) { value.copy(allowedAuthenticators = emptySet()) }
        assertEquals(value, value.copy())
        assertEquals(value.hashCode(), value.copy().hashCode())
    }

    @Test fun automationAlwaysNeedsConfirmationAndImportAlwaysNeedsPreview() {
        assertEquals(ExternalActionDisposition.UNAVAILABLE, AutomationPreferences().disposition(ExternalAction.CONNECT))
        val enabled = AutomationPreferences(enabled = true)
        assertEquals(ExternalActionDisposition.OPEN_PREVIEW, enabled.disposition(ExternalAction.IMPORT))
        ExternalAction.entries.filter { it != ExternalAction.IMPORT }.forEach {
            assertEquals(ExternalActionDisposition.OPEN_CONFIRMATION, enabled.disposition(it))
        }
    }
}
