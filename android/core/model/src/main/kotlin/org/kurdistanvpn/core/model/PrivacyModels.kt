// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.model

import java.util.Collections

enum class AllowedAuthenticator { STRONG_BIOMETRIC, DEVICE_CREDENTIAL }
enum class SensitiveAction { APP_ENTRY, PROFILE_CHANGE, EXPORT, RESET, DISCONNECT, RECOVER_INTERNET }
enum class ExternalAction { CONNECT, DISCONNECT, RECONNECT, IMPORT }
enum class ExternalActionDisposition { UNAVAILABLE, OPEN_CONFIRMATION, OPEN_PREVIEW }

class PrivacyPreferences(
    val collectUsageAggregates: Boolean = false,
    val usageRetentionDays: Int = 30,
    val appLockEnabled: Boolean = false,
    allowedAuthenticators: Set<AllowedAuthenticator> = setOf(AllowedAuthenticator.STRONG_BIOMETRIC),
) {
    val allowedAuthenticators: Set<AllowedAuthenticator> =
        Collections.unmodifiableSet(allowedAuthenticators.toSet())

    init {
        require(usageRetentionDays in 1..30)
        require(!appLockEnabled || this.allowedAuthenticators.isNotEmpty())
    }

    fun requiresUnlock(action: SensitiveAction): Boolean = appLockEnabled && when (action) {
        SensitiveAction.DISCONNECT, SensitiveAction.RECOVER_INTERNET -> false
        else -> true
    }

    fun copy(
        collectUsageAggregates: Boolean = this.collectUsageAggregates,
        usageRetentionDays: Int = this.usageRetentionDays,
        appLockEnabled: Boolean = this.appLockEnabled,
        allowedAuthenticators: Set<AllowedAuthenticator> = this.allowedAuthenticators,
    ): PrivacyPreferences = PrivacyPreferences(
        collectUsageAggregates, usageRetentionDays, appLockEnabled, allowedAuthenticators,
    )

    override fun equals(other: Any?): Boolean = other is PrivacyPreferences &&
        collectUsageAggregates == other.collectUsageAggregates && usageRetentionDays == other.usageRetentionDays &&
        appLockEnabled == other.appLockEnabled && allowedAuthenticators == other.allowedAuthenticators

    override fun hashCode(): Int =
        listOf(collectUsageAggregates, usageRetentionDays, appLockEnabled, allowedAuthenticators).hashCode()

    override fun toString(): String = "PrivacyPreferences(redacted)"
}

data class AutomationPreferences(val enabled: Boolean = false) {
    fun disposition(action: ExternalAction): ExternalActionDisposition = when {
        !enabled -> ExternalActionDisposition.UNAVAILABLE
        action == ExternalAction.IMPORT -> ExternalActionDisposition.OPEN_PREVIEW
        else -> ExternalActionDisposition.OPEN_CONFIRMATION
    }
}
