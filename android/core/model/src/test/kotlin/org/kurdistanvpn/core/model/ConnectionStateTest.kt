// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

import org.junit.Assert.*
import org.junit.Test

class ConnectionStateTest {
    @Test fun productFailureOrdinalsRemainAppendOnly() {
        val prefix = listOf(
            "INVALID_INPUT", "SIZE_LIMIT", "PROFILE_UNTRUSTED", "PROFILE_EXPIRED", "PROFILE_REVOKED",
            "PROFILE_ROLLBACK", "PROFILE_WRONG_DEVICE", "PROFILE_INCOMPATIBLE", "STORAGE_LOCKED",
            "STORAGE_KEY_INVALIDATED", "STORAGE_DEGRADED", "MIGRATION_REQUIRED", "VPN_CONSENT_REQUIRED",
            "VPN_CONSENT_DENIED", "NETWORK_UNAVAILABLE", "NETWORK_IDENTITY_UNAVAILABLE", "CAPTIVE_PORTAL",
            "NODE_UNREACHABLE", "SESSION_AUTHENTICATION_FAILED", "NO_PERMITTED_STRATEGY",
            "SOCKET_PROTECTION_FAILED", "TUN_ESTABLISH_FAILED", "ROUTE_POLICY_REJECTED",
            "DNS_POLICY_REJECTED", "DNS_HEALTH_FAILED", "APP_POLICY_DRIFT", "FOREGROUND_START_BLOCKED",
            "RECONNECT_EXHAUSTED", "UPDATE_SIGNATURE_INVALID", "UPDATE_ROLLBACK", "UPDATE_INCOMPATIBLE",
            "PROXY_BIND_FAILED", "PROXY_AUTHENTICATION_FAILED", "LOW_MEMORY", "THERMAL_LIMIT",
            "CANCELLED", "INTERNAL_FAILURE", "OPERATION_ALREADY_ACTIVE", "OPERATION_INTERRUPTED",
        )
        assertEquals(prefix, ProductFailureCode.entries.take(prefix.size).map { it.name })
        assertEquals(
            listOf("RESOURCE_LIMIT", "RATE_LIMITED", "OPERATION_TIMED_OUT", "UPDATE_FETCH_REJECTED"),
            ProductFailureCode.entries.drop(prefix.size).map { it.name },
        )
    }

    @Test fun newFailureActionsRemainCategorical() {
        assertEquals(ProductAction.RETRY, ProductFailure(ProductFailureCode.RESOURCE_LIMIT).nextAction)
        assertEquals(ProductAction.DISMISS, ProductFailure(ProductFailureCode.RATE_LIMITED).nextAction)
        assertEquals(ProductAction.RETRY, ProductFailure(ProductFailureCode.OPERATION_TIMED_OUT).nextAction)
        assertEquals(ProductAction.RETRY, ProductFailure(ProductFailureCode.UPDATE_FETCH_REJECTED).nextAction)
    }

    @Test fun everyConnectionVariantHasSafeRecreationAndResourceMetadata() {
        val id = CatalogId("profile-1")
        val route = VerifiedRouteSnapshot(id, IpMode.IPV4_ONLY, 1280)
        val states = listOf(
            ConnectionState.NoProfile,
            ConnectionState.StorageBlocked(StorageBlockReason.LOCKED),
            ConnectionState.Disconnected(ReadyContext(id)),
            ConnectionState.AwaitingVpnPermission,
            ConnectionState.Preparing(AttemptSummary(1)),
            ConnectionState.Connecting(AttemptSummary(1)),
            ConnectionState.Connected(route),
            ConnectionState.Degraded(route, DegradationReason.HEALTH),
            ConnectionState.FallingBack(FallbackProgress(1, 2)),
            ConnectionState.Reconnecting(ReconnectProgress(1, 3)),
            ConnectionState.Stopping,
            ConnectionState.Recovering(RecoveryProgress(RecoveryReason.PROCESS_RECREATION)),
            ConnectionState.Revoked(RevocationSummary(RevocationReason.PROFILE)),
            ConnectionState.PolicyBlocked(PolicyBlockReason.NO_PERMITTED_STRATEGY),
            ConnectionState.Failed(ProductFailure(ProductFailureCode.INTERNAL_FAILURE)),
            ConnectionState.SafeMode(SafeModeSummary(SafeModeReason.REPEATED_FAILURE)),
        )
        assertEquals(ConnectionCategory.entries.toSet(), states.map { it.category }.toSet())
        states.forEach { state ->
            val metadata = state.metadata
            assertEquals(ProductText.ConnectionTitle(state.category), metadata.title)
            assertEquals(ProductText.ConnectionExplanation(state.category), metadata.explanation)
            assertFalse(metadata.primaryAction in metadata.disabledActions)
            assertEquals(PersistencePolicy.NEVER_PERSIST_AUTHORITY, metadata.persistence)
            val restored = state.processRecreated()
            assertEquals(
                when (state) {
                    is ConnectionState.NoProfile, is ConnectionState.StorageBlocked,
                    is ConnectionState.Disconnected, is ConnectionState.Revoked,
                    is ConnectionState.PolicyBlocked, is ConnectionState.Failed, is ConnectionState.SafeMode -> state
                    else -> ConnectionState.Recovering(RecoveryProgress(RecoveryReason.PROCESS_RECREATION))
                },
                restored,
            )
        }
        assertTrue(ProductAction.CONNECT in ConnectionState.Connected(route).metadata.disabledActions)
        assertEquals(ProductAction.NONE, ConnectionState.Stopping.metadata.secondaryAction)
        assertTrue(ProductAction.RECOVER_INTERNET in ConnectionState.Stopping.metadata.disabledActions)
        assertEquals(ProductAction.RECOVER_INTERNET, ConnectionState.SafeMode(SafeModeSummary(SafeModeReason.REPEATED_FAILURE)).metadata.primaryAction)
    }

    @Test fun progressRejectsUnsafeBoundsAndSnapshotNeverStringifiesProfile() {
        assertThrows(IllegalArgumentException::class.java) { AttemptSummary(0) }
        assertThrows(IllegalArgumentException::class.java) { ReconnectProgress(4, 3) }
        assertThrows(IllegalArgumentException::class.java) { FallbackProgress(1, 0) }
        val route = VerifiedRouteSnapshot(CatalogId("private-profile"), IpMode.IPV4_ONLY, 1280)
        assertFalse(ConnectionState.Connected(route).toString().contains("private-profile"))
        assertEquals(route, route.copy())
    }

    @Test fun failureCannotRetainExceptionTextAndEveryCodeHasTypedLocalizedCopy() {
        ProductFailureCode.entries.forEach { code ->
            val failure = ProductFailure(code)
            assertEquals(ProductText.FailureTitle(code), failure.title)
            assertEquals(ProductText.FailureExplanation(code), failure.explanation)
            assertNotNull(failure.nextAction)
            assertEquals(failure, failure.copy())
            assertFalse(failure.toString().contains(code.name))
            val state = ConnectionState.Failed(failure)
            assertEquals(state, state.processRecreated())
            assertEquals(failure.nextAction, state.metadata.primaryAction)
            assertEquals(ProductAction.NONE, state.metadata.secondaryAction)
        }
        StorageBlockReason.entries.forEach { reason ->
            val state = ConnectionState.StorageBlocked(reason)
            assertEquals(state, state.processRecreated())
            assertEquals(if (reason == StorageBlockReason.LOCKED) ProductAction.UNLOCK_STORAGE else ProductAction.OPEN_SETTINGS, state.metadata.primaryAction)
        }
    }
}
