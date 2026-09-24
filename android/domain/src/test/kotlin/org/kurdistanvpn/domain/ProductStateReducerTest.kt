// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class ProductStateReducerTest {
    private val binding = RuntimeBinding(CatalogId("profile-a"), 7u, 3, 4, 5)
    private val session = SessionObservation(binding, CatalogId("session-a"))
    private val route = VerifiedRouteSnapshot(binding.profileId, IpMode.IPV4_ONLY, 1280)
    private fun healthy() = ProductStateInput(
        ProfileProjection(binding.profileId, SafeAlias("Local profile"), 7u, 1000, ProjectionStatus.VERIFIED),
        900, StorageHealth.AVAILABLE, session, setOf(NativeLifecycle.CONNECTED), session, session,
        session, session, 4, 4, route, currentActiveBinding = binding,
    )
    private val reducer = ProductStateReducer()

    @Test fun connectedRequiresEveryIndependentLiveWitness() {
        assertEquals(ConnectionState.Connected(route), reducer.reduce(healthy()))
        listOf(
            healthy().copy(profile = null),
            healthy().copy(storage = StorageHealth.LOCKED),
            healthy().copy(nativeSignals = emptySet()),
            healthy().copy(nativeSession = null),
            healthy().copy(tunSession = null),
            healthy().copy(routeSession = null),
            healthy().copy(dnsSession = null),
            healthy().copy(appliedRouteRevision = null),
            healthy().copy(appliedDnsRevision = null),
            healthy().copy(appliedRouteRevision = 3),
            healthy().copy(appliedDnsRevision = 3),
            healthy().copy(route = null),
        ).forEach { assertFalse(reducer.reduce(it) is ConnectionState.Connected) }
    }

    @Test fun allSixtyFourProtectionPredicateCombinationsRequireAllSixFacts() {
        for (mask in 0..63) {
            val input = healthy().copy(
                profile = healthy().profile!!.copy(status = if (mask and 1 != 0) ProjectionStatus.VERIFIED else ProjectionStatus.UNAVAILABLE),
                storage = if (mask and 2 != 0) StorageHealth.AVAILABLE else StorageHealth.LOCKED,
                nativeSignals = if (mask and 4 != 0) setOf(NativeLifecycle.CONNECTED) else emptySet(),
                tunSession = if (mask and 8 != 0) session else null,
                appliedRouteRevision = if (mask and 16 != 0) 4 else null,
                appliedDnsRevision = if (mask and 32 != 0) 4 else null,
            )
            assertEquals("predicate mask $mask", mask == 63, reducer.reduce(input) is ConnectionState.Connected)
        }
    }

    @Test fun profileAndPermissionAbsenceAndCleanStopHaveTruthfulNonLiveStates() {
        assertEquals(ConnectionState.NoProfile, reducer.reduce(healthy().copy(profile = null)))
        assertEquals(ConnectionState.AwaitingVpnPermission, reducer.reduce(healthy().copy(awaitingVpnPermission = true)))
        assertEquals(ConnectionState.Disconnected(ReadyContext(binding.profileId)), reducer.reduce(healthy().copy(
            nativeSignals = setOf(NativeLifecycle.STOPPED), tunSession = null, routeSession = null, dnsSession = null)))
    }

    @Test fun staleOrDifferentSessionProfileAndTrustNeverProveConnection() {
        val other = session.copy(sessionId = CatalogId("old-session"))
        val stale = session.copy(binding = binding.copy(trustRevision = 2))
        listOf(other, stale).forEach { witness ->
            listOf(healthy().copy(nativeSession = witness), healthy().copy(tunSession = witness),
                healthy().copy(routeSession = witness), healthy().copy(dnsSession = witness))
                .forEach { assertFalse(reducer.reduce(it) is ConnectionState.Connected) }
        }
        assertFalse(reducer.reduce(healthy().copy(route = route.copy(profileId = CatalogId("other")))) is ConnectionState.Connected)
        assertFalse(reducer.reduce(healthy().copy(profile = healthy().profile!!.copy(generation = 6u))) is ConnectionState.Connected)
    }

    @Test fun verifiedButInactiveProfileCannotProveConnectedOrDegraded() {
        for (signal in listOf(NativeLifecycle.CONNECTED, NativeLifecycle.DEGRADED)) {
            assertTrue(reducer.reduce(healthy().copy(nativeSignals = setOf(signal), currentActiveBinding = null)) is ConnectionState.SafeMode)
            assertTrue(reducer.reduce(healthy().copy(nativeSignals = setOf(signal),
                currentActiveBinding = binding.copy(profileId = CatalogId("new-active-profile")))) is ConnectionState.SafeMode)
        }
    }

    @Test fun uniformlyStaleMatchingSessionFactsCannotOverrideCurrentActiveRevisions() {
        val currentBindings = listOf(
            binding.copy(profileGeneration = 8u), binding.copy(trustRevision = 4),
            binding.copy(settingsRevision = 5), binding.copy(packageRevision = 6),
            RuntimeBinding(binding.profileId, 8u, 4, 5, 6),
        )
        for (current in currentBindings) {
            for (signal in listOf(NativeLifecycle.CONNECTED, NativeLifecycle.DEGRADED)) {
                // Profile, expected session, all four witnesses and both applied revisions stay old.
                val input = healthy().copy(nativeSignals = setOf(signal), currentActiveBinding = current)
                assertTrue(reducer.reduce(input) is ConnectionState.SafeMode)
            }
        }
    }

    @Test fun freshlyReconciledSessionCanMatchAdvancedIndependentActiveBinding() {
        val current = RuntimeBinding(binding.profileId, 8u, 4, 5, 6)
        val fresh = SessionObservation(current, CatalogId("fresh-session"))
        val input = healthy().copy(profile = healthy().profile!!.copy(generation = 8u),
            currentActiveBinding = current, expectedSession = fresh, nativeSession = fresh,
            tunSession = fresh, routeSession = fresh, dnsSession = fresh,
            appliedRouteRevision = 5, appliedDnsRevision = 5)
        assertEquals(ConnectionState.Connected(route), reducer.reduce(input))
    }

    @Test fun revokedTrustPreemptsStorageStopRecoveryAndConnected() {
        val input = healthy().copy(profile = healthy().profile!!.copy(status = ProjectionStatus.REVOKED),
            storage = StorageHealth.LOCKED, stopping = true, recovering = true)
        assertTrue(reducer.reduce(input) is ConnectionState.Revoked)
        assertTrue(reducer.reduce(healthy().copy(nativeSignals = setOf(NativeLifecycle.REVOKED, NativeLifecycle.CONNECTED))) is ConnectionState.Revoked)
    }

    @Test fun expiryAndUntrustedProfilesCannotBeConnected() {
        assertTrue(reducer.reduce(healthy().copy(nowEpochSeconds = 1000)) is ConnectionState.Failed)
        for (status in listOf(ProjectionStatus.UNAVAILABLE, ProjectionStatus.EXPIRED, ProjectionStatus.INCOMPATIBLE)) {
            assertTrue(reducer.reduce(healthy().copy(profile = healthy().profile!!.copy(status = status))) is ConnectionState.Failed)
        }
    }

    @Test fun conflictingLifecycleSignalsAreFailClosedButStopAndRecoveryPreempt() {
        for (signal in NativeLifecycle.entries.filter { it !in setOf(NativeLifecycle.CONNECTED, NativeLifecycle.REVOKED) }) {
            val input = healthy().copy(nativeSignals = setOf(NativeLifecycle.CONNECTED, signal))
            assertTrue(reducer.reduce(input) is ConnectionState.SafeMode)
            assertEquals(ConnectionState.Stopping, reducer.reduce(input.copy(stopping = true)))
            assertTrue(reducer.reduce(input.copy(recovering = true)) is ConnectionState.Recovering)
        }
    }

    @Test fun storageStatesMapWithoutClaimingProtection() {
        val expectations = mapOf(StorageHealth.LOCKED to StorageBlockReason.LOCKED,
            StorageHealth.KEY_INVALIDATED to StorageBlockReason.KEY_INVALIDATED,
            StorageHealth.DEGRADED to StorageBlockReason.DEGRADED,
            StorageHealth.QUARANTINED to StorageBlockReason.DEGRADED)
        expectations.forEach { (storage, reason) ->
            assertEquals(ConnectionState.StorageBlocked(reason), reducer.reduce(healthy().copy(storage = storage)))
        }
    }

    @Test fun lifecyclePresentationDoesNotInventLiveProof() {
        assertTrue(reducer.reduce(healthy().copy(nativeSignals = setOf(NativeLifecycle.CONNECTING))) is ConnectionState.Connecting)
        assertTrue(reducer.reduce(healthy().copy(nativeSignals = setOf(NativeLifecycle.RECONNECTING))) is ConnectionState.Reconnecting)
        assertTrue(reducer.reduce(healthy().copy(nativeSignals = setOf(NativeLifecycle.FALLING_BACK))) is ConnectionState.FallingBack)
        assertTrue(reducer.reduce(healthy().copy(nativeSignals = setOf(NativeLifecycle.FAILED))) is ConnectionState.Failed)
        assertTrue(reducer.reduce(healthy().copy(nativeSignals = setOf(NativeLifecycle.DEGRADED))) is ConnectionState.Degraded)
        assertFalse(reducer.reduce(healthy().copy(nativeSignals = setOf(NativeLifecycle.DEGRADED), tunSession = null)) is ConnectionState.Degraded)
    }

    @Test fun lifecycleInputIsAnImmutableSnapshotIncludingCopies() {
        val signals = mutableSetOf(NativeLifecycle.CONNECTED)
        val original = healthy().copy(nativeSignals = signals)
        signals.clear()
        signals += NativeLifecycle.STOPPED
        assertEquals(ConnectionState.Connected(route), reducer.reduce(original))
        assertEquals(ConnectionState.Connected(route), reducer.reduce(original.copy()))
        try {
            (original.nativeSignals as MutableSet<NativeLifecycle>).clear()
            fail("mutable signals")
        } catch (_: UnsupportedOperationException) { }
    }
}
