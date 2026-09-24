// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import org.kurdistanvpn.core.model.*

enum class NativeLifecycle { CONNECTING, CONNECTED, DEGRADED, FALLING_BACK, RECONNECTING, STOPPED, REVOKED, FAILED }
data class SessionObservation(val binding: RuntimeBinding, val sessionId: CatalogId)

/** Each witness is a safe observation of adapter-owned state, never the actual TUN descriptor. */
class ProductStateInput(
    val profile: ProfileProjection?, val nowEpochSeconds: Long, val storage: StorageHealth,
    val expectedSession: SessionObservation?, nativeSignals: Set<NativeLifecycle>,
    val nativeSession: SessionObservation?, val tunSession: SessionObservation?,
    val routeSession: SessionObservation?, val dnsSession: SessionObservation?,
    val appliedRouteRevision: Long?, val appliedDnsRevision: Long?, val route: VerifiedRouteSnapshot?,
    /**
     * Independently current active selection, verified local trust/generation and applied settings /
     * installed-package revisions, read freshly from their trusted owners in one reconciled snapshot.
     * Null means no currently verified active binding. Never derive this from expectedSession, native
     * events, persisted presentation or any of the session witnesses.
     */
    val currentActiveBinding: RuntimeBinding?,
    val stopping: Boolean = false, val recovering: Boolean = false,
    val awaitingVpnPermission: Boolean = false,
    val attempt: AttemptSummary = AttemptSummary(1),
    val fallback: FallbackProgress = FallbackProgress(1, 1),
    val reconnect: ReconnectProgress = ReconnectProgress(1, 1),
) {
    val nativeSignals: Set<NativeLifecycle> = java.util.Collections.unmodifiableSet(nativeSignals.toSet())
    fun copy(
        profile: ProfileProjection? = this.profile, nowEpochSeconds: Long = this.nowEpochSeconds,
        storage: StorageHealth = this.storage, expectedSession: SessionObservation? = this.expectedSession,
        nativeSignals: Set<NativeLifecycle> = this.nativeSignals, nativeSession: SessionObservation? = this.nativeSession,
        tunSession: SessionObservation? = this.tunSession, routeSession: SessionObservation? = this.routeSession,
        dnsSession: SessionObservation? = this.dnsSession, appliedRouteRevision: Long? = this.appliedRouteRevision,
        appliedDnsRevision: Long? = this.appliedDnsRevision, route: VerifiedRouteSnapshot? = this.route,
        currentActiveBinding: RuntimeBinding? = this.currentActiveBinding,
        stopping: Boolean = this.stopping, recovering: Boolean = this.recovering,
        awaitingVpnPermission: Boolean = this.awaitingVpnPermission, attempt: AttemptSummary = this.attempt,
        fallback: FallbackProgress = this.fallback, reconnect: ReconnectProgress = this.reconnect,
    ): ProductStateInput = ProductStateInput(profile, nowEpochSeconds, storage, expectedSession, nativeSignals,
        nativeSession, tunSession, routeSession, dnsSession, appliedRouteRevision, appliedDnsRevision, route,
        currentActiveBinding, stopping, recovering, awaitingVpnPermission, attempt, fallback, reconnect)
    override fun toString(): String = "ProductStateInput(redacted)"
}

/** One pure source of connection presentation truth. No input here is reusable execution authority. */
class ProductStateReducer {
    fun reduce(input: ProductStateInput): ConnectionState {
        val signals = input.nativeSignals.toSet()
        val profile = input.profile
        if (profile?.status == ProjectionStatus.REVOKED || NativeLifecycle.REVOKED in signals)
            return ConnectionState.Revoked(RevocationSummary(RevocationReason.PROFILE))
        if (input.storage != StorageHealth.AVAILABLE) return ConnectionState.StorageBlocked(when (input.storage) {
            StorageHealth.LOCKED -> StorageBlockReason.LOCKED
            StorageHealth.KEY_INVALIDATED -> StorageBlockReason.KEY_INVALIDATED
            else -> StorageBlockReason.DEGRADED
        })
        if (input.recovering) return ConnectionState.Recovering(RecoveryProgress(RecoveryReason.INTERNET_RECOVERY))
        if (input.stopping) return ConnectionState.Stopping
        if (signals.size > 1) return inconsistent()
        if (profile == null) return ConnectionState.NoProfile
        if (input.nowEpochSeconds < 0) return inconsistent()
        if (profile.status != ProjectionStatus.VERIFIED || input.nowEpochSeconds >= profile.expiresAtEpochSeconds)
            return ConnectionState.Failed(ProductFailure(when {
                profile.status == ProjectionStatus.INCOMPATIBLE -> ProductFailureCode.PROFILE_INCOMPATIBLE
                profile.status == ProjectionStatus.EXPIRED || input.nowEpochSeconds >= profile.expiresAtEpochSeconds -> ProductFailureCode.PROFILE_EXPIRED
                else -> ProductFailureCode.PROFILE_UNTRUSTED
            }))
        if (input.awaitingVpnPermission) return ConnectionState.AwaitingVpnPermission
        val signal = signals.singleOrNull()
        return when (signal) {
            NativeLifecycle.CONNECTED, NativeLifecycle.DEGRADED -> {
                val current = input.currentActiveBinding
                val expected = input.expectedSession
                val route = input.route
                if (current == null || expected == null || expected.binding != current ||
                    current.profileId != profile.id || current.profileGeneration != profile.generation ||
                    input.nativeSession != expected || input.tunSession != expected || input.routeSession != expected || input.dnsSession != expected ||
                    input.appliedRouteRevision != expected.binding.settingsRevision || input.appliedDnsRevision != expected.binding.settingsRevision ||
                    route == null || route.profileId != profile.id) inconsistent()
                else if (signal == NativeLifecycle.CONNECTED) ConnectionState.Connected(route)
                else ConnectionState.Degraded(route, DegradationReason.HEALTH)
            }
            NativeLifecycle.CONNECTING -> ConnectionState.Connecting(input.attempt)
            NativeLifecycle.FALLING_BACK -> ConnectionState.FallingBack(input.fallback)
            NativeLifecycle.RECONNECTING -> ConnectionState.Reconnecting(input.reconnect)
            NativeLifecycle.FAILED -> ConnectionState.Failed(ProductFailure(ProductFailureCode.INTERNAL_FAILURE))
            NativeLifecycle.STOPPED, null -> if (input.tunSession != null || input.routeSession != null || input.dnsSession != null)
                inconsistent() else ConnectionState.Disconnected(ReadyContext(profile.id))
            NativeLifecycle.REVOKED -> ConnectionState.Revoked(RevocationSummary(RevocationReason.PROFILE))
        }
    }

    private fun inconsistent() = ConnectionState.SafeMode(SafeModeSummary(SafeModeReason.INCONSISTENT_STATE))
}
