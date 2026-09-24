// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*
import org.kurdistanvpn.runtime.api.*

/** Main-process current binding is read independently; service evidence never supplies it. */
internal fun productConnectionPresentation(snapshot: VpnRuntimeSnapshot, profile: ProfileProjection?,
    current: RuntimePresentationBinding?, storage: StorageHealth, nowEpochSeconds: Long): ConnectionState {
    val status = snapshot.validatedForDisplay()
    if (status.failure == "INVALID_RUNTIME_STATUS")
        return ConnectionState.SafeMode(SafeModeSummary(SafeModeReason.INCONSISTENT_STATE))
    val evidence = status.presentation
    fun RuntimePresentationBinding.domain() = RuntimeBinding(CatalogId(profileId), profileGeneration,
        trustRevision, settingsRevision, packageRevision)
    fun witness(id: String?) = if (id == null || evidence == null) null
        else SessionObservation(evidence.binding.domain(), CatalogId(id))
    val signal = when (status.state) {
        VpnRuntimeState.ACTIVE_KURD_LIVE -> NativeLifecycle.CONNECTED
        VpnRuntimeState.DEGRADED -> NativeLifecycle.DEGRADED
        VpnRuntimeState.PREPARING, VpnRuntimeState.CONNECTING -> NativeLifecycle.CONNECTING
        VpnRuntimeState.FALLING_BACK -> NativeLifecycle.FALLING_BACK
        VpnRuntimeState.RECONNECTING -> NativeLifecycle.RECONNECTING
        VpnRuntimeState.REVOKED -> NativeLifecycle.REVOKED
        VpnRuntimeState.FAILED, VpnRuntimeState.BLOCKED -> NativeLifecycle.FAILED
        else -> NativeLifecycle.STOPPED
    }
    return ProductStateReducer().reduce(ProductStateInput(profile, nowEpochSeconds, storage,
        witness(evidence?.sessionId), setOf(signal), witness(evidence?.nativeSessionId),
        witness(evidence?.tunSessionId), witness(evidence?.sessionId?.takeIf { evidence.routeRevision != null }),
        witness(evidence?.sessionId?.takeIf { evidence.dnsRevision != null }),
        evidence?.routeRevision, evidence?.dnsRevision,
        evidence?.takeIf { it.routeRevision != null && status.ipMode != IpMode.AUTO }?.let {
            VerifiedRouteSnapshot(CatalogId(it.binding.profileId), status.ipMode, status.mtu)
        }, current?.domain(), stopping = status.state == VpnRuntimeState.STOPPING,
        recovering = status.state == VpnRuntimeState.RECOVERING || status.failure == "RUNTIME_PROCESS_LOST",
        awaitingVpnPermission = status.state == VpnRuntimeState.AWAITING_VPN_CONSENT))
}
