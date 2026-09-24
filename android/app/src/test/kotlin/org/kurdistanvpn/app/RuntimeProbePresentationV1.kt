// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*

/** Coarse legacy display only. The caller retains the typed path/result and writes no history. */
internal fun legacyProbeStateV1(result: NativeProductResult<NativeProbeResult>): ProbeExecutionState {
    val error = when (result) {
        is NativeProductResult.Success -> {
            val value = result.value
            val mean = value.meanLatencyMicros
            when {
                value.completion != NativeProbeCompletion.COMPLETE -> OperationError.AUTHORITY_UNAVAILABLE
                value.attempted != 1 || value.unstarted != 0 ||
                    value.attempted != value.succeeded + value.failed -> OperationError.INTERNAL_FAILURE
                value.succeeded == 0 -> OperationError.ENDPOINT_UNAVAILABLE
                value.succeeded != 1 || value.failed != 0 || mean == null ->
                    OperationError.INTERNAL_FAILURE
                else -> return ProbeExecutionState.Succeeded(mean.toLong() / 1000)
            }
        }
        is NativeProductResult.Failure -> when (result.code) {
            ProductFailureCode.PROFILE_INCOMPATIBLE, ProductFailureCode.NO_PERMITTED_STRATEGY,
            ProductFailureCode.PROFILE_EXPIRED, ProductFailureCode.PROFILE_REVOKED,
            ProductFailureCode.RATE_LIMITED, ProductFailureCode.OPERATION_TIMED_OUT -> OperationError.AUTHORITY_UNAVAILABLE
            ProductFailureCode.INVALID_INPUT -> OperationError.INVALID_INPUT
            ProductFailureCode.SIZE_LIMIT -> OperationError.SIZE_LIMIT
            ProductFailureCode.RESOURCE_LIMIT, ProductFailureCode.LOW_MEMORY -> OperationError.RESOURCE_LIMIT
            ProductFailureCode.PROFILE_UNTRUSTED, ProductFailureCode.PROFILE_WRONG_DEVICE -> OperationError.TRUST_REJECTED
            ProductFailureCode.PROFILE_ROLLBACK -> OperationError.RECOVERY_REQUIRED
            ProductFailureCode.NETWORK_UNAVAILABLE, ProductFailureCode.NETWORK_IDENTITY_UNAVAILABLE -> OperationError.NETWORK_LOST
            ProductFailureCode.NODE_UNREACHABLE -> OperationError.ENDPOINT_UNAVAILABLE
            ProductFailureCode.SESSION_AUTHENTICATION_FAILED -> OperationError.KURD_AUTH_REJECTED
            ProductFailureCode.ROUTE_POLICY_REJECTED, ProductFailureCode.SOCKET_PROTECTION_FAILED -> OperationError.POLICY_REJECTED
            ProductFailureCode.DNS_POLICY_REJECTED, ProductFailureCode.DNS_HEALTH_FAILED -> OperationError.DNS_UNAVAILABLE
            ProductFailureCode.CANCELLED, ProductFailureCode.OPERATION_INTERRUPTED -> OperationError.CANCELLED
            ProductFailureCode.INTERNAL_FAILURE, ProductFailureCode.STORAGE_LOCKED,
            ProductFailureCode.STORAGE_KEY_INVALIDATED, ProductFailureCode.STORAGE_DEGRADED,
            ProductFailureCode.MIGRATION_REQUIRED, ProductFailureCode.VPN_CONSENT_REQUIRED,
            ProductFailureCode.VPN_CONSENT_DENIED, ProductFailureCode.CAPTIVE_PORTAL,
            ProductFailureCode.TUN_ESTABLISH_FAILED, ProductFailureCode.APP_POLICY_DRIFT,
            ProductFailureCode.FOREGROUND_START_BLOCKED, ProductFailureCode.RECONNECT_EXHAUSTED,
            ProductFailureCode.UPDATE_SIGNATURE_INVALID, ProductFailureCode.UPDATE_ROLLBACK,
            ProductFailureCode.UPDATE_INCOMPATIBLE, ProductFailureCode.PROXY_BIND_FAILED,
            ProductFailureCode.PROXY_AUTHENTICATION_FAILED, ProductFailureCode.THERMAL_LIMIT,
            ProductFailureCode.OPERATION_ALREADY_ACTIVE, ProductFailureCode.UPDATE_FETCH_REJECTED -> OperationError.INTERNAL_FAILURE
        }
    }
    return ProbeExecutionState.Failed(error)
}
