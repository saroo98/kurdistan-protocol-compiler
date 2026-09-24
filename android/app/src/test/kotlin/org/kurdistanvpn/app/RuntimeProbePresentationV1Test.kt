// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*

class RuntimeProbePresentationV1Test {
    @Test fun completeOneSampleUsesMeasuredMicrosecondsForEitherPath() {
        for (path in NativeProbePath.entries) {
            assertEquals(ProbeExecutionState.Succeeded(123), legacyProbeStateV1(success(path, 123456)))
            assertEquals(ProbeExecutionState.Succeeded(0), legacyProbeStateV1(success(path, 500)))
        }
    }
    @Test fun incompleteAndZeroSuccessCannotLookSuccessful() {
        for (completion in listOf(NativeProbeCompletion.TIMED_OUT, NativeProbeCompletion.RATE_LIMITED)) {
            val result = success(NativeProbePath.ACTIVE_RELAY_END_TO_END, 123456).value.copy(completion = completion)
            assertEquals(ProbeExecutionState.Failed(OperationError.AUTHORITY_UNAVAILABLE),
                legacyProbeStateV1(NativeProductResult.Success(result)))
        }
        val failed = NativeProbeResult(NativeProbePath.ACTIVE_RELAY_END_TO_END, NativeProbeMethod.TCP_CONNECT,
            1, 0, 1, 0, null, null, 1000, NativeProbeStability.NOT_ENOUGH_SAMPLES, NativeProbeCompletion.COMPLETE)
        assertEquals(ProbeExecutionState.Failed(OperationError.ENDPOINT_UNAVAILABLE),
            legacyProbeStateV1(NativeProductResult.Success(failed)))
        val multiple = failed.copy(attempted = 2, failed = 2)
        assertEquals(ProbeExecutionState.Failed(OperationError.INTERNAL_FAILURE),
            legacyProbeStateV1(NativeProductResult.Success(multiple)))
    }
    @Test fun invalidAggregatesAreRejectedBeforePresentation() {
        val valid = success(NativeProbePath.ACTIVE_RELAY_END_TO_END, 1).value
        for (make in listOf<() -> NativeProbeResult>(
            { valid.copy(meanLatencyMicros = null) }, { valid.copy(failed = 1) },
            { valid.copy(unstarted = 1) }, { valid.copy(attempted = 0) })) {
            assertThrows(IllegalArgumentException::class.java) { make() }
        }
    }
    @Test fun allFailureCategoriesHaveExplicitCoarsePresentation() {
        val rows = mapOf(
            OperationError.AUTHORITY_UNAVAILABLE to listOf(ProductFailureCode.PROFILE_INCOMPATIBLE,
                ProductFailureCode.NO_PERMITTED_STRATEGY, ProductFailureCode.PROFILE_EXPIRED,
                ProductFailureCode.PROFILE_REVOKED, ProductFailureCode.RATE_LIMITED, ProductFailureCode.OPERATION_TIMED_OUT),
            OperationError.INVALID_INPUT to listOf(ProductFailureCode.INVALID_INPUT),
            OperationError.SIZE_LIMIT to listOf(ProductFailureCode.SIZE_LIMIT),
            OperationError.RESOURCE_LIMIT to listOf(ProductFailureCode.RESOURCE_LIMIT, ProductFailureCode.LOW_MEMORY),
            OperationError.TRUST_REJECTED to listOf(ProductFailureCode.PROFILE_UNTRUSTED, ProductFailureCode.PROFILE_WRONG_DEVICE),
            OperationError.RECOVERY_REQUIRED to listOf(ProductFailureCode.PROFILE_ROLLBACK),
            OperationError.NETWORK_LOST to listOf(ProductFailureCode.NETWORK_UNAVAILABLE, ProductFailureCode.NETWORK_IDENTITY_UNAVAILABLE),
            OperationError.ENDPOINT_UNAVAILABLE to listOf(ProductFailureCode.NODE_UNREACHABLE),
            OperationError.KURD_AUTH_REJECTED to listOf(ProductFailureCode.SESSION_AUTHENTICATION_FAILED),
            OperationError.POLICY_REJECTED to listOf(ProductFailureCode.ROUTE_POLICY_REJECTED, ProductFailureCode.SOCKET_PROTECTION_FAILED),
            OperationError.DNS_UNAVAILABLE to listOf(ProductFailureCode.DNS_POLICY_REJECTED, ProductFailureCode.DNS_HEALTH_FAILED),
            OperationError.CANCELLED to listOf(ProductFailureCode.CANCELLED, ProductFailureCode.OPERATION_INTERRUPTED))
        for (code in ProductFailureCode.entries) {
            val expected = rows.entries.singleOrNull { code in it.value }?.key ?: OperationError.INTERNAL_FAILURE
            assertEquals(code.name, ProbeExecutionState.Failed(expected),
                legacyProbeStateV1(NativeProductResult.Failure(code)))
        }
    }
    private fun success(path: NativeProbePath, micros: Int) = NativeProductResult.Success(NativeProbeResult(
        path, NativeProbeMethod.TCP_CONNECT, 1, 1, 0, 0, micros, null, 0,
        NativeProbeStability.NOT_ENOUGH_SAMPLES, NativeProbeCompletion.COMPLETE))
}
