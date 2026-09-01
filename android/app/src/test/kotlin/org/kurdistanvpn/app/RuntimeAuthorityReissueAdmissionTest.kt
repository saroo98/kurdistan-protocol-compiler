// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.runtime.api.*
import org.kurdistanvpn.runtime.android.*

class RuntimeAuthorityReissueAdmissionTest {
    @Test fun unmarkedLifecycleInputsAreTriggersNeverManualAuthority() {
        listOf(null, "android.net.VpnService", "vendor.OEM_RESTART").forEach { action ->
            assertEquals(RuntimeServiceCommand.AutomaticTrigger,
                RuntimeServiceCommand.classify(SanitizedRuntimeCommand(action, RuntimePrivateMarker.ABSENT, false, null)))
        }
        assertTrue(RuntimeServiceCommand.classify(SanitizedRuntimeCommand(RuntimeServiceCommand.ACTION_START,
            RuntimePrivateMarker.ABSENT, false, null)) is RuntimeServiceCommand.Rejected)
        assertTrue(RuntimeServiceCommand.classify(SanitizedRuntimeCommand(null,
            RuntimePrivateMarker.ABSENT, true, null)) is RuntimeServiceCommand.Rejected)
    }

    @Test fun onlyWellFormedMarkedPrivateStartIsManualAndStopCannotCarryAuthority() {
        val id = "1".repeat(32)
        assertEquals(RuntimeServiceCommand.Manual(id), RuntimeServiceCommand.classify(SanitizedRuntimeCommand(
            RuntimeServiceCommand.ACTION_START, RuntimePrivateMarker.VALID, false, id)))
        listOf(
            SanitizedRuntimeCommand(RuntimeServiceCommand.ACTION_START, RuntimePrivateMarker.MALFORMED, false, id),
            SanitizedRuntimeCommand(RuntimeServiceCommand.ACTION_START, RuntimePrivateMarker.VALID, true, id),
            SanitizedRuntimeCommand(RuntimeServiceCommand.ACTION_START, RuntimePrivateMarker.VALID, false, "invalid"),
            SanitizedRuntimeCommand("vendor.OEM_RESTART", RuntimePrivateMarker.VALID, false, id),
            SanitizedRuntimeCommand(RuntimeServiceCommand.ACTION_STOP, RuntimePrivateMarker.VALID, false, id),
            SanitizedRuntimeCommand(null, RuntimePrivateMarker.ABSENT, false, id),
        ).forEach { assertTrue(RuntimeServiceCommand.classify(it) is RuntimeServiceCommand.Rejected) }
        assertEquals(RuntimeServiceCommand.Stop, RuntimeServiceCommand.classify(SanitizedRuntimeCommand(
            RuntimeServiceCommand.ACTION_STOP, RuntimePrivateMarker.VALID, false, null)))
    }

    @Test fun admissionChecksCallerConsentRevisionDeadlineAndBudgetBeforeArming() {
        val request = request()
        listOf(environment().copy(callerUid = 0x1_0000_03e8), environment().copy(unlocked = false),
            environment().copy(vpnPrepared = false), environment().copy(currentRevision = 4),
            environment().copy(nowElapsedMillis = 1000), environment().copy(authoritativeRetryBudget = 1)).forEach { denied ->
            val admission = admission()
            assertTrue(admission.admit(request, denied) is RuntimeReissueAdmission.Rejected)
            assertEquals(RuntimeReissueAdmission.Allowed, admission.admit(request, environment()))
        }
    }

    @Test fun generationHighWaterIsPerBoundEpochAndSameArmLeasePurposesAreOrdered() {
        val admission = admission()
        val request = request()
        assertEquals(RuntimeReissueAdmission.Allowed, admission.admit(request, environment()))
        assertTrue(admission.checkLease(request.forPurpose(RuntimeAuthorityPurpose.PRE_ACTIVE), environment()) is RuntimeReissueAdmission.Rejected)
        assertEquals(RuntimeReissueAdmission.Allowed, admission.checkLease(request.forPurpose(RuntimeAuthorityPurpose.PRE_TUN), environment()))
        assertTrue(admission.checkLease(request.forPurpose(RuntimeAuthorityPurpose.PRE_TUN), environment()) is RuntimeReissueAdmission.Rejected)
        assertEquals(RuntimeReissueAdmission.Allowed, admission.checkLease(request.forPurpose(RuntimeAuthorityPurpose.PRE_ACTIVE), environment()))
        assertTrue(admission.admit(request, environment()) is RuntimeReissueAdmission.Rejected)
        val fresh = request.copy(generation = 2, requestId = "8".repeat(32), capabilityChannelId = "a".repeat(32), frameChannelId = "b".repeat(32))
        assertEquals(RuntimeReissueAdmission.Allowed, admission.admit(fresh, environment(fresh)))
        val newEpoch = "9".repeat(32)
        assertEquals(RuntimeReissueAdmission.Allowed, RuntimeAuthorityReissueAdmission(1000, newEpoch, request.providerEpoch)
            .admit(request.copy(consumerEpoch = newEpoch), environment()))
    }

    @Test fun providerEpochAndBothObservedPipeIdentitiesAreCheckedBeforeArming() {
        val request = request()
        val badRequests = listOf(request.copy(providerEpoch = "a".repeat(32)),
            request.copy(consumerEpoch = "b".repeat(32)),
            request.copy(capabilityChannelId = "c".repeat(32)),
            request.copy(frameChannelId = "d".repeat(32)),
            request.copy(capabilityChannelId = request.frameChannelId, frameChannelId = request.capabilityChannelId))
        for (bad in badRequests) {
            val gate = admission()
            assertTrue(gate.admit(bad, environment()) is RuntimeReissueAdmission.Rejected)
            assertEquals(RuntimeReissueAdmission.Allowed, gate.admit(request, environment()))
        }
    }

    @Test fun everySubsequentArmNeedsFreshRequestAndFreshSeparatedPipeContexts() {
        for (reuse in 0..2) {
            val gate = admission(); val first = request()
            assertEquals(RuntimeReissueAdmission.Allowed, gate.admit(first, environment()))
            gate.cancel(first.requestId)
            val next = first.copy(generation = 2, requestId = if (reuse == 0) first.requestId else "8".repeat(32),
                capabilityChannelId = if (reuse == 1) first.capabilityChannelId else "a".repeat(32),
                frameChannelId = if (reuse == 2) first.frameChannelId else "b".repeat(32))
            assertEquals(RuntimeAdmissionFailure.REPLAY,
                (gate.admit(next, environment(next)) as RuntimeReissueAdmission.Rejected).reason)
        }
        val gate = admission(); val first = request()
        gate.admit(first, environment()); gate.cancel(first.requestId)
        val swapped = first.copy(generation = 2, requestId = "8".repeat(32),
            capabilityChannelId = first.frameChannelId, frameChannelId = first.capabilityChannelId)
        assertEquals(RuntimeAdmissionFailure.REPLAY,
            (gate.admit(swapped, environment(swapped)) as RuntimeReissueAdmission.Rejected).reason)
    }

    @Test fun leaseCannotChangeEitherProcessOrPipeContextAndClosedProviderEpochCannotRevive() {
        val gate = admission(); val request = request()
        gate.admit(request, environment())
        for (other in listOf(request.copy(providerEpoch = "a".repeat(32)), request.copy(consumerEpoch = "b".repeat(32)),
            request.copy(capabilityChannelId = "c".repeat(32)), request.copy(frameChannelId = "d".repeat(32)))) {
            assertTrue(gate.checkLease(other.forPurpose(RuntimeAuthorityPurpose.PRE_TUN), environment(other)) is RuntimeReissueAdmission.Rejected)
        }
        assertEquals(RuntimeReissueAdmission.Allowed, gate.checkLease(request.forPurpose(RuntimeAuthorityPurpose.PRE_TUN), environment()))
        gate.close()
        assertTrue(gate.checkLease(request.forPurpose(RuntimeAuthorityPurpose.PRE_ACTIVE), environment()) is RuntimeReissueAdmission.Rejected)
        val providerRestart = RuntimeAuthorityReissueAdmission(1000, request.consumerEpoch, "a".repeat(32))
        assertTrue(providerRestart.admit(request, environment()) is RuntimeReissueAdmission.Rejected)
        val fresh = request.copy(providerEpoch = "a".repeat(32), requestId = "b".repeat(32), capabilityChannelId = "c".repeat(32), frameChannelId = "d".repeat(32))
        assertEquals(RuntimeReissueAdmission.Allowed, providerRestart.admit(fresh, environment(fresh)))
    }

    @Test fun networkRetryUsesFreshRequestAndPipesWithoutInventingANewSecurityRevision() {
        val gate = admission(); val first = request().copy(trigger = RuntimeAuthorityTrigger.AUTOMATIC)
        assertEquals(RuntimeReissueAdmission.Allowed, gate.admit(first, environment()))
        assertEquals(RuntimeReissueAdmission.Allowed, gate.checkLease(first.forPurpose(RuntimeAuthorityPurpose.PRE_TUN), environment()))
        assertEquals(RuntimeReissueAdmission.Allowed, gate.checkLease(first.forPurpose(RuntimeAuthorityPurpose.PRE_ACTIVE), environment()))
        val retry = first.copy(trigger = RuntimeAuthorityTrigger.NETWORK_RETRY, retryAttempt = 1, generation = 2,
            requestId = "8".repeat(32), capabilityChannelId = "9".repeat(32), frameChannelId = "a".repeat(32))
        assertEquals(first.revision, retry.revision)
        assertEquals(RuntimeReissueAdmission.Allowed, gate.admit(retry, environment(retry)))
        gate.cancel(retry.requestId)
        assertEquals(RuntimeAdmissionFailure.REPLAY,
            (gate.admit(retry.copy(generation = 3), environment(retry)) as RuntimeReissueAdmission.Rejected).reason)
        assertThrows(IllegalArgumentException::class.java) { retry.copy(retryAttempt = 3) }
    }

    @Test fun observedChannelAndDeadlineFailureDuringLeasePermanentlyDisarmsThatRequest() {
        for (reason in 0..2) {
            val gate = admission(); val full = request()
            gate.admit(full, environment())
            val lease = full.forPurpose(RuntimeAuthorityPurpose.PRE_TUN)
            val bad = when (reason) {
                0 -> environment().copy(observedCapabilityChannelId = "9".repeat(32))
                1 -> environment().copy(observedFrameChannelId = "a".repeat(32))
                else -> environment().copy(nowElapsedMillis = full.deadlineElapsedMillis)
            }
            assertTrue(gate.checkLease(lease, bad) is RuntimeReissueAdmission.Rejected)
            assertEquals(RuntimeAdmissionFailure.CANCELLED,
                (gate.checkLease(lease, environment()) as RuntimeReissueAdmission.Rejected).reason)
            assertTrue(gate.admit(full, environment()) is RuntimeReissueAdmission.Rejected)
        }
    }

    @Test fun cancellationAndClosedChannelCannotRearmOldRequests() {
        val admission = admission()
        val request = request()
        admission.admit(request, environment())
        admission.cancel(request.requestId)
        assertTrue(admission.checkLease(request.forPurpose(RuntimeAuthorityPurpose.PRE_TUN), environment()) is RuntimeReissueAdmission.Rejected)
        assertTrue(admission.admit(request, environment()) is RuntimeReissueAdmission.Rejected)
        admission.close()
        assertTrue(admission.admit(request.copy(generation = 2), environment()) is RuntimeReissueAdmission.Rejected)
    }

    private fun admission() = RuntimeAuthorityReissueAdmission(1000, "1".repeat(32), "5".repeat(32))
    private fun environment(request: RuntimeAuthorityRequest = request()) = RuntimeAdmissionEnvironment(1000, true, true, true, 2, 100, 2,
        request.capabilityChannelId, request.frameChannelId)
    private fun request() = RuntimeAuthorityRequest("1".repeat(32), "5".repeat(32), "2".repeat(32), 1,
        RuntimeAuthorityPurpose.FULL_AUTHORITY, RuntimeAuthorityTrigger.MANUAL, 2, 1000,
        "3".repeat(32), "6".repeat(32), RuntimeDescriptorBinding("4".repeat(32), 1, 2, 1000, 4480, 232, 0), 2, 0)
}
