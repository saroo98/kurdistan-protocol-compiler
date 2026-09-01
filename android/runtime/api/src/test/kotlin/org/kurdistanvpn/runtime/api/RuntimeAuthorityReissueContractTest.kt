// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

import org.junit.Assert.*
import org.junit.Test

class RuntimeAuthorityReissueContractTest {
    @Test fun automaticAttemptCannotBeLiveForMoreThanSixtySeconds() {
        val automatic = request().copy(trigger = RuntimeAuthorityTrigger.AUTOMATIC, deadlineElapsedMillis = 60_100)
        assertTrue(automatic.isLiveAt(100))
        assertFalse(automatic.isLiveAt(99))
        assertTrue(automatic.isLiveAt(60_099))
        assertFalse(automatic.isLiveAt(60_100))
        assertFalse(automatic.copy(deadlineElapsedMillis = Long.MAX_VALUE).isLiveAt(0))
        assertTrue(automatic.copy(deadlineElapsedMillis = Long.MAX_VALUE).isLiveAt(Long.MAX_VALUE - 60_000))
        assertFalse(automatic.copy(deadlineElapsedMillis = Long.MAX_VALUE).isLiveAt(Long.MAX_VALUE - 60_001))
    }

    @Test fun committedRevisionAndDescriptorNumbersAreCheckedBeforeNarrowing() {
        listOf(0L, -2L, 1L, Long.MAX_VALUE).forEach { revision ->
            assertThrows(IllegalArgumentException::class.java) { request().copy(revision = revision) }
        }
        listOf(-1L, 0xffff_ffffL, Long.MAX_VALUE).forEach { uid ->
            assertThrows(IllegalArgumentException::class.java) { descriptor().copy(ownerUid = uid) }
        }
        assertThrows(IllegalArgumentException::class.java) { descriptor().copy(length = Long.MAX_VALUE) }
        assertThrows(IllegalArgumentException::class.java) { descriptor().copy(mode = 0x1_0000_0180L) }
        assertThrows(IllegalArgumentException::class.java) { descriptor().copy(accessMode = 1) }
    }

    @Test fun leasePurposePreservesArmedIdentityAndGenerationIsEpochLocal() {
        val full = request()
        assertTrue(full.sameArm(full.forPurpose(RuntimeAuthorityPurpose.PRE_TUN)))
        assertFalse(full.sameArm(full.copy(consumerEpoch = "9".repeat(32))))
        assertFalse(full.sameArm(full.copy(providerEpoch = "a".repeat(32))))
        assertFalse(full.sameArm(full.copy(capabilityChannelId = "b".repeat(32))))
        assertFalse(full.sameArm(full.copy(frameChannelId = "c".repeat(32))))
        assertFalse(full.sameArm(full.copy(requestId = "3".repeat(32))))
        assertTrue(full.isLiveAt(100))
        assertFalse(full.isLiveAt(1000))
        assertFalse(full.isLiveAt(-1))
        assertThrows(IllegalArgumentException::class.java) { full.copy(generation = 0) }
        assertThrows(IllegalArgumentException::class.java) { full.copy(requestId = "../invalid") }
        assertThrows(IllegalArgumentException::class.java) { full.copy(trigger = RuntimeAuthorityTrigger.NETWORK_RETRY, retryAttempt = 0) }
    }

    @Test fun eachProcessAndBothPipeIdentitiesAreRequiredRuntimeSizedAndNotInterchangeable() {
        val full = request()
        for (invalid in listOf("", "0".repeat(32), "1".repeat(64), "A".repeat(32))) {
            assertThrows(IllegalArgumentException::class.java) { full.copy(providerEpoch = invalid) }
            assertThrows(IllegalArgumentException::class.java) { full.copy(consumerEpoch = invalid) }
            assertThrows(IllegalArgumentException::class.java) { full.copy(capabilityChannelId = invalid) }
            assertThrows(IllegalArgumentException::class.java) { full.copy(frameChannelId = invalid) }
        }
        assertThrows(IllegalArgumentException::class.java) { full.copy(providerEpoch = full.consumerEpoch) }
        assertThrows(IllegalArgumentException::class.java) { full.copy(frameChannelId = full.capabilityChannelId) }
        val changedDescriptor = full.descriptor.copy(id = "d".repeat(32), inode = 3, length = 213)
        assertTrue(full.sameArm(full.forPurpose(RuntimeAuthorityPurpose.PRE_ACTIVE, changedDescriptor)))
        assertFalse(full.sameArm(full.copy(capabilityChannelId = full.frameChannelId, frameChannelId = full.capabilityChannelId)))
    }

    private fun descriptor() = RuntimeDescriptorBinding("4".repeat(32), 1, 2, 1000, 4480, 200, 0)
    private fun request() = RuntimeAuthorityRequest("1".repeat(32), "5".repeat(32), "2".repeat(32), 1,
        RuntimeAuthorityPurpose.FULL_AUTHORITY, RuntimeAuthorityTrigger.MANUAL, 2, 1000,
        "3".repeat(32), "6".repeat(32), descriptor(), 2, 0)
}
