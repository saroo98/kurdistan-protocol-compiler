// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.runtime.api.*

class RuntimeRevisionLeaseClientTest {
    @Test fun finalLeaseBoundStartsBeforeRpcAndCannotBeExtendedByLateResponse() {
        val full = request().copy(deadlineElapsedMillis = 60_000)
        val client = RuntimeRevisionLeaseClient(full)
        assertTrue(client.beginFinalLease(100))
        assertFalse(client.beginFinalLease(101))
        assertFalse(client.authorizeTun(checks().copy(nowElapsedMillis = 2100)))
        assertFalse(client.beginFinalLease(2200))
    }

    @Test fun longAuthorityLifetimeAloneCannotAuthorizeTheFinalLease() {
        val client = RuntimeRevisionLeaseClient(request().copy(deadlineElapsedMillis = 60_000))
        assertFalse(client.authorizeTun(checks()))
        assertFalse(client.beginFinalLease(100))
    }

    @Test fun orderedFreshLeasesAreRequiredBeforeTunAndActivePublication() {
        val client = RuntimeRevisionLeaseClient(request())
        assertFalse(client.authorizeTun(checks()))
        val valid = RuntimeRevisionLeaseClient(request())
        assertTrue(valid.accept(lease(RuntimeAuthorityPurpose.PRE_TUN), checks()))
        assertTrue(valid.authorizeTun(checks()))
        assertTrue(valid.accept(lease(RuntimeAuthorityPurpose.PRE_ACTIVE), checks()))
        assertTrue(valid.authorizePublication(checks()))
        assertFalse(valid.authorizePublication(checks()))
    }

    @Test fun wrongRevisionGenerationConsentCancellationOrDeadlineNeverPublishes() {
        listOf(checks().copy(revision = 4), checks().copy(generation = 2), checks().copy(unlocked = false),
            checks().copy(vpnPrepared = false), checks().copy(cancelled = true), checks().copy(nowElapsedMillis = 1000),
            checks().copy(epoch = "9".repeat(32)), checks().copy(providerEpoch = "a".repeat(32))).forEach { stale ->
            val client = RuntimeRevisionLeaseClient(request())
            assertTrue(client.accept(lease(RuntimeAuthorityPurpose.PRE_TUN), checks()))
            assertTrue(client.authorizeTun(checks()))
            assertTrue(client.accept(lease(RuntimeAuthorityPurpose.PRE_ACTIVE), checks()))
            assertFalse(client.authorizePublication(stale))
            assertFalse(client.authorizePublication(checks()))
        }
    }

    @Test fun competingPurposeAndClosedClientCannotRearm() {
        val client = RuntimeRevisionLeaseClient(request())
        assertFalse(client.accept(lease(RuntimeAuthorityPurpose.PRE_ACTIVE), checks()))
        assertFalse(client.accept(lease(RuntimeAuthorityPurpose.PRE_TUN), checks()))
        val closed = RuntimeRevisionLeaseClient(request())
        closed.close()
        assertFalse(closed.accept(lease(RuntimeAuthorityPurpose.PRE_TUN), checks()))
    }

    private fun checks() = RuntimeActivationChecks("1".repeat(32), "5".repeat(32), 1, 2, true, true, false, 100)
    private fun request() = RuntimeAuthorityRequest("1".repeat(32), "5".repeat(32), "2".repeat(32), 1,
        RuntimeAuthorityPurpose.FULL_AUTHORITY, RuntimeAuthorityTrigger.MANUAL, 2, 1000,
        "3".repeat(32), "6".repeat(32), RuntimeDescriptorBinding("4".repeat(32), 1, 2, 1000, 4480, 232, 0), 2, 0)
    private fun lease(purpose: RuntimeAuthorityPurpose): RuntimeVerifiedAuthority {
        val expected = request().forPurpose(purpose, request().descriptor.copy(length = RuntimeAuthorityFrameCodec.encodedLength(0).toLong()))
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 5 }, expected).seal(byteArrayOf())!!
        return (RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 5 }, expected)
            .verifyAndConsume(frame, expected.descriptor, 100) as RuntimeFrameVerification.Verified).authority
    }
}
