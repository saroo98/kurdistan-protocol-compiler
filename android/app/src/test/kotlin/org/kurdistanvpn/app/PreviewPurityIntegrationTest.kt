// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.VerifiedPreviewHandle
import org.kurdistanvpn.data.protectedstate.NativePreviewRequestOutcome
import org.kurdistanvpn.data.protectedstate.ProtectedStatePreviewBackupPolicy
import org.kurdistanvpn.data.protectedstate.ReleasedNativePreviewRequest
import org.kurdistanvpn.data.secure.*
import java.util.concurrent.CancellationException

/** Host integration of the actual projection, request/handle ownership and read-only capabilities.
 * It does not exercise Android startup, Room, Keystore or the Activity/ViewModel scheduler.
 */
class PreviewPurityIntegrationTest {
    @Test fun nativeReleaseFailureCannotProduceConfirmableRequestAndWipesNativeInput() {
        val fixture = PreviewOwnershipFixture()
        fixture.releaseResult = NativeResult.Failure(OperationError.INTERNAL_FAILURE)
        val result = fixture.resolve()
        assertSame(NativePreviewRequestOutcome.CleanupUnproven, result)
        assertEquals(1, fixture.releases)
        fixture.assertNativeInputsWiped()
        assertArrayEquals(byteArrayOf(7, 11, 13), fixture.callerBytes)
    }

    @Test fun throwingReleaseCannotProduceConfirmationOrRetryTheNativeHandle() {
        val fixture = PreviewOwnershipFixture()
        fixture.releaseFailure = IllegalStateException("synthetic release failure")
        assertSame(NativePreviewRequestOutcome.CleanupUnproven, fixture.resolve())
        assertEquals(1, fixture.releases)
        fixture.assertNativeInputsWiped()
    }

    @Test fun resolverExceptionWipesOwnedRequestAndDoesNotInventAHandle() {
        val fixture = PreviewOwnershipFixture()
        fixture.resolveFailure = IllegalStateException("synthetic resolution failure")
        assertEquals(OperationError.INTERNAL_FAILURE,
            (fixture.resolve() as NativePreviewRequestOutcome.Rejected).error)
        assertEquals(0, fixture.releases)
        fixture.assertNativeInputsWiped()
    }

    @Test fun cancellationPropagatesAfterOwnedRequestWipe() {
        val fixture = PreviewOwnershipFixture()
        fixture.resolveFailure = CancellationException("synthetic cancellation")
        assertThrows(CancellationException::class.java) { fixture.resolve() }
        assertEquals(0, fixture.releases)
        fixture.assertNativeInputsWiped()
    }

    @Test fun ordinaryRejectionPreservesCategoryAndWipesRequest() {
        val fixture = PreviewOwnershipFixture()
        fixture.resolveResult = NativeResult.Failure(OperationError.TRUST_REJECTED)
        assertEquals(OperationError.TRUST_REJECTED,
            (fixture.resolve() as NativePreviewRequestOutcome.Rejected).error)
        assertEquals(0, fixture.releases)
        fixture.assertNativeInputsWiped()
    }

    @Test fun successfulReleasePrecedesConfirmationAndOwnedRequestIsOneUse() {
        val fixture = PreviewOwnershipFixture()
        val result = fixture.resolve() as NativePreviewRequestOutcome.Ready
        assertEquals(1, fixture.releases)
        fixture.assertNativeInputsWiped()
        fixture.callerBytes.fill(99)
        assertEquals(fixture.handle.preview, result.request.display)
        val confirmed = result.request.takeConfirmedRequest()
        try { assertArrayEquals(byteArrayOf(7, 11, 13), confirmed) }
        finally { confirmed.fill(0) }
        assertThrows(IllegalStateException::class.java) { result.request.takeConfirmedRequest() }
        result.request.close()
        result.request.close()
        assertEquals(1, fixture.releases)
    }

    @Test fun cancelOrRejectClosesOwnedRequestAndCannotLaterConfirm() {
        val fixture = PreviewOwnershipFixture()
        val result = fixture.resolve() as NativePreviewRequestOutcome.Ready
        result.request.close()
        result.request.close()
        assertThrows(IllegalStateException::class.java) { result.request.takeConfirmedRequest() }
        fixture.assertNativeInputsWiped()
        assertEquals(1, fixture.releases)
    }

    @Test fun invalidNativeHandleStillReleasesOnceAndNeverConfirms() {
        val fixture = PreviewOwnershipFixture()
        fixture.resolveResult = NativeResult.Success(fixture.handle.copy(handle = 0))
        assertEquals(OperationError.INTERNAL_FAILURE,
            (fixture.resolve() as NativePreviewRequestOutcome.Rejected).error)
        assertEquals(1, fixture.releases)
        fixture.assertNativeInputsWiped()
    }

    @Test fun invalidRequestBoundsRejectBeforeNativeAccess() {
        val fixture = PreviewOwnershipFixture()
        for (input in listOf(byteArrayOf(), ByteArray(1_500_001))) {
            assertEquals(OperationError.INVALID_INPUT,
                (fixture.resolve(input) as NativePreviewRequestOutcome.Rejected).error)
        }
        assertEquals(0, fixture.nativeInputs.size)
        assertEquals(0, fixture.releases)
    }

    @Test fun projectionAndRefreshLeaveExistingRoutingDiagnosticsAndPreferencesUntouched() {
        val blobs = CountingBlobs()
        SecureRoutingPolicyStore(blobs).savePackages(setOf("org.committed.browser"))
        val events = listOf(DiagnosticEvent(1, DiagnosticLogLevel.INFO, DiagnosticComponent.APP, "EXPLICIT_EVENT", 10))
        EncryptedDiagnosticEventStore(blobs).save(events)
        val before = blobs.snapshot()
        val writes = blobs.writes
        val settings = Phase9Settings(
            connection = ConnectionPreferences(autoConnectOnLaunch = true),
            routing = RoutingPreferences(mode = PerAppSelectionMode.EXCLUDE_SELECTED, packages = setOf("org.legacy.package")),
            profiles = ProfilePreferences("missing", setOf("missing", "known")),
        )
        val routing = SecureRoutingPolicyStore.readOnly(blobs)
        val diagnostics = EncryptedDiagnosticEventStore.readOnly(blobs)
        val projected = ProtectedStatePreviewBackupPolicy.projectSettings(settings, routing.loadPackages())
        assertEquals(setOf("org.committed.browser"), projected.routing.packages)
        assertEquals(events, diagnostics.load())
        val refreshed = ProtectedStatePreviewBackupPolicy.projectProfiles(projected.profiles, listOf("known"))
        assertEquals(ProfilePreferences("known", setOf("known")), refreshed)
        assertEquals("missing", settings.profiles.activeLocalRecordId)
        assertTrue(settings.connection.autoConnectOnLaunch)
        assertEquals(setOf("org.legacy.package"), settings.routing.packages)
        assertEquals(writes, blobs.writes)
        assertEquals(before.keys, blobs.snapshot().keys)
        before.forEach { (key, bytes) -> assertArrayEquals(bytes, blobs.snapshot()[key]) }
    }

    @Test fun missingReadOnlyStoresDoNotBootstrapOrPromoteLegacyPackages() {
        val blobs = CountingBlobs()
        val routing = SecureRoutingPolicyStore.readOnly(blobs)
        val diagnostics = EncryptedDiagnosticEventStore.readOnly(blobs)
        assertEquals(0, blobs.reads)
        val source = Phase9Settings(routing = RoutingPreferences(packages = setOf("org.legacy.app")))
        val projected = ProtectedStatePreviewBackupPolicy.projectSettings(source, routing.loadPackages())
        assertTrue(projected.routing.packages.isEmpty())
        assertTrue(diagnostics.load().isEmpty())
        assertEquals(0, blobs.writes)
        assertTrue(blobs.snapshot().isEmpty())
        assertEquals(setOf("org.legacy.app"), source.routing.packages)
    }

    @Test fun deniedWriteCannotEvenReadFromAnUnavailableSnapshot() {
        val noReads = object : SecureBlobReadAccess {
            override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray = error("unexpected read")
            override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean = error("unexpected read")
        }
        val routing = SecureRoutingPolicyStore.readOnly(noReads)
        val diagnostics = EncryptedDiagnosticEventStore.readOnly(noReads)
        assertEquals("READ_ONLY_ROUTING_VIEW", assertThrows(IllegalStateException::class.java) { routing.clear() }.message)
        assertEquals("READ_ONLY_ROUTING_VIEW", assertThrows(IllegalStateException::class.java) { routing.savePackages(emptySet()) }.message)
        assertEquals("READ_ONLY_DIAGNOSTIC_VIEW", assertThrows(IllegalStateException::class.java) { diagnostics.clear() }.message)
        assertEquals("READ_ONLY_DIAGNOSTIC_VIEW", assertThrows(IllegalStateException::class.java) { diagnostics.save(emptyList()) }.message)
    }

    private class PreviewOwnershipFixture {
        val callerBytes = byteArrayOf(7, 11, 13)
        val handle = VerifiedPreviewHandle(17, RedactedProfilePreview(
            "synthetic", "synthetic", "public-summary", "lineage-summary", 1uL, 100, false,
        ))
        val nativeInputs = mutableListOf<ByteArray>()
        var resolveResult: NativeResult<VerifiedPreviewHandle> = NativeResult.Success(handle)
        var releaseResult: NativeResult<Unit> = NativeResult.Success(Unit)
        var resolveFailure: Exception? = null
        var releaseFailure: Exception? = null
        var releases = 0

        fun resolve(input: ByteArray = callerBytes): NativePreviewRequestOutcome =
            ReleasedNativePreviewRequest.resolve(input, { owned ->
                assertNotSame(input, owned)
                nativeInputs += owned
                resolveFailure?.let { throw it }
                resolveResult
            }, { released ->
                assertSame((resolveResult as NativeResult.Success).value, released)
                releases++
                releaseFailure?.let { throw it }
                releaseResult
            })

        fun assertNativeInputsWiped() {
            assertEquals(1, nativeInputs.size)
            assertTrue(nativeInputs.all { bytes -> bytes.all { it == 0.toByte() } })
        }
    }

    private class CountingBlobs : SecureBlobAccess {
        private val entries = mutableMapOf<Pair<String, SecureDataClass>, ByteArray>()
        var reads = 0
        var writes = 0
        fun snapshot() = entries.mapValues { it.value.copyOf() }
        override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) { writes++; entries[localRecordId to dataClass] = exactBytes.copyOf() }
        override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray { reads++; return entries.getValue(localRecordId to dataClass).copyOf() }
        override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean { reads++; return entries.containsKey(localRecordId to dataClass) }
        override fun delete(localRecordId: String, dataClass: SecureDataClass) { writes++; entries.remove(localRecordId to dataClass)?.fill(0) }
        override fun deleteAll() { writes++; entries.values.forEach { it.fill(0) }; entries.clear() }
    }
}
