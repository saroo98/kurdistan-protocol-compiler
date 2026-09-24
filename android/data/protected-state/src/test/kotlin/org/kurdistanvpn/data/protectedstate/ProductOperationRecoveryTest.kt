// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.data.secure.*
import org.kurdistanvpn.core.model.OperationKind

class ProductOperationRecoveryTest {
    @Test fun verifiedOperationTemporaryPrecedesSequenceTwoAndFreshBrokerRetainsIncompleteCandidate() {
        for (settings in listOf(false, true)) {
            val state = BrokerFixture()
            val prior = state.snapshot().encode()
            var temporaryReads = 0
            var returnedCiphertext: ByteArray? = null
            var interruptedBeforeSequenceTwo = false
            state.afterObjectRead = { name, bytes ->
                if (name == operationObjectLeaf(state.journal.readControl().operationId(), 1)) {
                    temporaryReads++
                    returnedCiphertext = checkNotNull(bytes)
                    assertTrue(bytes.any { it != 0.toByte() })
                }
            }
            state.beforeObjectWrite = { name ->
                if (name == operationObjectLeaf(state.journal.readControl().operationId(), 2)) {
                    // persist reaches sequence two only after sequence one's equality/authenticated
                    // decode checks and finally block. The captured reread buffer is now cleared.
                    assertEquals(1, temporaryReads)
                    assertTrue(checkNotNull(returnedCiphertext).all { it == 0.toByte() })
                    assertEquals(1, state.objectWrites)
                    interruptedBeforeSequenceTwo = true
                    error("SYNTHETIC_AFTER_VERIFIED_TEMPORARY")
                }
            }
            val result = if (settings) state.broker().applyProductSettings(2, 0,
                org.kurdistanvpn.core.model.ProductSettings(highContrast = true)).status
            else state.broker().applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100)).status
            assertEquals(ProtectedMutationStatus.DIRTY, result)
            assertTrue(interruptedBeforeSequenceTwo)
            state.afterObjectRead = null; state.beforeObjectWrite = null
            val retry = if (settings) state.broker().recoverProductSettingsConfirmed(false).status
                else state.broker().recoverProductOperationConfirmed(false).status
            assertNotEquals(ProtectedMutationStatus.COMMITTED, retry)
            assertTrue(state.journal.readControl().dirty)
            assertEquals(1, state.objectWrites)
            assertEquals(0, state.projections.publications)
            assertArrayEquals(prior, state.journal.readPriorCheckpointForExplicitRecovery())
            prior.fill(0)
        }
    }
    @Test fun productPostPersistenceInterruptionsNeverCertifyMixedStateAcrossNewBrokers() {
        for (point in listOf("dirty", "intent", "temporary", "object", "observation", "terminal", "clean")) {
            val state = BrokerFixture()
            val prior = state.snapshot().encode()
            var reached = false
            fun interrupt() { reached = true; error("SYNTHETIC_POST_BOUNDARY") }
            state.storage.afterReplace = { name, bytes ->
                if ((point == "dirty" && name == "journal-control" && JournalControl.decode(bytes).dirty) ||
                    (point == "intent" && name.startsWith("journal-intent-")) ||
                    (point == "terminal" && name.startsWith("journal-record-")) ||
                    (point == "clean" && name == "journal-control" && !JournalControl.decode(bytes).dirty)) interrupt()
            }
            state.afterObjectWrite = { name ->
                val operation = state.journal.readControl().operationId()
                if (name == operationObjectLeaf(operation, if (point == "temporary") 1 else 2) &&
                    point in listOf("temporary", "object")) interrupt()
            }
            state.projections.afterRead = {
                if (point == "observation" && state.projections.publications > 0) interrupt()
            }
            val result = state.broker().applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100))
            assertTrue(point, reached)
            assertNotEquals(point, ProtectedMutationStatus.COMMITTED, result.status)
            state.storage.afterReplace = null; state.afterObjectWrite = null; state.projections.afterRead = null
            val expected = stagedCandidate(state, settings = false)
            val retry = state.broker().recoverProductOperationConfirmed(false)
            if (retry.status == ProtectedMutationStatus.COMMITTED) {
                val snapshot = state.snapshot()
                assertArrayEquals(point, checkNotNull(expected), snapshot.encode())
                assertEquals(point, 4L, snapshot.revision)
                val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
                val record = checkNotNull(CrashSafeModeStore.readOnly(blobs).load())
                assertEquals(point, 100L, record.startedEpochHour)
                assertFalse(record.cleanStop); assertEquals(0, record.consecutiveUncleanStarts); assertFalse(record.safeMode)
                state.projections.current.requireMatches(snapshot)
                state.journal.readProjectionWitness(snapshot).requireMatches(snapshot, state.projections.current.physical())
            } else {
                assertTrue(point, state.journal.readControl().dirty || state.snapshot().encode().contentEquals(prior))
            }
            assertTrue(point, state.nativeSecrets.all { bytes -> bytes.all { it == 0.toByte() } })
            assertSyntheticCanariesAbsent(state)
            expected?.fill(0)
            prior.fill(0)
        }
    }
    @Test fun eachSettingsObjectIncludingBootstrapCanInterruptWithoutMixedCommittedSettings() {
        val successful = BrokerFixture()
        assertEquals(ProtectedMutationStatus.COMMITTED, successful.broker().applyProductSettings(2, 0,
            org.kurdistanvpn.core.model.ProductSettings(highContrast = true)).status)
        val sequences = successful.snapshot().objects().map { it.dataClass }
        assertTrue(sequences.contains(26))
        // Sequence one is the preserved v1 settings operation, followed by every staged object.
        for (sequence in 1..successful.objectWrites) {
            val state = BrokerFixture()
            var reached = false
            state.afterObjectWrite = { name ->
                if (name == operationObjectLeaf(state.journal.readControl().operationId(), sequence.toLong())) {
                    reached = true; error("SYNTHETIC_POST_OBJECT")
                }
            }
            val result = state.broker().applyProductSettings(2, 0, org.kurdistanvpn.core.model.ProductSettings(highContrast = true))
            assertTrue("sequence=$sequence", reached)
            assertNotEquals(ProtectedMutationStatus.COMMITTED, result.status)
            state.afterObjectWrite = null
            val expected = stagedCandidate(state, settings = true)
            val retry = state.broker().recoverProductSettingsConfirmed(false)
            if (retry.status == ProtectedMutationStatus.COMMITTED) {
                val snapshot = state.snapshot()
                assertArrayEquals(checkNotNull(expected), snapshot.encode())
                val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
                assertEquals(org.kurdistanvpn.core.model.ProductSettings(highContrast = true), readProductSettings(snapshot, blobs))
                assertEquals(sequences.toSet(), snapshot.objects().map { it.dataClass }.toSet())
                state.projections.current.requireMatches(snapshot)
                state.journal.readProjectionWitness(snapshot).requireMatches(snapshot, state.projections.current.physical())
            } else assertTrue(state.journal.readControl().dirty)
            assertSyntheticCanariesAbsent(state)
            expected?.fill(0)
        }
    }
    @Test fun durableCandidateCannotMakeFailedQuiescenceReleaseSuccessfulOrReviveOldOwner() {
        val state = BrokerFixture()
        val failedOwner = ActiveSessionMutationPolicy(acquireQuiescence = {
            AutoCloseable { error("SYNTHETIC_RELEASE_FAILURE") }
        }, monotonicMillis = { 100L })
        val result = protectedCommandResult {
            state.broker(policy = failedOwner).applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100))
        }
        assertSame(ProtectedStateApplicationFacade.CommandResult.Unproven, result)
        assertFalse(state.journal.readControl().dirty)
        assertNull(failedOwner.reserveMutation())
        val freshOwner = ActiveSessionMutationPolicy { 100L }
        assertEquals(ProtectedMutationStatus.COMMITTED,
            state.broker(policy = freshOwner).recoverProductOperationConfirmed(false).status)
        assertNull(failedOwner.reserveMutation())
        val snapshot = state.snapshot()
        val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
        assertEquals(100L, checkNotNull(CrashSafeModeStore.readOnly(blobs).load()).startedEpochHour)
        assertSyntheticCanariesAbsent(state)
    }
    private fun stagedCandidate(state: BrokerFixture, settings: Boolean): ByteArray? {
        val control = state.journal.readControl()
        val operation = if (control.dirty) control.operationId() else state.snapshot().operationId()
        val encrypted = state.objects[operationObjectLeaf(operation, 1)] ?: return null
        val opened = state.codec.openForOperation(encrypted,
            if (settings) SettingsOperationState.RECORD_ID else ProductOperationState.RECORD_ID,
            SecureDataClass.OPERATION_STATE, state.key, SecureOperationBinding(operation, 4))
        return try {
            if (settings) SettingsOperationState.decode(opened.plaintext).use { it.candidateSnapshot() }
            else ProductOperationState.decode(opened.plaintext).use { it.candidateSnapshot() }
        } finally { opened.plaintext.fill(0); operation.fill(0) }
    }
    @Test fun categorizedRollbackPublishesNewMatchingRolledBackDescriptor() {
        val state = BrokerFixture()
        state.projections.afterPublish = { error("SYNTHETIC_INTERRUPTION") }
        assertEquals(ProtectedMutationStatus.DIRTY, state.broker().applyProductStoreCommand(2,
            ProductStoreCommand.SetDeploymentDisplay(DeploymentDisplayMetadata(emptyList()))).status)
        val identity = state.journal.readControl().operationId().joinToString("") { "%02x".format(it) }
        state.projections.afterPublish = null
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(true).status)
        val raw = state.snapshot().catalogBytes()
        try {
            val descriptor = checkNotNull(org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.decode(raw).operation)
            assertEquals(identity, descriptor.operationId)
            assertEquals("ROLLED_BACK", descriptor.state)
            assertFalse(descriptor.resumable)
        } finally { raw.fill(0) }
    }
    @Test fun categorizedDescriptorIsBoundAndUncategorizedResumeOrRollbackClearsIt() {
        for (rollback in listOf(false, true)) {
            val state = BrokerFixture()
            val display = DeploymentDisplayMetadata(emptyList())
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(2,
                ProductStoreCommand.SetDeploymentDisplay(display)).status)
            val raw = state.snapshot().catalogBytes()
            val operation = try { org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.decode(raw).operation } finally { raw.fill(0) }
            assertNotNull(operation)
            assertEquals("SETTINGS_CHANGE", operation!!.kind)
            assertEquals("APPLIED", operation.state)
            state.projections.afterPublish = { error("SYNTHETIC_INTERRUPTION") }
            assertEquals(ProtectedMutationStatus.DIRTY, state.broker().applyProductStoreCommand(4, ProductStoreCommand.RecordStart(100)).status)
            state.projections.afterPublish = null
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(rollback).status)
            val next = state.snapshot().catalogBytes()
            try {
                assertFalse(org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.isProduct(next))
                assertNull(org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.decode(next).operation)
            } finally { next.fill(0) }
        }
    }
    @Test fun missingTemporaryOrCandidateCiphertextKeepsDirtyAndNeverPublishes() {
        for (temporary in listOf(false, true)) {
            val state = BrokerFixture()
            state.projections.beforePublish = { error("SYNTHETIC_INTERRUPTION") }
            assertEquals(ProtectedMutationStatus.DIRTY, state.broker().applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100)).status)
            state.projections.beforePublish = null
            val operation = state.journal.readControl().operationId()
            state.objects.remove(operationObjectLeaf(operation, if (temporary) 1 else 2))?.fill(0)
            val publications = state.projections.publications
            for (rollback in listOf(false, true)) {
                assertNotEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(rollback).status)
                assertTrue(state.journal.readControl().dirty)
                assertEquals(publications, state.projections.publications)
            }
        }
    }
    @Test fun missingTemporaryBeforeAnyObjectWriteCannotBecomeEmptySuccess() {
        val state = BrokerFixture()
        state.beforeObjectWrite = { error("SYNTHETIC_INTERRUPTION") }
        assertEquals(ProtectedMutationStatus.DIRTY, state.broker().applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100)).status)
        state.beforeObjectWrite = null
        assertEquals(0, state.objectWrites)
        assertNotEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(true).status)
        assertTrue(state.journal.readControl().dirty)
    }
    @Test fun authenticatedWrongDescriptorDoesNotAuthorizeRecovery() {
        val state = BrokerFixture()
        state.projections.beforePublish = { error("SYNTHETIC_INTERRUPTION") }
        assertEquals(ProtectedMutationStatus.DIRTY, state.broker().applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100)).status)
        state.projections.beforePublish = null
        val control = state.journal.readControl()
        val operation = control.operationId()
        val leaf = operationObjectLeaf(operation, 1)
        val binding = SecureOperationBinding(operation, 4)
        val opened = state.codec.openForOperation(state.objects.getValue(leaf), ProductOperationState.RECORD_ID, SecureDataClass.OPERATION_STATE, state.key, binding)
        try { ProductOperationState.decode(opened.plaintext).use { original ->
            val prior = original.priorSnapshot(); val candidate = original.candidateSnapshot()
            try { ProductOperationState(operation, 16, OperationKind.UPDATE, "missing", 0, 100, 2, 4, 0, 0, prior, candidate).use {
                val bytes = it.encode()
                try { state.objects.put(leaf, state.codec.sealForOperation(ProductOperationState.RECORD_ID,
                    SecureDataClass.OPERATION_STATE, bytes, state.key, binding))?.fill(0) } finally { bytes.fill(0) }
            } } finally { prior.fill(0); candidate.fill(0) }
        } } finally { opened.plaintext.fill(0) }
        assertNotEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(false).status)
        assertTrue(state.journal.readControl().dirty)
    }
    @Test fun interruptedProductObservationResumesOrRollsBackAtReservedRevision() {
        for (rollback in listOf(false, true)) {
            val state = BrokerFixture()
            val prior = state.snapshot()
            state.projections.afterPublish = { error("SYNTHETIC_INTERRUPTION") }
            assertEquals(ProtectedMutationStatus.DIRTY, state.broker().applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100)).status)
            state.projections.afterPublish = null
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(rollback).status)
            assertEquals(4L, state.snapshot().revision)
            assertEquals(if (rollback) prior.objects().size else prior.objects().size + 1, state.snapshot().objects().size)
            state.storage.events.clear()
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(rollback).status)
            assertFalse(state.storage.events.any { it.startsWith("write:") })
        }
    }
    @Test fun unrelatedCleanStateIsNotAProductRecoverySuccess() {
        assertNotEquals(ProtectedMutationStatus.COMMITTED, BrokerFixture().broker().recoverProductOperationConfirmed(false).status)
    }
}
