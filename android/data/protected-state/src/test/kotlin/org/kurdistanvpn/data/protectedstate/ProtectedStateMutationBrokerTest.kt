// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.data.metadata.*
import org.kurdistanvpn.data.secure.*
import org.kurdistanvpn.data.settings.SettingsProjectionCodec

internal fun syntheticObjectBinding() = org.kurdistanvpn.data.secure.SecureOperationBinding(ByteArray(32) { 2 }, 2)

class ProtectedStateMutationBrokerTest {
    @Test fun presentationSettingsDoNotRetireActiveOrChangeAuthorityCheckpointAndProjection() {
        val state = BrokerFixture()
        var closes = 0
        state.sessions.register("0a".repeat(16), 1, 2, AutoCloseable { closes++ })
        val control = state.journal.readControl().encode()
        val checkpoint = state.journal.readCheckpoint()
        val settings = SettingsProjectionCodec.toModel(state.snapshot().settingsBytes())
        val result = state.broker().replaceSettings(2, settings.copy(theme = org.kurdistanvpn.core.model.ThemePreference.DARK,
            highContrast = true, reducedMotion = true))
        assertEquals(ProtectedMutationStatus.COMMITTED, result.status)
        assertEquals(0, closes)
        assertArrayEquals(control, state.journal.readControl().encode())
        assertArrayEquals(checkpoint, state.journal.readCheckpoint())
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
        ProtectedPresentationOverlay.read(state.storage::read, ByteArray(16) { 1 })!!.use {
            val merged = it.merge(settings)
            assertEquals(org.kurdistanvpn.core.model.ThemePreference.DARK, merged.theme)
            assertTrue(merged.highContrast); assertTrue(merged.reducedMotion)
            assertEquals(settings.connection, merged.connection)
            assertEquals(settings.routing, merged.routing)
            assertEquals(settings.diagnostics, merged.diagnostics)
        }
    }

    @Test fun sanitizedDiagnosticsDoNotRetireActiveOrWriteAnAuthorityObject() {
        val state = BrokerFixture()
        var closes = 0
        state.sessions.register("0a".repeat(16), 1, 2, AutoCloseable { closes++ })
        val checkpoint = state.journal.readCheckpoint()
        val result = state.broker().replaceDiagnostics(listOf(DiagnosticEvent(1, DiagnosticLogLevel.INFO,
            DiagnosticComponent.APP, "EXPLICIT_EVENT", 10)))
        assertEquals(ProtectedMutationStatus.COMMITTED, result.status)
        assertEquals(0, closes)
        assertEquals(2L, state.journal.readControl().revision)
        assertArrayEquals(checkpoint, state.journal.readCheckpoint())
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
    }

    @Test fun oversizedDiagnosticsAreRejectedBeforeCallerElementsAreReadOrCopied() {
        val state = BrokerFixture()
        var elementRead = false
        val oversized = object : AbstractList<DiagnosticEvent>() {
            override val size: Int = 201
            override fun get(index: Int): DiagnosticEvent {
                elementRead = true
                error("OVERSIZED_CALLER_ELEMENT_READ")
            }
        }

        val result = state.broker().replaceDiagnostics(oversized)

        assertEquals(ProtectedMutationStatus.NO_MUTATION, result.status)
        assertEquals(OperationError.INVALID_INPUT, result.error)
        assertFalse(elementRead)
        assertNull(state.storage.read(ProtectedPresentationOverlay.NAME, JournalLimits.RECORD_BYTES))
    }

    @Test fun automaticConnectionPolicyCannotBeMisclassifiedAsPresentationOnly() {
        val state = BrokerFixture()
        var closes = 0
        state.sessions.register("0a".repeat(16), 1, 2, AutoCloseable { closes++ })
        val settings = SettingsProjectionCodec.toModel(state.snapshot().settingsBytes())
        val result = state.broker().replaceSettings(2, settings.copy(connection = settings.connection.copy(autoConnectOnBoot = true)))
        assertEquals(ProtectedMutationStatus.COMMITTED, result.status)
        assertEquals(1, closes)
        assertEquals(4L, state.journal.readControl().revision)
        assertEquals(1, state.projections.publications)
    }

    @Test fun pendingPresentationKeepsPriorVisibleAndRequiresExplicitRecoveryWithoutRetiringActive() {
        val state = BrokerFixture()
        var closes = 0
        state.sessions.register("0a".repeat(16), 1, 2, AutoCloseable { closes++ })
        val settings = SettingsProjectionCodec.toModel(state.snapshot().settingsBytes())
        val checkpoint = state.journal.readCheckpoint()
        var writes = 0
        state.storage.beforeReplace = { name, _, _ ->
            if (name == ProtectedPresentationOverlay.NAME && ++writes == 2) error("terminal publication refused")
        }
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN,
            state.broker().replaceSettings(2, settings.copy(highContrast = true)).status)
        assertTrue(ProtectedPresentationOverlay.requiresExplicitRecovery(
            state.storage::read,
            ByteArray(16) { 1 },
        ))
        val pending = checkNotNull(state.storage.read(ProtectedPresentationOverlay.NAME, JournalLimits.RECORD_BYTES))
        assertEquals(1, pending[5].toInt())
        ProtectedPresentationOverlay.read(state.storage::read, ByteArray(16) { 1 })!!.use { assertFalse(it.highContrast) }
        state.storage.beforeReplace = null
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN,
            state.broker().replaceDiagnostics(emptyList()).status)
        assertArrayEquals(pending, state.storage.read(ProtectedPresentationOverlay.NAME, JournalLimits.RECORD_BYTES))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverPresentationConfirmed().status)
        assertFalse(ProtectedPresentationOverlay.requiresExplicitRecovery(
            state.storage::read,
            ByteArray(16) { 1 },
        ))
        ProtectedPresentationOverlay.read(state.storage::read, ByteArray(16) { 1 })!!.use { assertTrue(it.highContrast) }
        assertEquals(2, checkNotNull(state.storage.read(ProtectedPresentationOverlay.NAME, JournalLimits.RECORD_BYTES))[5].toInt())
        assertArrayEquals(checkpoint, state.journal.readCheckpoint())
        assertEquals(0, closes); assertEquals(0, state.projections.publications)
    }

    @Test fun presentationWriteReadAndLeaseCloseFailuresNeverReturnSuccessOrChangeAuthority() {
        for (failurePoint in listOf("before-pending", "after-pending", "terminal-reread", "writer-close")) {
            val state = BrokerFixture()
            val control = state.journal.readControl().encode()
            val checkpoint = state.journal.readCheckpoint()
            val settings = SettingsProjectionCodec.toModel(state.snapshot().settingsBytes())
            var writes = 0
            var failRead = false
            val broken = object : JournalStorage by state.storage {
                override fun <T> exclusive(block: () -> T): T {
                    val result = state.storage.exclusive(block)
                    if (failurePoint == "writer-close") error("ambiguous writer close")
                    return result
                }
                override fun read(name: String, maximum: Int): ByteArray? {
                    if (name == ProtectedPresentationOverlay.NAME && failRead) error("independent reopen unavailable")
                    return state.storage.read(name, maximum)
                }
                override fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray) {
                    if (name == ProtectedPresentationOverlay.NAME) {
                        writes++
                        if (failurePoint == "before-pending" && writes == 1) error("write unavailable")
                    }
                    state.storage.compareAndReplace(name, expected, replacement)
                    if (name == ProtectedPresentationOverlay.NAME && failurePoint == "after-pending" && writes == 1)
                        error("publication acknowledgement lost")
                    if (name == ProtectedPresentationOverlay.NAME && failurePoint == "terminal-reread" && writes == 2)
                        failRead = true
                }
            }
            assertEquals(failurePoint, ProtectedMutationStatus.MUTATION_UNPROVEN,
                state.broker(broken).replaceSettings(2, settings.copy(reducedMotion = true)).status)
            assertArrayEquals(control, state.journal.readControl().encode())
            assertArrayEquals(checkpoint, state.journal.readCheckpoint())
            assertEquals(0, state.objectWrites); assertEquals(0, state.projections.publications)
        }
    }

    @Test fun presentationCodecRejectsMalformedOversizeForeignStoreAndIllegalEffects() {
        val state = BrokerFixture()
        val settings = SettingsProjectionCodec.toModel(state.snapshot().settingsBytes())
        assertEquals(ProtectedMutationStatus.COMMITTED,
            state.broker().replaceSettings(2, settings.copy(highContrast = true)).status)
        val canonical = checkNotNull(state.storage.read(ProtectedPresentationOverlay.NAME, JournalLimits.RECORD_BYTES))
        assertEquals(97, canonical.size)
        val variants = listOf(canonical + 0,
            canonical.clone().also { it[4] = 2 }, canonical.clone().also { it[5] = 0 },
            canonical.clone().also { java.nio.ByteBuffer.wrap(it).putLong(22, 0) },
            canonical.clone().also { it.fill(0, 30, 62) }, canonical.clone().also { it[62] = 3 },
            canonical.clone().also { java.nio.ByteBuffer.wrap(it).putInt(63, Int.MAX_VALUE) },
            canonical.clone().also { it[85] = 2 },
            canonical.clone().also { it[62] = 2 }, // Diagnostics command is not permitted to change contrast.
            ByteArray(JournalLimits.RECORD_BYTES + 1))
        for ((index, bytes) in variants.withIndex()) assertThrows("variant $index", Exception::class.java) {
            ProtectedPresentationOverlay.read({ _, _ -> bytes.clone() }, ByteArray(16) { 1 })?.close()
        }
        for (length in canonical.indices) assertThrows("prefix $length", Exception::class.java) {
            ProtectedPresentationOverlay.read({ _, _ -> canonical.copyOf(length) }, ByteArray(16) { 1 })?.close()
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProtectedPresentationOverlay.read(state.storage::read, ByteArray(16) { 2 })?.close()
        }
        val count = state.storage.events.count { it.startsWith("write:") }
        val invalid = state.broker().replaceDiagnostics(
            List(201) { DiagnosticEvent(it + 1L, DiagnosticLogLevel.INFO, DiagnosticComponent.APP, "EXPLICIT_EVENT", 10) })
        assertEquals(ProtectedMutationStatus.NO_MUTATION, invalid.status)
        assertEquals(OperationError.INVALID_INPUT, invalid.error)
        assertEquals(count, state.storage.events.count { it.startsWith("write:") })
    }

    @Test fun scopedMutationsAndCompactionPreservePresentationWithoutMakingItAnAuthorityObject() {
        val state = BrokerFixture(pendingReset = true)
        val settings = SettingsProjectionCodec.toModel(state.snapshot().settingsBytes())
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().replaceSettings(2,
            settings.copy(reducedMotion = true)).status)
        val overlay = checkNotNull(state.storage.read(ProtectedPresentationOverlay.NAME, JournalLimits.RECORD_BYTES))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().resetProfiles(setOf("profile-other")).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().resetPendingCredentials().status)
        val checkpoint = state.journal.readCheckpoint()
        assertEquals(ProtectedMutationStatus.COMMITTED, state.journal.compact { checkpoint.clone() })
        assertArrayEquals(overlay, state.storage.read(ProtectedPresentationOverlay.NAME, JournalLimits.RECORD_BYTES))
        assertFalse(state.snapshot().objects().any { it.logicalId == ProtectedPresentationOverlay.NAME })
        ProtectedPresentationOverlay.read(state.storage::read, ByteArray(16) { 1 })!!.use { assertTrue(it.reducedMotion) }
    }

    @Test fun securityAndPresentationSettingsResetReportsBothUpdatesWithoutDiscardingDiagnostics() {
        val state = BrokerFixture()
        val settings = SettingsProjectionCodec.toModel(state.snapshot().settingsBytes())
        val events = listOf(DiagnosticEvent(1, DiagnosticLogLevel.INFO, DiagnosticComponent.APP, "EXPLICIT_EVENT", 10))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().replaceDiagnostics(events).status)
        assertEquals(ProtectedMutationStatus.COMMITTED,
            state.broker().replaceSettings(2, settings.copy(highContrast = true)).status)
        val mixed = settings.copy(connection = settings.connection.copy(autoConnectOnBoot = true))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().replaceSettings(2, mixed).status)
        assertEquals(4L, state.journal.readControl().revision)
        ProtectedPresentationOverlay.read(state.storage::read, ByteArray(16) { 1 })!!.use {
            assertFalse(it.highContrast); assertEquals(events, it.events())
        }
    }

    @Test fun restoreKeyInvalidationAtEachPreparedStagePreservesExactPriorCommittedState() {
        val stages = listOf(
            "marker-write", "marker-open", "profile-input-write", "profile-staged-write",
            "profile-staged-open", "profile-active-write", "profile-active-open",
            "profile-preview-write", "profile-preview-open", "recipient-binding-index", "rollback-index",
        )
        for (stage in stages) {
            val state = BrokerFixture(pendingReset = true, restoreNative = true)
            val control = state.journal.readControl().encode()
            val checkpoint = state.journal.readCheckpoint()
            val objects = state.objects.mapValues { it.value.clone() }
            val projection = state.projections.current.copyOwned()
            var restoring = false
            var indexWrites = 0
            var injected = 0
            state.rejectRestoreSecond = stage == "rollback-index"
            state.keyBoundary = { action, id, role ->
                if (action == "wrap" && role == SecureDataClass.RESTORE_BATCH) restoring = true
                if (restoring && action == "wrap" && role == SecureDataClass.RECIPIENT_KEY_INDEX) indexWrites++
                val matches = restoring && when (stage) {
                    "marker-write" -> action == "wrap" && role == SecureDataClass.RESTORE_BATCH
                    "marker-open" -> action == "unwrap" && role == SecureDataClass.RESTORE_BATCH
                    "profile-input-write" -> action == "wrap" && role == SecureDataClass.IMPORT_REQUEST
                    "profile-staged-write" -> action == "wrap" && role == SecureDataClass.ACTIVATION_STAGED
                    "profile-staged-open" -> action == "unwrap" && role == SecureDataClass.ACTIVATION_STAGED
                    "profile-active-write" -> action == "wrap" && role == SecureDataClass.ACTIVATION_ACTIVE
                    "profile-active-open" -> action == "unwrap" && role == SecureDataClass.ACTIVATION_ACTIVE && id !in setOf("profile-kept", "profile-other")
                    "profile-preview-write" -> action == "wrap" && role == SecureDataClass.PROFILE_PREVIEW
                    "profile-preview-open" -> action == "unwrap" && role == SecureDataClass.PROFILE_PREVIEW && id !in setOf("profile-kept", "profile-other")
                    "recipient-binding-index" -> action == "wrap" && role == SecureDataClass.RECIPIENT_KEY_INDEX && indexWrites == 1
                    "rollback-index" -> action == "wrap" && role == SecureDataClass.RECIPIENT_KEY_INDEX && indexWrites == 2
                    else -> false
                }
                if (matches && injected++ == 0) throw KeyInvalidatedException(IllegalStateException("synthetic $stage invalidation"))
            }
            val payload = restorePayload(state.rejectRestoreSecond)
            val outcome = try { state.broker().restoreBackup(payload) } finally { payload.fill(0) }
            assertTrue("stage never reached: $stage", injected > 0)
            assertNotEquals(stage, ProtectedMutationStatus.COMMITTED, outcome.status)
            assertArrayEquals(stage, control, state.journal.readControl().encode())
            assertArrayEquals(stage, checkpoint, state.journal.readCheckpoint())
            assertTrue(stage, projection.sameContent(state.projections.current))
            assertEquals(stage, 0, state.projections.publications)
            assertEquals(stage, 0, state.objectWrites)
            assertEquals(stage, 0, state.recipientCreations)
            assertEquals(stage, objects.keys, state.objects.keys)
            objects.forEach { (name, bytes) -> assertArrayEquals(stage, bytes, state.objects[name]) }
            assertEquals(stage, state.activationOpens, state.activationCloses)
            assertEquals(stage, state.verificationHandles, state.verificationReleases)
            assertTrue(stage, state.nativeSecrets.all { bytes -> bytes.all { it == 0.toByte() } })
        }
    }

    @Test fun restoreKeyInvalidationAfterDurableDirtyNeverPublishesCleanAndKeepsPriorObjects() {
        for (stage in listOf("room-publication-before", "room-publication-after", "durable-profile-reread")) {
            val state = BrokerFixture(pendingReset = true, restoreNative = true)
            val prior = state.objects.mapValues { it.value.clone() }
            var injected = 0
            val failure = {
                assertTrue(state.journal.readControl().dirty)
                assertEquals(MutationKind.RESTORE, state.journal.readControl().kind)
                injected++
                throw KeyInvalidatedException(IllegalStateException("synthetic $stage invalidation"))
            }
            when (stage) {
                "room-publication-before" -> state.projections.beforePublish = failure
                "room-publication-after" -> state.projections.afterPublish = failure
                else -> state.keyBoundary = { action, _, role ->
                    if (action == "unwrap" && role == SecureDataClass.IMPORT_REQUEST && state.objectWrites > 0 && injected == 0) failure()
                }
            }
            val payload = restorePayload(false)
            val result = try { state.broker().restoreBackup(payload) } finally { payload.fill(0) }
            assertEquals(stage, 1, injected)
            assertEquals(stage, ProtectedMutationStatus.DIRTY, result.status)
            assertTrue(stage, state.journal.readControl().dirty)
            assertEquals(stage, 3L, state.journal.readControl().revision)
            assertThrows(IllegalStateException::class.java) { state.journal.readCheckpoint() }
            prior.forEach { (name, bytes) -> assertArrayEquals(stage, bytes, state.objects[name]) }
            assertEquals(stage, 0, state.recipientCreations)
            assertEquals(stage, state.activationOpens, state.activationCloses)
            assertEquals(stage, state.verificationHandles, state.verificationReleases)
            assertTrue(stage, state.nativeSecrets.all { bytes -> bytes.all { it == 0.toByte() } })
        }
    }

    @Test fun pendingCredentialResetPreservesProfilesBoundKeyRoutingDiagnosticsAndSettings() {
        val state = BrokerFixture(pendingReset = true)
        val before = state.snapshot()
        val previousObjects = state.objects.mapValues { it.value.clone() }
        val beforeKeys = state.readKeys(before).list()
        assertEquals(setOf(ClientKeyStatus.REQUEST_READY, ClientKeyStatus.AWAITING_PROFILE,
            ClientKeyStatus.PROFILE_VERIFIED), beforeKeys.map { it.status }.toSet())
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
        var retired = 0
        state.sessions.register("0b".repeat(16), 1, before.revision, AutoCloseable {
            assertTrue(state.journal.readControl().dirty)
            assertEquals(MutationKind.CREDENTIAL_DELETE, state.journal.readControl().kind)
            assertEquals(0, state.objectWrites)
            retired++
        })
        val outcome = state.broker().resetPendingCredentials()
        assertEquals(ProtectedMutationStatus.COMMITTED, outcome.status)
        assertEquals(2, outcome.value)
        assertEquals(1, retired)
        val after = state.snapshot()
        assertEquals(before.revision + 2, after.revision)
        assertArrayEquals(before.settingsBytes(), after.settingsBytes())
        val beforeRows = ProfileCatalogProjectionCodec.decode(before.catalogBytes())
        val afterRows = ProfileCatalogProjectionCodec.decode(after.catalogBytes())
        assertEquals(beforeRows.map { it.localRecordId to it.health }, afterRows.map { it.localRecordId to it.health })
        assertEquals(listOf("bound-key"), state.readKeys(after).list().map { it.localRecordId })
        assertEquals(ClientKeyStatus.PROFILE_VERIFIED, state.readKeys(after).list().single().status)
        state.readKeys(after).credentialsForProfile("profile-kept")!!.use { assertEquals("bound-key", it.localRecordId) }
        val untouched = before.objects().filter { it.dataClass != SecureDataClass.RECIPIENT_KEY_INDEX.wireValue &&
            it.logicalId !in setOf("pending-ready", "pending-awaiting") }
        untouched.forEach { old -> assertEquals(old.physicalId,
            after.objects().single { it.dataClass == old.dataClass && it.logicalId == old.logicalId }.physicalId) }
        previousObjects.forEach { (name, bytes) -> assertArrayEquals(bytes, state.objects[name]) }
    }

    @Test fun scopedProfileResetPreservesBothPendingEnrollmentStatesAndUnrelatedData() {
        val state = BrokerFixture(pendingReset = true)
        val before = state.snapshot()
        val result = state.broker().resetProfiles(setOf("profile-kept"))
        assertEquals(ProtectedMutationStatus.COMMITTED, result.status)
        val after = state.snapshot()
        assertEquals(setOf("pending-ready", "pending-awaiting"), state.readKeys(after).list().map { it.localRecordId }.toSet())
        assertEquals(setOf(ClientKeyStatus.REQUEST_READY, ClientKeyStatus.AWAITING_PROFILE),
            state.readKeys(after).list().map { it.status }.toSet())
        assertEquals(listOf("profile-other"), ProfileCatalogProjectionCodec.decode(after.catalogBytes()).map { it.localRecordId })
        for (old in before.objects().filter { it.dataClass in setOf(SecureDataClass.ROUTING_POLICY.wireValue,
            SecureDataClass.DIAGNOSTIC_EVENTS.wireValue) || it.logicalId == "profile-other" }) {
            assertEquals(old.physicalId, after.objects().single { it.logicalId == old.logicalId && it.dataClass == old.dataClass }.physicalId)
        }
    }

    @Test fun inconsistentPendingResetCannotDeleteOrRepairAnyAuthenticatedRecord() {
        for (fault in listOf("missing-material", "missing-index", "prepared", "conflicting-status", "tampered-object")) {
            val state = BrokerFixture(pendingReset = true, seedFault = fault)
            val before = state.objects.mapValues { it.value.clone() }
            val oldControl = state.journal.readControl().encode()
            assertNotEquals(fault, ProtectedMutationStatus.COMMITTED, state.broker().resetPendingCredentials().status)
            assertArrayEquals(fault, oldControl, state.journal.readControl().encode())
            assertEquals(fault, 0, state.objectWrites)
            assertEquals(fault, 0, state.projections.publications)
            before.forEach { (name, bytes) -> assertArrayEquals(fault, bytes, state.objects[name]) }
        }
    }

    @Test fun invalidatedRecipientMaterialRejectsPendingResetWithoutPublication() {
        val state = BrokerFixture(pendingReset = true)
        state.rejectRecipient = true
        assertNotEquals(ProtectedMutationStatus.COMMITTED, state.broker().resetPendingCredentials().status)
        assertEquals(2L, state.journal.readControl().revision)
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
    }

    @Test fun pendingResetWithUnprovenRetirementStaysDirtyAndPreservesAllPriorObjects() {
        val state = BrokerFixture(pendingReset = true)
        val before = state.objects.mapValues { it.value.clone() }
        state.sessions.register("0c".repeat(16), 1, 2, AutoCloseable { error("synthetic cleanup uncertainty") })
        assertEquals(ProtectedMutationStatus.DIRTY, state.broker().resetPendingCredentials().status)
        assertTrue(state.journal.readControl().dirty)
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
        before.forEach { (name, bytes) -> assertArrayEquals(bytes, state.objects[name]) }
        assertThrows(IllegalStateException::class.java) { state.journal.readCheckpoint() }
    }

    @Test fun failedPendingResetPublicationCannotClaimSuccessOrDeleteRecoverablePriorState() {
        val state = BrokerFixture(pendingReset = true)
        val before = state.objects.mapValues { it.value.clone() }
        state.projections.failPublication = true
        assertEquals(ProtectedMutationStatus.DIRTY, state.broker().resetPendingCredentials().status)
        assertTrue(state.journal.readControl().dirty)
        assertEquals(1, state.projections.publications)
        before.forEach { (name, bytes) -> assertArrayEquals(bytes, state.objects[name]) }
        assertNotEquals(ProtectedMutationStatus.COMMITTED, state.broker().resetPendingCredentials().status)
        assertThrows(IllegalStateException::class.java) { state.journal.readCheckpoint() }
    }

    @Test fun repeatedConfirmedPendingResetCannotDeleteBoundCredential() {
        val state = BrokerFixture(pendingReset = true)
        assertEquals(2, state.broker().resetPendingCredentials().value)
        val repeated = state.broker().resetPendingCredentials()
        assertEquals(ProtectedMutationStatus.COMMITTED, repeated.status)
        assertEquals(0, repeated.value)
        assertEquals(listOf("bound-key"), state.readKeys(state.snapshot()).list().map { it.localRecordId })
    }

    @Test fun confirmedImportCannotCrossStoreEpochOrRevisionAndNeverReachesNative() {
        val state = BrokerFixture()
        val current = ProtectedStateSnapshot.decode(state.journal.readCheckpoint())
        val display = org.kurdistanvpn.core.model.RedactedProfilePreview("synthetic", "synthetic", "a", "b", 1u, 1_900_000_000, false)
        for (candidate in listOf(
            ProtectedStateSnapshot.create(ByteArray(16) { 7 }, current.revision, null, current.objects(),
                current.settingsBytes(), current.catalogBytes(), current.operationId()),
            ProtectedStateSnapshot.create(current.storeId(), current.revision + 2, null, current.objects(),
                current.settingsBytes(), current.catalogBytes(), current.operationId()),
        )) {
            ConfirmedProtectedImport.owned(byteArrayOf(1, 2), display, null, candidate).use { confirmation ->
                val result = state.broker().importProfile(confirmation)
                assertEquals(ProtectedMutationStatus.NO_MUTATION, result.status)
                assertEquals(org.kurdistanvpn.core.model.OperationError.RECOVERY_REQUIRED, result.error)
                assertThrows(IllegalStateException::class.java) { confirmation.takeRequest() }
            }
        }
        assertEquals(2L, state.journal.readControl().revision)
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
    }

    @Test fun securityMutationRetiresTheActiveOwnerAfterVerifiedDirtyAndIntentBeforeProductWrites() {
        val state = BrokerFixture()
        var stops = 0
        state.storage.events.clear()
        state.sessions.register("01".repeat(16), 1, 2, AutoCloseable {
            assertEquals(listOf("write:journal-control", "read:journal-control",
                "write:journal-intent-0000000000000002", "read:journal-intent-0000000000000002"),
                state.storage.events.takeLast(4))
            assertEquals(3L, state.journal.readControl().revision)
            assertEquals(0, state.objectWrites)
            assertEquals(0, state.projections.publications)
            stops++
        })
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().replaceRouting(setOf("example.safe")))
        assertEquals(1, stops)
    }

    @Test fun uncertainActiveCleanupLeavesDurableDirtyAndCannotWriteProductState() {
        val state = BrokerFixture()
        var attempts = 0
        val session = state.sessions.register("02".repeat(16), 1, 2, AutoCloseable {
            attempts++
            if (attempts == 1) error("synthetic uncertain cleanup")
        })!!
        val final = state.sessions.acquireFinalLease(session, 2, 200)!!
        final.close()
        assertEquals(ProtectedMutationStatus.DIRTY, state.broker().replaceRouting(setOf("example.safe")))
        assertEquals(3L, state.journal.readControl().revision)
        assertFalse(final.validate(2))
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
        assertThrows(IllegalStateException::class.java) { state.journal.readCheckpoint() }
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, state.broker().replaceRouting(setOf("another.safe")))
        assertEquals(1, attempts)
        session.close()
        session.close()
        assertEquals(2, attempts)
        assertEquals(3L, state.journal.readControl().revision)
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
    }

    @Test fun failedDirtyPublicationPreservesCleanAndDoesNotCallPriorOwnerCleanup() {
        val state = BrokerFixture()
        var closes = 0
        val session = state.sessions.register("03".repeat(16), 1, 2, AutoCloseable { closes++ })!!
        state.storage.beforeReplace = { name, _, _ ->
            if (name == "journal-control") error("synthetic failure before DIRTY write")
        }
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, state.broker().replaceRouting(setOf("example.safe")))
        assertEquals(2L, state.journal.readControl().revision)
        assertEquals(0, closes)
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
        session.close()
        assertEquals(1, closes)
    }

    @Test fun failedIntentPublicationLeavesDirtyWithoutCallingPriorOwnerCleanup() {
        val state = BrokerFixture()
        var closes = 0
        state.sessions.register("04".repeat(16), 1, 2, AutoCloseable { closes++ })
        state.storage.beforeReplace = { name, _, _ ->
            if (name == "journal-intent-0000000000000002") error("synthetic failed intent write")
        }
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, state.broker().replaceRouting(setOf("example.safe")))
        assertEquals(3L, state.journal.readControl().revision)
        assertEquals(0, closes)
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
    }

    @Test fun failedDirtyOrIntentRereadCannotCallCleanupOrWriteProductState() {
        for (corruptedLeaf in listOf("journal-control", "journal-intent-0000000000000002")) {
            val state = BrokerFixture()
            var closes = 0
            state.sessions.register("09".repeat(16), 1, 2, AutoCloseable { closes++ })
            state.storage.beforeReplace = { name, _, _ ->
                if (name == corruptedLeaf) state.storage.corruptNextWrite = true
            }
            assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN,
                state.broker().replaceRouting(setOf("example.safe")))
            assertEquals(0, closes)
            assertEquals(0, state.objectWrites)
            assertEquals(0, state.projections.publications)
            if (corruptedLeaf == "journal-control") {
                assertThrows(IllegalArgumentException::class.java) { state.journal.readCheckpoint() }
            } else {
                assertThrows(IllegalStateException::class.java) { state.journal.readCheckpoint() }
                assertEquals(3L, state.journal.readControl().revision)
            }
        }
    }

    @Test fun reservationExcludesConcurrentAdmissionBeforeDirtyWithoutStartingCleanup() {
        val state = BrokerFixture()
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val result = java.util.concurrent.atomic.AtomicReference<ProtectedMutationStatus>()
        var closes = 0
        val session = state.sessions.register("05".repeat(16), 1, 2, AutoCloseable { closes++ })!!
        val final = state.sessions.acquireFinalLease(session, 2, 200)!!
        final.close()
        state.storage.beforeReplace = { name, _, _ ->
            if (name == "journal-control") {
                entered.countDown()
                check(release.await(2, java.util.concurrent.TimeUnit.SECONDS))
                error("synthetic pre-DIRTY failure after admission observation")
            }
        }
        val thread = Thread { result.set(state.broker().replaceRouting(setOf("example.safe"))) }.also { it.start() }
        assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS))
        try {
            assertEquals(0, closes)
            assertFalse(final.validate(2))
            assertNull(state.sessions.acquireFinalLease(session, 2, 200))
            var rejectedClose = 0
            assertNull(state.sessions.register("06".repeat(16), 1, 2, AutoCloseable { rejectedClose++ }))
            assertEquals(1, rejectedClose)
            assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN,
                state.broker().replaceRouting(setOf("concurrent.safe")))
        } finally { release.countDown(); thread.join(2000) }
        assertFalse(thread.isAlive)
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, result.get())
        assertEquals(2L, state.journal.readControl().revision)
        assertEquals(0, closes)
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
    }

    @Test fun cleanupAfterDirtyDoesNotHoldAdmissionMonitorOrAllowConcurrentMutation() {
        val state = BrokerFixture()
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val result = java.util.concurrent.atomic.AtomicReference<ProtectedMutationStatus>()
        val session = state.sessions.register("07".repeat(16), 1, 2, AutoCloseable {
            assertEquals(3L, state.journal.readControl().revision)
            entered.countDown()
            check(release.await(2, java.util.concurrent.TimeUnit.SECONDS))
        })!!
        val final = state.sessions.acquireFinalLease(session, 2, 200)!!
        final.close()
        val thread = Thread { result.set(state.broker().replaceRouting(setOf("example.safe"))) }.also { it.start() }
        assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS))
        try {
            assertFalse(final.validate(2))
            assertNull(state.sessions.register("07".repeat(16), 1, 2, AutoCloseable {}))
            assertNull(state.sessions.register("08".repeat(16), 1, 2, AutoCloseable {}))
            assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN,
                state.broker().replaceRouting(setOf("concurrent.safe")))
            assertEquals(0, state.objectWrites)
            assertEquals(0, state.projections.publications)
        } finally { release.countDown(); thread.join(2000) }
        assertFalse(thread.isAlive)
        assertEquals(ProtectedMutationStatus.COMMITTED, result.get())
        assertEquals(4L, state.journal.readControl().revision)
    }

    @Test fun missingProfileDeletionNeverPublishesDirtyOrTouchesObjects() {
        val state = BrokerFixture()
        var closes = 0
        state.sessions.register("0a".repeat(16), 1, 2, AutoCloseable { closes++ })
        val outcome = state.broker().deleteProfile("missing-profile")
        assertEquals(ProtectedMutationStatus.NO_MUTATION, outcome.status)
        assertEquals(2L, state.journal.readControl().revision)
        assertEquals(0, state.objectWrites)
        assertEquals(0, closes)
    }

    @Test fun enrollmentIndexAndMaterialAreOneCommittedOperationAndFailureCannotLeakPreparedState() {
        val state = BrokerFixture()
        val first = state.broker().createEnrollment(600, 1_800_000_000)
        assertEquals(ProtectedMutationStatus.COMMITTED, first.status)
        val snapshot = ProtectedStateSnapshot.decode(state.journal.readCheckpoint())
        assertEquals(setOf(4, 13), snapshot.objects().map { it.dataClass }.toSet())
        val reader = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
        val keys = org.kurdistanvpn.data.secure.ClientKeyBundleStore.readOnly(reader,
            org.kurdistanvpn.data.secure.KurdRecipientKeyNative(state.native))
        assertEquals(org.kurdistanvpn.data.secure.ClientKeyStatus.REQUEST_READY, keys.list().single().status)
        val writes = state.objectWrites
        val duplicate = state.broker().createEnrollment(600, 1_800_000_000)
        assertEquals(ProtectedMutationStatus.NO_MUTATION, duplicate.status)
        assertEquals(org.kurdistanvpn.core.model.OperationError.DUPLICATE, duplicate.error)
        assertEquals(writes, state.objectWrites)
        assertEquals(4L, state.journal.readControl().revision)
    }

    @Test fun routingPlanCannotWriteBeforeDirtyAndIndependentProjectionMismatchPreventsClean() {
        val state = BrokerFixture()
        val broker = state.broker()
        state.projections.failPublication = true
        assertEquals(ProtectedMutationStatus.DIRTY, broker.replaceRouting(setOf("example.safe")))
        assertTrue(state.journal.readControl().dirty)
        assertEquals(1, state.objectWrites)
        assertEquals(1, state.projections.publications)
        assertThrows(IllegalStateException::class.java) { state.journal.readCheckpoint() }
    }

    @Test fun committedBrokerRoutingUsesImmutableObjectsAndFreshProjectionRead() {
        val state = BrokerFixture()
        val broker = state.broker()
        val input = linkedSetOf("example.safe")
        assertEquals(ProtectedMutationStatus.COMMITTED, broker.replaceRouting(input))
        input.clear()
        val snapshot = ProtectedStateSnapshot.decode(state.journal.readCheckpoint())
        assertEquals(4L, snapshot.revision)
        assertEquals(1, snapshot.objects().size)
        val view = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
        assertEquals(setOf("example.safe"), org.kurdistanvpn.data.secure.SecureRoutingPolicyStore.readOnly(view).loadPackages())
        state.projections.current.witness!!.requireMatches(snapshot)
        assertTrue(state.projections.reads >= 3)
    }

    @Test fun brokerRejectsWrongExistingProjectionWithoutBeginningMutation() {
        val state = BrokerFixture()
        state.projections.current = ProjectionImages(byteArrayOf(3), byteArrayOf(9), null)
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, state.broker().replaceRouting(setOf("example.safe")))
        assertEquals(2L, state.journal.readControl().revision)
        assertEquals(0, state.objectWrites)
        assertEquals(0, state.projections.publications)
    }
    @Test fun dirtyMustBeIndependentlyRereadBeforeProductMutation() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        disk.corruptNextWrite = true
        var writes = 0
        val result = journal.mutate(MutationKind.PROFILE_IMPORT, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(9),
            mutation = { writes++ }, reconstruct = { byteArrayOf(9) })
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, result)
        assertEquals(0, writes)
    }
    @Test fun productFailureLeavesDirtyAndRejectsNextOperationAcrossNewInstance() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        assertEquals(ProtectedMutationStatus.DIRTY, journal.mutate(MutationKind.PROFILE_IMPORT,
            ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(9), { error("synthetic failure") }, { byteArrayOf(9) }))
        var writes = 0
        assertEquals(ProtectedMutationStatus.DIRTY, ProtectedStateOperationJournal(disk).mutate(
            MutationKind.PROFILE_DELETE, ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(8), { writes++ }, { byteArrayOf(8) }))
        assertEquals(0, writes)
        assertEquals(1L, journal.readControl().revision)
    }
    @Test fun writerReturnCannotCertifyCleanWhenIndependentReconstructionDisagrees() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        assertEquals(ProtectedMutationStatus.DIRTY, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(9), {}, { byteArrayOf(8) }))
        assertTrue(journal.readControl().dirty)
    }
    @Test fun successfulMutationBindsExactOperationAndFreshReread() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        var product = byteArrayOf(0)
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(9), { product = byteArrayOf(9) }, { product.clone() }))
        assertEquals(2L, journal.readControl().revision)
        assertFalse(journal.readControl().dirty)
        assertArrayEquals(byteArrayOf(9), journal.readCheckpoint())
    }
}

private class BrokerFixture(pendingReset: Boolean = false, seedFault: String? = null, restoreNative: Boolean = false) {
    val sessions = ActiveSessionMutationPolicy { 100 }
    val storage = MemoryJournalStorage()
    val journal = ProtectedStateOperationJournal(storage)
    val objects = linkedMapOf<String, ByteArray>()
    val codec = org.kurdistanvpn.data.secure.SecureEnvelopeCodec()
    var keyBoundary: ((String, String, SecureDataClass) -> Unit)? = null
    val key: KeyEncryptionKey = object : KeyEncryptionKey {
        private val delegate = JournalTestKey()
        override val generation = delegate.generation
        override val hardwareSecurityLevel = delegate.hardwareSecurityLevel
        override fun wrap(recordId: String, dataClass: SecureDataClass, key: ByteArray): WrappedKey {
            keyBoundary?.invoke("wrap", recordId, dataClass)
            return delegate.wrap(recordId, dataClass, key)
        }
        override fun unwrap(recordId: String, dataClass: SecureDataClass, wrapped: WrappedKey): ByteArray {
            keyBoundary?.invoke("unwrap", recordId, dataClass)
            return delegate.unwrap(recordId, dataClass, wrapped)
        }
    }
    val projections: MemoryProjectionAccess
    var objectWrites = 0
    var rejectRecipient = false
    var rejectRestoreSecond = false
    var recipientCreations = 0
    var verificationHandles = 0
    var verificationReleases = 0
    var activationOpens = 0
    var activationCloses = 0
    val nativeSecrets = mutableListOf<ByteArray>()
    val native = java.lang.reflect.Proxy.newProxyInstance(
        org.kurdistanvpn.core.nativeapi.KurdNativeCore::class.java.classLoader,
        arrayOf(org.kurdistanvpn.core.nativeapi.KurdNativeCore::class.java),
    ) { _, method, args -> when (method.name) {
        "validateRecipient" -> {
            nativeSecrets += args!![0] as ByteArray; nativeSecrets += args[1] as ByteArray
            if (rejectRecipient) NativeResult.Failure(OperationError.KEY_INVALIDATED) else NativeResult.Success(Unit)
        }
        "createRecipient" -> { recipientCreations++; org.kurdistanvpn.core.nativeapi.NativeResult.Success(object : org.kurdistanvpn.core.nativeapi.NativeRecipient {
            override fun publicRequest() = org.kurdistanvpn.core.nativeapi.NativeResult.Success(byteArrayOf(11, 12))
            override fun privateBundle() = org.kurdistanvpn.core.nativeapi.NativeResult.Success(byteArrayOf(13, 14))
            override fun cancel() = org.kurdistanvpn.core.nativeapi.NativeResult.Success(Unit)
            override fun close() = Unit
        }) }
        "verifyPreview" -> { check(restoreNative); NativeResult.Failure(OperationError.TRUST_REJECTED) }
        "verifyPreviewWithRecipient" -> {
            check(restoreNative)
            val input = args!![0] as ByteArray
            val request = args[1] as ByteArray
            val private = args[2] as ByteArray
            nativeSecrets += request; nativeSecrets += private
            if ((rejectRestoreSecond && input.firstOrNull() == 99.toByte()) ||
                !request.contentEquals(byteArrayOf(1, 11)) || !private.contentEquals(byteArrayOf(1, 12))) {
                NativeResult.Failure(OperationError.TRUST_REJECTED)
            } else {
                verificationHandles++
                NativeResult.Success(VerifiedPreviewHandle(verificationHandles.toLong(),
                    RedactedProfilePreview("sealed-device", "device-recipient", "new-synthetic-content",
                        "new-synthetic-lineage", 1uL, 1_900_000_000, true)))
            }
        }
        "releaseVerified" -> { check(restoreNative); verificationReleases++; NativeResult.Success(Unit) }
        "openActivation" -> {
            check(restoreNative); activationOpens++
            NativeResult.Success(ScriptedRestoreActivation { activationCloses++ })
        }
        else -> error("Unexpected native operation: ${method.name}")
    } } as org.kurdistanvpn.core.nativeapi.KurdNativeCore
    init {
        val seed = if (pendingReset) pendingResetSeed(seedFault) else null
        val references = seed?.first?.entries?.mapIndexed { index, (identity, plaintext) ->
            val physical = "object-seed-$index"
            val binding = syntheticObjectBinding()
            val encrypted = codec.sealForOperation(identity.first, identity.second, plaintext, key, binding)
            plaintext.fill(0)
            objects[physical] = encrypted
            ProtectedObjectReference.fromEncryptedObject(identity.second.wireValue, identity.first,
                physical, key.generation, encrypted, binding)
        }.orEmpty()
        if (seedFault == "tampered-object") objects.values.first().let { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        journal.initialize(ByteArray(16) { 1 })
        val settings = if (seed == null) Phase9Settings() else Phase9Settings(profiles =
            ProfilePreferences("profile-kept", setOf("profile-kept", "profile-other")))
        val initial = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, settings.profiles.activeLocalRecordId, references,
            SettingsProjectionCodec.fromModel(settings),
            ProfileCatalogProjectionCodec.encode(seed?.second.orEmpty()), ByteArray(JournalLimits.OPERATION_BYTES) { 2 })
        val raw = initial.encode()
        check(journal.mutate(MutationKind.MIGRATION, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, raw, {}, {
            bindSyntheticProjection(journal, raw); raw.clone()
        }) == ProtectedMutationStatus.COMMITTED)
        projections = MemoryProjectionAccess(ProjectionImages(initial.catalogBytes(), initial.settingsBytes(),
            ProjectionImageWitness.reconstruct(initial.storeId(), initial.operationId(), 2, initial.catalogBytes(), initial.settingsBytes()),
            syntheticProjectionObservations(initial)))
    }
    fun snapshot(): ProtectedStateSnapshot = ProtectedStateSnapshot.decode(journal.readCheckpoint())
    fun readKeys(snapshot: ProtectedStateSnapshot): ClientKeyBundleStore = ClientKeyBundleStore.readOnly(
        ReadOnlyProtectedBlobView(snapshot.objects(), { objects[it]?.clone() }, codec, key), KurdRecipientKeyNative(native))
    fun broker(journalStorage: JournalStorage = storage): ProtectedStateMutationBroker = ProtectedStateMutationBroker.compose(journalStorage,
        { name -> objects[name]?.clone() }, { operation -> object : ImmutableProtectedObjectWriter {
            override fun requireDirtyOperation(operation: ByteArray) {
                val control = journal.readControl()
                check(control.dirty && control.operationId().contentEquals(operation))
            }
            override fun read(name: String) = objects[name]?.clone()
            override fun create(name: String, bytes: ByteArray) {
                requireDirtyOperation(operation)
                check(!objects.containsKey(name)); objectWrites++; objects[name] = bytes.clone()
            }
        } }, codec, key, projections, native, sessions, object : JournalObjectAccess {
            override fun inventory() = objects.map { JournalStoredEntry(it.key, it.value.size.toLong()) }
            override fun read(name: String) = objects[name]?.clone()
            override fun delete(name: String, expected: ByteArray) {
                check(objects[name]?.contentEquals(expected) == true)
                objects.remove(name)?.fill(0)
            }
        })
}

/** Synthetic committed fixture. Real secure index and envelope codecs are used;
 * recipient cryptography is replaced at the existing native API, never claimed as device proof. */
private fun pendingResetSeed(fault: String?): Pair<MutableMap<Pair<String, SecureDataClass>, ByteArray>, List<ProfileCatalogEntity>> {
    val plain = linkedMapOf<Pair<String, SecureDataClass>, ByteArray>()
    val blobs = object : SecureBlobAccess {
        override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
            plain.put(localRecordId to dataClass, exactBytes.clone())?.fill(0)
        }
        override fun reopen(localRecordId: String, dataClass: SecureDataClass) = plain.getValue(localRecordId to dataClass).clone()
        override fun exists(localRecordId: String, dataClass: SecureDataClass) = plain.containsKey(localRecordId to dataClass)
        override fun delete(localRecordId: String, dataClass: SecureDataClass) { plain.remove(localRecordId to dataClass)?.fill(0) }
        override fun deleteAll() { error("fixture never resets") }
    }
    var sequence = 0
    val ids = listOf("pending-ready", "pending-awaiting", "bound-key")
    val keys = ClientKeyBundleStore(blobs, object : RecipientKeyNative {
        override fun create(validitySeconds: Int): NativeResult<NativeRecipient> {
            val index = ++sequence
            return NativeResult.Success(object : NativeRecipient {
                override fun publicRequest() = NativeResult.Success(byteArrayOf(index.toByte(), 11))
                override fun privateBundle() = NativeResult.Success(byteArrayOf(index.toByte(), 12))
                override fun cancel() = NativeResult.Success(Unit)
                override fun close() = Unit
            })
        }
        override fun validate(publicRequest: ByteArray, privateBundle: ByteArray) = NativeResult.Success(Unit)
    }) { ids[sequence - 1] }
    repeat(3) { check(keys.create(600, 1_800_000_000L + it) is ClientKeyResult.Success) }
    keys.markRequestExported("pending-awaiting")
    keys.bindProfile("bound-key", "profile-kept")
    val rows = listOf("profile-kept", "profile-other").map { id ->
        val encoded = fixedCommittedPreview(id == "profile-kept")
        try { blobs.stage(id, SecureDataClass.PROFILE_PREVIEW, encoded) } finally { encoded.fill(0) }
        blobs.stage(id, SecureDataClass.IMPORT_REQUEST, byteArrayOf(31, 32))
        blobs.stage(id, SecureDataClass.ACTIVATION_ACTIVE, byteArrayOf(41, 42))
        ProfileCatalogEntity(id, TransactionState.FINALIZED.name, 2, 1, CatalogHealth.AVAILABLE.name)
    }
    SecureRoutingPolicyStore(blobs).savePackages(setOf("org.synthetic.allowed"))
    EncryptedDiagnosticEventStore(blobs).save(listOf(DiagnosticEvent(1, DiagnosticLogLevel.INFO,
        DiagnosticComponent.APP, "EXPLICIT_EVENT", 10)))
    when (fault) {
        "missing-material" -> blobs.delete("pending-ready", SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        "missing-index" -> blobs.delete("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        "prepared", "conflicting-status" -> {
            val index = plain.getValue("recipient-index" to SecureDataClass.RECIPIENT_KEY_INDEX)
            val firstStatusOffset = 7 + (index[6].toInt() and 0xff)
            index[firstStatusOffset] = if (fault == "prepared") 1 else 4
        }
    }
    return plain to rows
}

/** Independently encoded KPR2 input: generation 1, expiry 1900000000, empty optional fields.
 * This fixed fixture avoids importing an internal codec across the module boundary. */
private fun fixedCommittedPreview(sealed: Boolean): ByteArray {
    val hex = "4b5052320973796e7468657469630973796e746865746963" +
        "0e7075626c69632d73756d6d6172790f6c696e656167652d73756d6d617279" +
        "000000001153796e7468657469632070726f66696c65" +
        (if (sealed) "01" else "00") + "000000000000000100000000713fb300"
    return ByteArray(hex.length / 2) { index -> hex.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
}

private fun restorePayload(rollback: Boolean): ByteArray = BackupPayloadCodec.encode(
    listOf(BackupProfileRecord("synthetic-source-one", 1uL, byteArrayOf(64))) +
        if (rollback) listOf(BackupProfileRecord("synthetic-source-two", 1uL, byteArrayOf(99))) else emptyList(),
)

/** Fixed native-protocol script. The production journal drives every storage operation;
 * the injected native boundary rejects a failed submit and cannot manufacture durability. */
private class ScriptedRestoreActivation(private val onClose: () -> Unit) : NativeActivationSession {
    private val kinds = listOf(ActivationCommandKind.SNAPSHOT, ActivationCommandKind.STAGE_CANDIDATE,
        ActivationCommandKind.REOPEN_CANDIDATE, ActivationCommandKind.MARK_ACTIVATION,
        ActivationCommandKind.COMMIT_MARKED, ActivationCommandKind.FINALIZE_ACTIVATION,
        ActivationCommandKind.COMPLETE)
    private var next = 0
    private var failed = false
    private var closed = false
    override fun next(): NativeResult<ActivationCommand> {
        check(!closed)
        if (failed) return NativeResult.Failure(OperationError.KEY_INVALIDATED)
        val kind = kinds[next]
        return NativeResult.Success(ActivationCommand(next + 1L, kind,
            if (kind == ActivationCommandKind.STAGE_CANDIDATE || kind == ActivationCommandKind.COMPLETE)
                byteArrayOf(2, 3, 5, 7) else byteArrayOf()))
    }
    override fun submit(command: ActivationCommand, storageSucceeded: Boolean,
        active: ByteArray, lastKnownGood: ByteArray, reopened: ByteArray): NativeResult<Unit> {
        check(!closed && command.sequence == next + 1L && command.kind == kinds[next])
        if (!storageSucceeded) { failed = true; return NativeResult.Failure(OperationError.KEY_INVALIDATED) }
        if (command.kind == ActivationCommandKind.REOPEN_CANDIDATE) assertArrayEquals(byteArrayOf(2, 3, 5, 7), reopened)
        next++
        return NativeResult.Success(Unit)
    }
    override fun cancel(): NativeResult<Unit> { failed = true; return NativeResult.Success(Unit) }
    override fun close() { check(!closed); closed = true; onClose() }
}

private class MemoryProjectionAccess(var current: ProjectionImages) : ProtectedProjectionAccess {
    var publications = 0; var reads = 0; var failPublication = false
    var beforePublish: (() -> Unit)? = null
    var afterPublish: (() -> Unit)? = null
    override fun read(): ProjectionImages { reads++; return current.copyOwned() }
    override fun publish(expected: ProjectionImages, replacement: ProtectedStateSnapshot) {
        publications++
        beforePublish?.invoke()
        if (failPublication) return // A returning writer is deliberately not evidence of success.
        check(current.sameContent(expected))
        current = ProjectionImages(replacement.catalogBytes(), replacement.settingsBytes(), ProjectionImageWitness.reconstruct(
            replacement.storeId(), replacement.operationId(), replacement.revision, replacement.catalogBytes(), replacement.settingsBytes()),
            syntheticProjectionObservations(replacement))
        afterPublish?.invoke()
    }
}

/** Synthetic disk fixture, not SQLite/DataStore encoding or installed filesystem evidence. */
internal fun syntheticProjectionObservations(snapshot: ProtectedStateSnapshot): List<ProjectionFileObservation> =
    ProjectionFileRole.entries.map { role ->
        val bytes = when (role) {
            ProjectionFileRole.ROOM_MAIN -> snapshot.catalogBytes()
            ProjectionFileRole.DATASTORE -> snapshot.settingsBytes()
            else -> null
        }
        try { ProjectionFileObservation.fromRead(role, if (bytes == null)
            org.kurdistanvpn.core.nativeapi.DurableReadResult(org.kurdistanvpn.core.nativeapi.DurableCode.ABSENT)
        else org.kurdistanvpn.core.nativeapi.DurableReadResult(org.kurdistanvpn.core.nativeapi.DurableCode.OK,
            org.kurdistanvpn.core.nativeapi.DurableSnapshot(org.kurdistanvpn.core.nativeapi.DurableFileIdentity(
                1, snapshot.revision * 10 + role.wire), bytes))) }
        finally { bytes?.fill(0) }
    }

internal fun bindSyntheticProjection(journal: ProtectedStateOperationJournal, raw: ByteArray) {
    val snapshot = ProtectedStateSnapshot.decode(raw)
    journal.bindProjection(snapshot, PhysicalProjectionWitness.capture(snapshot, syntheticProjectionObservations(snapshot)))
}

internal class MemoryJournalStorage : JournalStorage {
    private val lock = Any()
    private val values = linkedMapOf<String, ByteArray>()
    var corruptNextWrite = false
    val events = mutableListOf<String>()
    var beforeReplace: ((String, ByteArray?, ByteArray) -> Unit)? = null
    override fun <T> exclusive(block: () -> T): T = synchronized(lock) { block() }
    override fun read(name: String, maximum: Int): ByteArray? {
        events += "read:$name"
        return values[name]?.clone()?.also { require(it.size <= maximum) }
    }
    override fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray) {
        beforeReplace?.invoke(name, expected, replacement)
        val current = values[name]
        check(if (expected == null) current == null else current != null && current.contentEquals(expected))
        events += "write:$name"
        values[name] = replacement.clone().also {
            if (corruptNextWrite) { it[0] = (it[0].toInt() xor 1).toByte(); corruptNextWrite = false }
        }
    }
    override fun delete(name: String, expected: ByteArray) {
        check(values[name]?.contentEquals(expected) == true)
        values.remove(name)?.fill(0)
    }
    override fun inventory(maximum: Int): List<JournalStoredEntry> {
        check(values.size <= maximum)
        return values.map { JournalStoredEntry(it.key, it.value.size.toLong()) }
    }
}
