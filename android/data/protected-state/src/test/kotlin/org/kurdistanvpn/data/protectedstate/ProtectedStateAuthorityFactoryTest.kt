// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import org.kurdistanvpn.data.settings.SettingsProjectionCodec
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.secure.*

class ProtectedStateAuthorityFactoryTest {
    @Test fun productionCaptureAuthenticatesBootstrapOnceWithoutReusingItAcrossCaptures() {
        val fixture = AuthorityFixture(withProfile = true)
        val settings = ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductionSettings(2, 0, settings).status)
        val snapshot = ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint())
        val bootstrap = snapshot.objects().single { it.logicalId == RuntimeBootstrapRecord.RECORD_ID }
        val factory = fixture.factory()
        repeat(2) { attempt ->
            val ready = factory.reconstructProductionCapture() as ProductionCaptureReadResult.Ready
            ready.capture.close()
            assertEquals(attempt + 1, fixture.selectedObjectReads[bootstrap.physicalId])
        }
        fixture.objects.remove(bootstrap.physicalId)?.fill(0)
        assertTrue(factory.reconstructProductionCapture() is ProductionCaptureReadResult.Rejected)
        assertEquals(0, fixture.nativeOpens)
    }

    @Test fun productionStartupRejectsInvalidAuthorityAndMissingBootstrapWithoutPublishing() {
        val failures = listOf(
            org.kurdistanvpn.core.model.ProductFailureCode.PROFILE_UNTRUSTED,
            org.kurdistanvpn.core.model.ProductFailureCode.PROFILE_EXPIRED,
            org.kurdistanvpn.core.model.ProductFailureCode.PROFILE_REVOKED,
            null,
        )
        for (failure in failures) {
            val fixture = AuthorityFixture(withProfile = true)
            val settings = ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
            assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductionSettings(2, 0, settings).status)
            val checkpoint = fixture.journal.readCheckpoint()
            val closes = fixture.selectorCloses
            val reads = fixture.productionReads
            if (failure == null) {
                val bootstrap = ProtectedStateSnapshot.decode(checkpoint).objects().single {
                    it.logicalId == RuntimeBootstrapRecord.RECORD_ID && it.dataClass == SecureDataClass.RUNTIME_BOOTSTRAP.wireValue
                }
                fixture.objects.remove(bootstrap.physicalId)?.fill(0)
            } else fixture.productionFailure = failure

            val rejected = fixture.factory().reconstructProductionCapture() as ProductionCaptureReadResult.Rejected
            assertEquals(if (failure == null) AuthorityReadFailure.STATE_UNPROVEN else AuthorityReadFailure.AUTHORITY_REJECTED,
                rejected.category)
            if (failure != null) {
                assertEquals(bootstrapOperationErrorV1(failure), rejected.error)
                assertTrue(fixture.borrowedSettings!!.all { it == 0.toByte() })
            }
            assertEquals(reads + if (failure == null) 0 else 1, fixture.productionReads)
            assertEquals(closes, fixture.selectorCloses) // Rejection never acquires selector ownership.
            assertEquals(0, fixture.nativeOpens)
            assertArrayEquals(checkpoint, fixture.journal.readCheckpoint())
            checkpoint.fill(0)
        }
    }

    @Test fun productionCaptureCleanupUncertaintyStaysTerminalAndNeverBecomesProven() {
        val fixture=AuthorityFixture(withProfile=true)
        val requested=ProductSettings(profiles=org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
        assertEquals(ProtectedMutationStatus.COMMITTED,fixture.broker().applyProductionSettings(2,0,requested).status)
        val ready=fixture.factory().reconstructProductionCapture() as ProductionCaptureReadResult.Ready
        fixture.selectorCloseThrows=true
        assertThrows(IllegalStateException::class.java){ready.capture.close()}
        fixture.selectorCloseThrows=false
        assertThrows(IllegalStateException::class.java){ready.capture.close()}
        val output=java.io.ByteArrayOutputStream()
        assertThrows(IllegalStateException::class.java){ready.capture.writeTo(output)}
        assertEquals(0,output.size())
    }
    @Test fun productionCaptureFinalAndTransferFencesRejectChangedAdmissionAndCloseBothRoles() {
        val changes=listOf<(AuthorityFixture)->Unit>({it.environment.unlocked=false},
            {it.environment.prepared=false},{it.environment.cancelled=true},{it.environment.now=5200})
        for(change in changes) for(duringRead in listOf(false,true)) {
            val fixture=AuthorityFixture(withProfile=true)
            val requested=ProductSettings(profiles=org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
            assertEquals(ProtectedMutationStatus.COMMITTED,fixture.broker().applyProductionSettings(2,0,requested).status)
            val closes=fixture.selectorCloses
            if(duringRead)fixture.onProductionRead={change(fixture)}
            val result=fixture.factory().reconstructProductionCapture()
            if(duringRead)assertTrue(result is ProductionCaptureReadResult.Rejected)
            else {
                val ready=result as ProductionCaptureReadResult.Ready
                change(fixture)
                val output=java.io.ByteArrayOutputStream()
                assertThrows(IllegalStateException::class.java){ready.capture.writeTo(output)}
                assertEquals(0,output.size())
            }
            assertEquals(closes+2,fixture.selectorCloses)
            assertEquals(0,fixture.nativeOpens)
        }
    }
    @Test fun productionCaptureUsesCommittedRowsAndSameSettingsOneUseWithoutRuntimeOpen() {
        for(legacy in listOf(false,true)) {
            val fixture=AuthorityFixture(withProfile=true)
            val requested=ProductSettings(profiles=org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"),
                highContrast=true,connection=org.kurdistanvpn.core.model.ConnectionPreferences(reconnectOnFailure=true,reconnectMaximum=2))
            val applied=if(legacy)fixture.broker().applyProductSettings(2,0,requested) else fixture.broker().applyProductionSettings(2,0,requested)
            assertEquals(ProtectedMutationStatus.COMMITTED,applied.status)
            val opens=fixture.nativeOpens;val oldReads=fixture.productionReads
            val result=fixture.factory().reconstructProductionCapture() as ProductionCaptureReadResult.Ready
            assertEquals(4L,result.capture.revision);assertEquals(3,result.capture.signedRetryBudget)
            assertEquals("synthetic-profile", result.capture.presentation.profileId)
            assertEquals(fixture.nativeGeneration.toULong(), result.capture.presentation.profileGeneration)
            assertEquals(1L, result.capture.presentation.settingsRevision)
            assertTrue(result.capture.presentation.trustRevision in 1L..2L)
            assertEquals(opens,fixture.nativeOpens);assertEquals(oldReads+1,fixture.productionReads)
            if(legacy)assertEquals(1,fixture.legacyReads)
            val output=java.io.ByteArrayOutputStream();result.capture.writeTo(output)
            val raw=output.toByteArray()
            org.kurdistanvpn.runtime.api.RuntimeCaptureCodecV1.decode(java.nio.ByteBuffer.wrap(raw)).use{capture->
                val row=java.nio.ByteBuffer.allocate(2)
                capture.copyVerifyRequestTo(row);assertArrayEquals(byteArrayOf(21,22),row.array())
                capture.copyActivationRecordTo(row);assertArrayEquals(byteArrayOf(23,24),row.array())
                capture.copyRecipientRequestTo(row);assertArrayEquals(byteArrayOf(11,12),row.array())
                capture.copyRecipientPrivateTo(row);assertArrayEquals(byteArrayOf(13,14),row.array())
                val expected=(encodeProductionSettingsOwnedV1(requested) as NativeProductResult.Success).value
                val settings=java.nio.ByteBuffer.allocate(expected.size);capture.copySettingsTo(settings)
                assertArrayEquals(expected,settings.array());expected.fill(0);settings.array().fill(0)
            }
            assertThrows(IllegalStateException::class.java){result.capture.writeTo(output)}
            result.capture.close();raw.fill(0)
        }
    }
    @Test fun productionCaptureRechecksCheckpointAndClosesAvailabilityOnFailure() {
        val fixture=AuthorityFixture(withProfile=true)
        val requested=ProductSettings(profiles=org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
        assertEquals(2L,ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint()).revision)
        val first=fixture.broker().applyProductionSettings(2,0,requested)
        assertEquals(ProtectedMutationStatus.COMMITTED,first.status)
        assertEquals(1L,first.value!!.settingsRevision)
        assertEquals(4L,ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint()).revision)
        val ready=fixture.factory().reconstructProductionCapture() as ProductionCaptureReadResult.Ready
        val second=fixture.broker().applyProductionSettings(4,1,requested.copy(highContrast=true))
        assertEquals(ProtectedMutationStatus.COMMITTED,second.status)
        assertEquals(2L,second.value!!.settingsRevision)
        assertEquals(6L,ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint()).revision)
        val output=java.io.ByteArrayOutputStream()
        assertThrows(IllegalStateException::class.java){ready.capture.writeTo(output)}
        assertEquals(0,output.size())
        fixture.productionDigest=ByteArray(32){9}
        val before=fixture.selectorCloses
        assertTrue(fixture.factory().reconstructProductionCapture() is ProductionCaptureReadResult.Rejected)
        assertEquals(before+2,fixture.selectorCloses)
        assertEquals(0,fixture.nativeOpens)
    }
    @Test fun productionWriterStagesFullModesAndVersionTwoWithoutOpeningRuntime() {
        for(mode in org.kurdistanvpn.core.model.TunnelMode.entries) {
            val fixture=AuthorityFixture(withProfile=true)
            val requested=ProductSettings(tunnelMode=mode,profiles=org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"),
                connection=org.kurdistanvpn.core.model.ConnectionPreferences(reconnectOnFailure=true,reconnectMaximum=2),
                routing=org.kurdistanvpn.core.model.RoutingPreferences(org.kurdistanvpn.core.model.PerAppSelectionMode.INCLUDE_ONLY,setOf("org.example.allowed")))
            val outcome=fixture.broker().applyProductionSettings(2,0,requested)
            assertEquals(ProtectedMutationStatus.COMMITTED,outcome.status)
            assertEquals(ProductSettingsCommit(1,1280,2),outcome.value)
            assertEquals(0,fixture.nativeOpens);assertEquals(1,fixture.productionReads);assertEquals(2,fixture.selectorCloses)
            val snapshot=ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint())
            val blobs=ReadOnlyProtectedBlobView(snapshot.objects(),{fixture.objects[it]?.clone()},fixture.codec,fixture.key)
            val raw=blobs.reopen(RuntimeBootstrapRecord.RECORD_ID,SecureDataClass.RUNTIME_BOOTSTRAP)
            try {assertTrue(RuntimeProductionBootstrapRecord.decode(raw).matches(1,"synthetic-profile",1uL,fixture.productionDigest,fixture.nativeCompatibility))}
            finally{raw.fill(0)}
            assertEquals(requested,readProductSettings(snapshot,blobs))
            assertTrue(checkNotNull(fixture.borrowedSettings).all{it==0.toByte()})
        }
    }
    @Test fun productionWriterFailureDoesNotPublishAndRollbackKeepsExactVersion() {
        for(legacy in listOf(false,true)) {
            val fixture=AuthorityFixture(withProfile=true)
            val requested=ProductSettings(profiles=org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
            val first=if(legacy)fixture.broker().applyProductSettings(2,0,requested)
                else fixture.broker().applyProductionSettings(2,0,requested)
            assertEquals(ProtectedMutationStatus.COMMITTED,first.status)
            fun bootstrap():ByteArray {
                val snapshot=ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint())
                return ReadOnlyProtectedBlobView(snapshot.objects(),{fixture.objects[it]?.clone()},fixture.codec,fixture.key)
                    .reopen(RuntimeBootstrapRecord.RECORD_ID,SecureDataClass.RUNTIME_BOOTSTRAP)
            }
            val prior=bootstrap()
            fixture.productionFailure=org.kurdistanvpn.core.model.ProductFailureCode.PROFILE_INCOMPATIBLE
            val checkpoint=fixture.journal.readCheckpoint()
            assertNotEquals(ProtectedMutationStatus.COMMITTED,fixture.broker().applyProductionSettings(4,1,requested.copy(highContrast=true)).status)
            assertArrayEquals(checkpoint,fixture.journal.readCheckpoint())
            fixture.productionFailure=null
            assertEquals(ProtectedMutationStatus.COMMITTED,fixture.broker().applyProductionSettings(4,1,requested.copy(highContrast=true)).status)
            assertEquals(ProtectedMutationStatus.COMMITTED,fixture.broker().rollbackLastProductSettings(6).status)
            assertArrayEquals(prior,bootstrap())
            if(legacy)assertTrue(fixture.legacyReads>0)
            prior.fill(0);checkpoint.fill(0)
        }
    }
    @Test fun reconstructedBootstrapRejectsEveryChangedNativeCompatibilityBindingAndGeneration() {
        val baseline = NativeCompatibility("bridge-v1", "core-v1", "profile-v1", "strategy-v1", "relay-v1", "diagnostic-v1", 1, 100, 4, 100, 100, 10)
        val changed = listOf(baseline.copy(bridgeVersion = "bridge-v2"), baseline.copy(goCoreVersion = "core-v2"),
            baseline.copy(profileSchema = "profile-v2"), baseline.copy(strategyRegistry = "strategy-v2"),
            baseline.copy(relaySchema = "relay-v2"), baseline.copy(diagnosticSchema = "diagnostic-v2"),
            baseline.copy(cryptoSuite = 2), baseline.copy(maxInputBytes = 101), baseline.copy(maxQrChunks = 5),
            baseline.copy(maxQrChunkChars = 101), baseline.copy(maxResultBytes = 101), baseline.copy(maxConcurrentHandles = 11))
        for (compatibility in changed + baseline) {
            val fixture = AuthorityFixture(withProfile = true)
            val requested = ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
            assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductSettings(2, 0, requested).status)
            (fixture.factory().reconstruct() as AuthorityReadResult.Ready).authority.close()
            val before = fixture.journal.readCheckpoint()
            fixture.nativeCompatibility = compatibility
            if (compatibility == baseline) fixture.nativeGeneration = 2
            assertTrue(fixture.factory().reconstruct() is AuthorityReadResult.Rejected)
            assertArrayEquals(before, fixture.journal.readCheckpoint()); before.fill(0)
            assertEquals(fixture.nativeOpens, fixture.nativeCloses)
        }
    }
    @Test fun rawLegacyMigrationImageNeverGrantsRuntimeStartupAuthority() {
        val original = SettingsProjectionCodec.fromModel(ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile")))
        val raw = original.clone().also { java.nio.ByteBuffer.wrap(it).putInt(0x4b535231) }
        val fixture = AuthorityFixture(withProfile = true, initialSettings = raw)
        assertTrue(fixture.factory().reconstruct() is AuthorityReadResult.Rejected)
        assertEquals(0, fixture.nativeOpens)
    }
    @Test fun committedSettingsReceiptDoesNotDependOnAnotherFallibleNativeOpen() = kotlinx.coroutines.runBlocking {
        val fixture = AuthorityFixture(withProfile = true)
        fixture.onOpen = { if (fixture.nativeOpens > 1) fixture.nativeFailure = OperationError.AUTHORITY_UNAVAILABLE }
        val requested = ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
        val result = fixture.broker().settingsPort().apply(2, 0, requested)
        assertTrue(result is org.kurdistanvpn.data.settings.SettingsPortResult.Success)
        assertEquals(1, fixture.nativeOpens)
        assertEquals(4L, ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint()).revision)
    }
    @Test fun reopenedSettingsExposeFreshEffectiveValuesWithoutDiscardingRequest() = kotlinx.coroutines.runBlocking {
        val fixture = AuthorityFixture(withProfile = true)
        fixture.nativeMtu = 1280
        val requested = ProductSettings(tunnel = org.kurdistanvpn.core.model.TunnelPreferences(mtu = 1500),
            profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductSettings(2, 0, requested).status)
        val state = (fixture.broker().settingsPort().read() as org.kurdistanvpn.data.settings.SettingsPortResult.Success).value
        assertEquals(1500, state.requested.tunnel.mtu)
        assertEquals(1280, state.effective?.mtu)
        assertEquals(1, fixture.nativeOpens)
        assertEquals(1, fixture.legacyReads) // Fresh proof uses the read-only legacy binding.
    }
    @Test fun recoveryRejectsStaleNativeBootstrapBeforeRepublishing() {
        val fixture = AuthorityFixture(withProfile = true)
        val requested = ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
        fixture.afterPublish = { error("SYNTHETIC_INTERRUPTION") }
        assertEquals(ProtectedMutationStatus.DIRTY, fixture.broker().applyProductSettings(2, 0, requested).status)
        fixture.afterPublish = {}
        fixture.nativeDigest = ByteArray(32) { 8 }
        val priorControl = fixture.journal.readControl().encode()
        assertNotEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().recoverProductSettingsConfirmed(false).status)
        assertArrayEquals(priorControl, fixture.journal.readControl().encode())
    }
    @Test fun interruptedMigratedProfileDeleteUsesBoundSettingsRecovery() {
        val fixture = AuthorityFixture(withProfile = true)
        val requested = ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductSettings(2, 0, requested).status)
        fixture.afterPublish = { error("SYNTHETIC_INTERRUPTION") }
        assertEquals(ProtectedMutationStatus.DIRTY, fixture.broker().deleteProfile("synthetic-profile").status)
        fixture.afterPublish = {}
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().recoverProductSettingsConfirmed(false).status)
        assertNull(ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint()).selectedProfile)
    }
    @Test fun migratedLegacySelectionRoutingAndDeleteRemainOneBoundSettingsTransition() {
        val fixture = AuthorityFixture(withProfile = true)
        val selected = ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile", setOf("synthetic-profile")))
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductSettings(2, 0, selected).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().replaceSettings(4, selected.copy(profiles = org.kurdistanvpn.core.model.ProfilePreferences())).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().replaceSettings(6, selected).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().replaceRouting(emptySet()))
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().deleteProfile("synthetic-profile").status)
        val state = ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint())
        assertEquals(12L, state.revision); assertNull(state.selectedProfile)
        assertEquals(5L, org.kurdistanvpn.data.settings.ProductSettingsImage.decode(state.settingsBytes()).revision)
        assertTrue(fixture.factory().reconstruct() is AuthorityReadResult.Rejected)
    }
    @Test fun compensationRevalidatesSelectedBootstrapAndRestoresSemanticRevision() {
        val fixture = AuthorityFixture(withProfile = true)
        val requested = ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductSettings(2, 0, requested).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductSettings(4, 1, requested.copy(highContrast = true)).status)
        val compensated = fixture.broker().rollbackLastProductSettings(6)
        assertEquals(ProtectedMutationStatus.COMMITTED, compensated.status)
        assertEquals(1L, compensated.value?.settingsRevision)
        val ready = fixture.factory().reconstruct() as AuthorityReadResult.Ready
        assertEquals(8L, ready.authority.revision); ready.authority.close()
        assertEquals(3, fixture.nativeOpens)
        assertEquals(1, fixture.legacyReads) // Exact rollback does not allocate a runtime.
    }
    @Test fun migrationCannotReplaceUnprovenAppliedLegacyResolverWithInternalDns() {
        val fixture = AuthorityFixture(withProfile = true)
        val selected = ProductSettings(profiles = org.kurdistanvpn.core.model.ProfilePreferences("synthetic-profile"))
        val brand = selected.copy(tunnel = org.kurdistanvpn.core.model.TunnelPreferences(
            dnsMode = org.kurdistanvpn.core.model.ResolverPolicy.PRESET,
            resolverCatalogId = org.kurdistanvpn.core.model.CatalogId("legacy-resolver-2")))
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().replaceSettings(2, brand).status)
        val original = fixture.journal.readCheckpoint()
        assertEquals(ProtectedMutationStatus.NO_MUTATION, fixture.broker().applyProductSettings(4, 0, selected).status)
        assertArrayEquals(original, fixture.journal.readCheckpoint())
        assertEquals(0, fixture.nativeOpens)
    }
    @Test fun productApplyPreservesSelectedOwnerAndRequiresFreshMatchingBootstrapAtStartup() {
        val fixture = AuthorityFixture(withProfile = true)
        val requested = ProductSettings(highContrast = true, profiles = org.kurdistanvpn.core.model.ProfilePreferences(
            "synthetic-profile", setOf("synthetic-profile")))
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductSettings(2, 0, requested).status)
        assertEquals(1, fixture.nativeOpens); assertEquals(1, fixture.nativeCloses)
        val ready = fixture.factory().reconstruct() as AuthorityReadResult.Ready
        assertEquals(4L, ready.authority.revision); ready.authority.close()
        assertEquals(2, fixture.nativeOpens)
        fixture.nativeDigest = ByteArray(32) { 9 }
        assertTrue(fixture.factory().reconstruct() is AuthorityReadResult.Rejected)
        assertEquals(3, fixture.nativeCloses)
    }
    @Test fun emptyAndHistoricalDefaultExclusionsAreIdenticalNoBypassRequests() {
        val empty = AuthorityFixture(withProfile = true)
        val legacy = AuthorityFixture(withProfile = true, excludedRoutes = org.kurdistanvpn.core.model.SAFE_EXCLUDED_ROUTES)
        (empty.factory().reconstruct() as AuthorityReadResult.Ready).authority.close()
        (legacy.factory().reconstruct() as AuthorityReadResult.Ready).authority.close()
        assertArrayEquals(empty.capturedNativeWire, legacy.capturedNativeWire)
        val unsupported = AuthorityFixture(withProfile = true, excludedRoutes = listOf("10.0.0.0/8"))
        assertEquals(AuthorityReadFailure.POLICY_REJECTED, (unsupported.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertEquals(0, unsupported.nativeOpens)
    }
    @Test fun selectedReadBoundsRejectBeforeAdditionalIoAndWipeRejectedBytes() {
        val refs = (1..17).map { ProtectedObjectReference.fromEncryptedObject(1, "profile-$it", "object-$it", 1, byteArrayOf(it.toByte()), syntheticObjectBinding()) }
        var reads = 0
        val reader = SelectedAuthorityObjectReader(refs, { name, _ -> reads++; byteArrayOf(name.substringAfterLast('-').toByte()) }, {})
        repeat(16) { reader.read("object-${it + 1}")!!.fill(0) }
        assertThrows(IllegalStateException::class.java) { reader.read("object-17") }
        assertEquals(16, reads)
        val corrupt = byteArrayOf(99)
        val rejecting = SelectedAuthorityObjectReader(refs, { _, _ -> corrupt }, {})
        assertThrows(IllegalStateException::class.java) { rejecting.read("object-1") }
        assertTrue(corrupt.all { it == 0.toByte() })
        val eightMiB = ByteArray(8 * 1024 * 1024)
        val large = listOf(
            ProtectedObjectReference.fromEncryptedObject(1, "first", "object-first", 1, eightMiB, syntheticObjectBinding()),
            ProtectedObjectReference.fromEncryptedObject(1, "second", "object-second", 1, eightMiB, syntheticObjectBinding()),
            ProtectedObjectReference.fromEncryptedObject(1, "third", "object-third", 1, byteArrayOf(1), syntheticObjectBinding()))
        var largeReads = 0
        val bounded = SelectedAuthorityObjectReader(large, { _, _ -> largeReads++; eightMiB.clone() }, {})
        bounded.read("object-first")!!.fill(0); bounded.read("object-second")!!.fill(0)
        assertThrows(IllegalStateException::class.java) { bounded.read("object-third") }
        assertEquals(2, largeReads)
        eightMiB.fill(0)
    }

    @Test fun changedPhysicalProjectionIsRejectedBeforeNativeAuthorityValidation() {
        val fixture = AuthorityFixture(withProfile = true)
        val snapshot = ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint())
        fixture.projection = ProjectionImages(snapshot.catalogBytes(), snapshot.settingsBytes(),
            fixture.projection.witness, syntheticProjectionObservations(ProtectedStateSnapshot.create(
                snapshot.storeId(), 4, snapshot.selectedProfile, snapshot.objects(), snapshot.settingsBytes(),
                snapshot.catalogBytes(), ByteArray(JournalLimits.OPERATION_BYTES) { 3 })))
        assertEquals(AuthorityReadFailure.STATE_UNPROVEN,
            (fixture.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertEquals(0, fixture.nativeOpens)
    }

    @Test fun everyReconstructionRevalidatesNativeAuthorityWithoutOpeningASocketAndOwnsItsWire() {
        val fixture = AuthorityFixture(withProfile = true)
        repeat(2) {
            val before = fixture.journal.readControl().encode()
            val ready = (fixture.factory().reconstruct() as AuthorityReadResult.Ready).authority
            assertEquals(2L, ready.revision)
            assertEquals(3, ready.signedRetryBudget)
            var borrowed: ByteArray? = null
            val output = java.io.ByteArrayOutputStream()
            ready.writeTo(object : java.io.OutputStream() {
                override fun write(value: Int) = error("bounded bulk write required")
                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    borrowed = bytes; output.write(bytes, offset, length)
                }
            })
            assertEquals("KRV2", output.toByteArray().copyOfRange(0, 4).toString(Charsets.US_ASCII))
            assertTrue(borrowed!!.all { it == 0.toByte() })
            assertThrows(IllegalStateException::class.java) { ready.writeTo(output) }
            ready.close()
            assertArrayEquals(before, fixture.journal.readControl().encode())
        }
        assertEquals(2, fixture.nativeOpens)
        assertEquals(2, fixture.nativeCloses)
        assertTrue(fixture.borrowedNativeWire!!.all { it == 0.toByte() })
    }

    @Test fun nativeRejectionCancellationAndUncertainCleanupNeverReleaseWire() {
        for (failure in listOf(OperationError.TRUST_REJECTED, OperationError.KEY_INVALIDATED, OperationError.POLICY_REJECTED)) {
            val fixture = AuthorityFixture(withProfile = true)
            fixture.nativeFailure = failure
            val rejected = fixture.factory().reconstruct() as AuthorityReadResult.Rejected
            assertEquals(AuthorityReadFailure.AUTHORITY_REJECTED, rejected.category)
            assertEquals(failure, rejected.error)
            assertTrue(fixture.borrowedNativeWire!!.all { it == 0.toByte() })
        }
        val cancelled = AuthorityFixture(withProfile = true)
        cancelled.onOpen = { cancelled.environment.cancelled = true }
        assertEquals(AuthorityReadFailure.CANCELLED,
            (cancelled.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertEquals(1, cancelled.nativeCloses)
        val unproven = AuthorityFixture(withProfile = true)
        unproven.closeThrows = true
        assertEquals(AuthorityReadFailure.CLEANUP_UNPROVEN,
            (unproven.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertEquals(1, unproven.nativeCloses)
    }

    @Test fun staleProjectionOrExpiredReadDeadlineIsNotReleasedAfterNativeValidation() {
        val stale = AuthorityFixture(withProfile = true)
        stale.onOpen = { stale.projection = ProjectionImages(byteArrayOf(1), byteArrayOf(2), null) }
        assertEquals(AuthorityReadFailure.STATE_UNPROVEN,
            (stale.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        val expired = AuthorityFixture(withProfile = true)
        expired.onOpen = { expired.environment.now = 5200 }
        assertEquals(AuthorityReadFailure.EXPIRED,
            (expired.factory().reconstruct() as AuthorityReadResult.Rejected).category)
    }

    @Test fun lockedAndUnpreparedStartsCannotReadAnyProtectedState() {
        for (locked in listOf(true, false)) {
            val fixture = AuthorityFixture()
            fixture.environment.unlocked = !locked
            fixture.environment.prepared = locked
            val result = fixture.factory().reconstruct()
            assertEquals(if (locked) AuthorityReadFailure.LOCKED else AuthorityReadFailure.CONSENT_REQUIRED,
                (result as AuthorityReadResult.Rejected).category)
            assertEquals(0, fixture.projectionReads)
            assertEquals(0, fixture.objectReads)
            assertEquals(0, fixture.nativeCalls)
        }
    }

    @Test fun missingSelectionDoesNotCreateDefaultsOrRepairState() {
        val fixture = AuthorityFixture()
        val before = fixture.journal.readControl().encode()
        val result = fixture.factory().reconstruct() as AuthorityReadResult.Rejected
        assertEquals(AuthorityReadFailure.POLICY_REJECTED, result.category)
        assertArrayEquals(before, fixture.journal.readControl().encode())
        assertEquals(0, fixture.nativeCalls)
    }

    @Test fun dirtyOrMismatchedProjectionCannotProduceAuthority() {
        val fixture = AuthorityFixture()
        fixture.projection = ProjectionImages(byteArrayOf(1), byteArrayOf(2), null)
        assertEquals(AuthorityReadFailure.STATE_UNPROVEN,
            (fixture.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        fixture.journal.mutate(MutationKind.SETTINGS, ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(9),
            { error("interrupted mutation") }, { byteArrayOf(9) })
        assertEquals(AuthorityReadFailure.STATE_UNPROVEN,
            (fixture.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertTrue(fixture.journal.readControl().dirty)
        assertEquals(0, fixture.nativeCalls)
    }

    @Test fun cancellationIsTerminalBeforeAnyProtectedRead() {
        val fixture = AuthorityFixture()
        fixture.environment.cancelled = true
        assertEquals(AuthorityReadFailure.CANCELLED,
            (fixture.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertEquals(0, fixture.projectionReads)
    }
}

private class AuthorityFixture(withProfile: Boolean = false, excludedRoutes: List<String> = emptyList(), initialSettings: ByteArray? = null) {
    val storage = MemoryJournalStorage()
    val journal = ProtectedStateOperationJournal(storage)
    val codec = SecureEnvelopeCodec()
    val key = JournalTestKey()
    val environment = AuthorityEnvironment()
    var projectionReads = 0
    var objectReads = 0
    val selectedObjectReads = mutableMapOf<String, Int>()
    var nativeCalls = 0
    var nativeOpens = 0
    var nativeCloses = 0
    var closeThrows = false
    var nativeFailure: OperationError? = null
    var borrowedNativeWire: ByteArray? = null
    var capturedNativeWire: ByteArray? = null
    var onOpen: () -> Unit = {}
    var nativeDigest = ByteArray(32) { 1 }
    var nativeGeneration = 1L
    var nativeCompatibility = NativeCompatibility("bridge-v1", "core-v1", "profile-v1", "strategy-v1", "relay-v1", "diagnostic-v1", 1, 100, 4, 100, 100, 10)
    var nativeMtu = 1500
    var productionReads=0
    var legacyReads=0
    var selectorCloses=0
    var selectorCloseThrows=false
    var onProductionRead:()->Unit={}
    var productionFailure:org.kurdistanvpn.core.model.ProductFailureCode?=null
    var productionDigest=ByteArray(32){2}
    var borrowedSettings:ByteArray?=null
    val objects = linkedMapOf<String, ByteArray>()
    var projection: ProjectionImages
    var afterPublish: () -> Unit = {}
    val native = java.lang.reflect.Proxy.newProxyInstance(KurdNativeCore::class.java.classLoader,
        arrayOf(KurdNativeCore::class.java,NativeBootstrapValidator::class.java)) { _, method, args ->
        nativeCalls++
        when (method.name) {
            "compatibility" -> NativeResult.Success(nativeCompatibility)
            "validateRecipient" -> NativeResult.Success(Unit)
            "readLegacyBinding" -> {
                legacyReads++
                nativeFailure?.let{NativeResult.Failure(it)} ?: NativeResult.Success(NativeLegacyBootstrapFactsV1(nativeGeneration.toULong(),nativeDigest,3))
            }
            "readProductionBinding" -> {
                productionReads++
                onProductionRead()
                val settings=args!![1] as java.nio.ByteBuffer
                borrowedSettings=settings.array()
                productionFailure?.let{NativeProductResult.Failure(it)} ?: NativeProductResult.Success(
                    NativeProductionBootstrapReadV1(NativeProductionBootstrapFactsV1(nativeGeneration.toULong(),productionDigest,1280,3,2),
                        object:NativeActiveProductionSelectorsV1 {
                            override fun copyTo(output:java.nio.ByteBuffer):Int=error("fixture availability not transferred")
                            override fun containsStrategy(id:String)=false
                            override fun containsProbe(target:Int)=false
                            override fun close(){selectorCloses++;if(selectorCloseThrows)error("synthetic selector cleanup uncertainty")}
                        },object:NativeDisconnectedProductionSelectorsV1 {
                            override fun copyTo(output:java.nio.ByteBuffer):Int=error("fixture availability not transferred")
                            override fun containsStrategy(id:String)=false
                            override fun containsProbe(target:Int)=false
                            override fun close(){selectorCloses++;if(selectorCloseThrows)error("synthetic selector cleanup uncertainty")}
                        }))
            }
            "openLiveRuntimeSession" -> {
                nativeOpens++; borrowedNativeWire = args!![0] as ByteArray; capturedNativeWire = borrowedNativeWire!!.clone(); onOpen()
                nativeFailure?.let { NativeResult.Failure(it) } ?: NativeResult.Success(nativeSession())
            }
            else -> error("Unexpected native operation: ${method.name}")
        }
    } as KurdNativeCore
    init {
        journal.initialize(ByteArray(16) { 1 })
        val refs = if (withProfile) profileObjects() else emptyList()
        val settings = ProductSettings(routing = org.kurdistanvpn.core.model.RoutingPreferences(excludedCidrs = excludedRoutes), profiles = org.kurdistanvpn.core.model.ProfilePreferences(
            activeLocalRecordId = if (withProfile) "synthetic-profile" else null))
        val rows = if (withProfile) listOf(ProfileCatalogEntity("synthetic-profile", "FINALIZED", 1, 1, "AVAILABLE")) else emptyList()
        val state = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, settings.profiles.activeLocalRecordId, refs,
            initialSettings ?: SettingsProjectionCodec.fromModel(settings), ProfileCatalogProjectionCodec.encode(rows), ByteArray(JournalLimits.OPERATION_BYTES) { 2 })
        val raw = state.encode()
        check(journal.mutate(MutationKind.MIGRATION, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, raw, {}, {
            bindSyntheticProjection(journal, raw); raw.clone()
        }) == ProtectedMutationStatus.COMMITTED)
        projection = ProjectionImages(state.catalogBytes(), state.settingsBytes(), ProjectionImageWitness.reconstruct(
            state.storeId(), state.operationId(), 2, state.catalogBytes(), state.settingsBytes()),
            syntheticProjectionObservations(state))
    }
    fun factory() = ProtectedStateAuthorityFactory(
        ProtectedStateSnapshotReader(journal) { objectReads++; objects[it.physicalId]!!.clone() },
        { name, maximum -> objectReads++; selectedObjectReads[name] = (selectedObjectReads[name] ?: 0) + 1
            objects[name]?.clone()?.also { check(it.size <= maximum) } }, codec, key, native,
        object : ProtectedProjectionReadAccess { override fun read(): ProjectionImages { projectionReads++; return projection.copyOwned() } },
        environment,
    )

    fun broker() = ProtectedStateMutationBroker.compose(storage, { objects[it]?.clone() }, { operation ->
        object : ImmutableProtectedObjectWriter {
            override fun requireDirtyOperation(operation: ByteArray) { check(journal.readControl().dirty && journal.readControl().operationId().contentEquals(operation)) }
            override fun read(name: String) = objects[name]?.clone()
            override fun create(name: String, bytes: ByteArray) { requireDirtyOperation(operation); check(name !in objects); objects[name] = bytes.clone() }
        }
    }, codec, key, object : ProtectedProjectionAccess {
        override fun requireClosedSchema(expected: ProtectedStateSnapshot, version: Int) {
            check(version == 3)
            projection.requireMatches(expected)
            val actual = projection.physical()
            val synthetic = syntheticProjectionObservations(expected)
            check(actual.size == synthetic.size && actual.zip(synthetic).all { (a, b) -> a.bytes().contentEquals(b.bytes()) })
        }
        override fun read() = projection.copyOwned()
        override fun publish(expected: ProjectionImages, replacement: ProtectedStateSnapshot) {
            check(projection.sameContent(expected))
            projection = ProjectionImages(replacement.catalogBytes(), replacement.settingsBytes(), ProjectionImageWitness.reconstruct(
                replacement.storeId(), replacement.operationId(), replacement.revision, replacement.catalogBytes(), replacement.settingsBytes()), syntheticProjectionObservations(replacement))
            afterPublish()
        }
        override fun recover(prior: ProtectedStateSnapshot, candidate: ProtectedStateSnapshot, replacement: ProtectedStateSnapshot) {
            publish(projection.copyOwned(), replacement)
        }
    }, native, ActiveSessionMutationPolicy(monotonicMillis = { 100L }), object : JournalObjectAccess {
        override fun inventory() = objects.map { JournalStoredEntry(it.key, it.value.size.toLong()) }
        override fun read(name: String) = objects[name]?.clone()
        override fun delete(name: String, expected: ByteArray) { check(objects[name]?.contentEquals(expected) == true); objects.remove(name)?.fill(0) }
    })

    private fun nativeSession(): NativeLiveRuntimeSession = object : NativeLiveRuntimeSession {
        override val snapshot = NativeLiveRuntimeSessionSnapshot(nativeGeneration, nativeDigest.clone(), ByteArray(16), ByteArray(16), ByteArray(16),
            org.kurdistanvpn.core.model.SelectionMode.AUTOMATIC, org.kurdistanvpn.core.model.PerAppSelectionMode.ALL_APPS,
            emptyList(), org.kurdistanvpn.core.model.IpMode.AUTO, org.kurdistanvpn.core.model.ResolverPolicy.INTERNAL, nativeMtu, false,
            ByteArray(4), ByteArray(4), ByteArray(16), ByteArray(16), emptyList(), emptySet(), 32, 8, 3, 3000, 300000)
        override fun prepareSocket(): NativeResult<Int> = error("Reissue must not create network resources")
        override fun commitProtected(protectedSocket: Boolean): NativeResult<Unit> = error("Reissue must not connect")
        override fun attachTun(fileDescriptor: Int): NativeResult<Unit> = error("Reissue cannot own TUN")
        override fun status() = NativeResult.Success(NativeRuntimeState.VERIFIED)
        override fun stop() = NativeResult.Success(Unit)
        override fun close() { nativeCloses++; if (closeThrows) error("synthetic close uncertainty") }
    }

    private fun profileObjects(): List<ProtectedObjectReference> {
        val values = linkedMapOf<Pair<String, SecureDataClass>, ByteArray>()
        val blobs = object : SecureBlobAccess {
            override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) { values[localRecordId to dataClass] = exactBytes.clone() }
            override fun reopen(localRecordId: String, dataClass: SecureDataClass) = values[localRecordId to dataClass]!!.clone()
            override fun exists(localRecordId: String, dataClass: SecureDataClass) = values.containsKey(localRecordId to dataClass)
            override fun delete(localRecordId: String, dataClass: SecureDataClass) { values.remove(localRecordId to dataClass)?.fill(0) }
            override fun deleteAll() { error("No reset in authority fixture") }
        }
        val recipient = object : RecipientKeyNative {
            override fun create(validitySeconds: Int): NativeResult<NativeRecipient> = NativeResult.Success(object : NativeRecipient {
                override fun publicRequest() = NativeResult.Success(byteArrayOf(11, 12))
                override fun privateBundle() = NativeResult.Success(byteArrayOf(13, 14))
                override fun cancel() = NativeResult.Success(Unit)
                override fun close() = Unit
            })
            override fun validate(publicRequest: ByteArray, privateBundle: ByteArray) = NativeResult.Success(Unit)
        }
        val keys = ClientKeyBundleStore(blobs, recipient) { "synthetic-recipient" }
        val created = keys.create(600, 1_800_000_000) as ClientKeyResult.Success
        keys.bindProfile(created.summary.localRecordId, "synthetic-profile")
        blobs.stage("synthetic-profile", SecureDataClass.IMPORT_REQUEST, byteArrayOf(21, 22))
        blobs.stage("synthetic-profile", SecureDataClass.ACTIVATION_ACTIVE, byteArrayOf(23, 24))
        // Independent fixture of the existing KPR2 layout, not verifier-generated output.
        val preview = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(preview).use { out ->
            out.writeInt(0x4b505232)
            listOf("sealed-device", "device-recipient", "synthetic-content", "synthetic-lineage", "", "", "", "", "Synthetic").forEach {
                val raw = it.toByteArray(Charsets.UTF_8); out.writeByte(raw.size); out.write(raw)
            }
            out.writeByte(1); out.writeLong(1); out.writeLong(2_000_000_000)
        }
        blobs.stage("synthetic-profile", SecureDataClass.PROFILE_PREVIEW, preview.toByteArray())
        return values.entries.mapIndexed { index, (identity, plaintext) ->
            val name = "object-synthetic-$index"
            val encrypted = codec.sealForOperation(identity.first, identity.second, plaintext, key, syntheticObjectBinding())
            objects[name] = encrypted
            plaintext.fill(0)
            ProtectedObjectReference.fromEncryptedObject(identity.second.wireValue, identity.first, name, 1, encrypted, syntheticObjectBinding())
        }
    }
}

private class AuthorityEnvironment : ProtectedAuthorityEnvironment {
    var unlocked = true
    var prepared = true
    var cancelled = false
    var now = 100L
    override fun isUserUnlocked() = unlocked
    override fun isConsentPrepared() = prepared
    override fun isCancelled() = cancelled
    override fun elapsedRealtimeMillis() = now
}
