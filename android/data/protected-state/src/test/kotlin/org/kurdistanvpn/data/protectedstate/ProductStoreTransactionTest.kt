// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.data.secure.ProductOperationState
import org.kurdistanvpn.data.secure.*
import org.kurdistanvpn.core.model.*

class ProductStoreTransactionTest {
    @Test fun syntheticHostCanariesStayEncryptedAndQueuedTrustOwnsCallerHmacOnSuccessAndFailure() {
        val canaries = syntheticProductCanaries
        for (failAfterStage in listOf(false, true)) {
            val state = BrokerFixture(productProjectionNative = true)
            val payload = canaries.drop(3).joinToString("|").toByteArray()
            val preview = RedactedProfilePreview("synthetic", "synthetic", "public-summary", "lineage-summary", 1uL, 1_900_000_000, false)
            val admitted = state.broker().importProfile(ConfirmedProtectedImport.owned(payload, preview, null, state.snapshot()))
            payload.fill(0)
            assertEquals(ProtectedMutationStatus.COMMITTED, admitted.status)
            val id = checkNotNull(admitted.value)
            val display = DeploymentDisplayMetadata(listOf(DeploymentDisplayEntry(CatalogId(id), SafeAlias(canaries[0]),
                0, false, UpdateCategory.NOT_CHECKED)))
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(state.snapshot().revision,
                ProductStoreCommand.SetDeploymentDisplay(display)).status)
            val settings = ProductSettings(routing = RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY, setOf(canaries[1])))
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(state.snapshot().revision, 0, settings).status)
            val source = ByteArray(32) { (it + 65).toByte() }
            val expectedHmac = source.clone()
            TrustedNetworkRule(CatalogId("rule-canary"), source, SafeAlias(canaries[2])).use { rule ->
                StoredTrustedNetworks(1, listOf(rule), emptySet()).use { queued ->
                    val command = ProductStoreCommand.ReplaceTrustedRules(queued)
                    source.fill(0)
                    val copy = rule.hmac(); copy.fill(0)
                    state.storage.beforeReplace = { _, _, _ -> source.fill(3) }
                    assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(state.snapshot().revision, command).status)
                    state.storage.beforeReplace = null
                }
            }
            val snapshot = state.snapshot()
            val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
            checkNotNull(TrustedNetworkStore.readOnly(blobs).load()).use {
                val actual = it.rules.single().hmac()
                try { assertArrayEquals(expectedHmac, actual) } finally { actual.fill(0) }
                assertEquals(SafeAlias(canaries[2]), it.rules.single().alias)
            }
            // Alias text can coincide with a Wi-Fi name. It is an alias here, never a raw-network API parameter.
            val capturedBefore = state.nativeSecrets.size
            val thrownMessages = mutableListOf<ByteArray>()
            if (failAfterStage) state.afterObjectWrite = {
                val failure = IllegalStateException("SYNTHETIC_STAGE_FAILURE")
                thrownMessages += failure.message!!.toByteArray()
                throw failure
            }
            val outcome = state.broker().applyProductStoreCommand(snapshot.revision,
                ProductStoreCommand.SetDeploymentDisplay(DeploymentDisplayMetadata(display.entries.map { it.copy(expanded = true) })))
            assertEquals(if (failAfterStage) ProtectedMutationStatus.DIRTY else ProtectedMutationStatus.COMMITTED, outcome.status)
            assertTrue(state.nativeSecrets.size > capturedBefore)
            assertTrue(state.nativeSecrets.all { bytes -> bytes.all { it == 0.toByte() } })
            assertEquals(state.verificationHandles, state.verificationReleases)
            val publicImages = listOf(state.projections.current.catalog(), state.projections.current.settings()) +
                state.projections.current.physical().map { it.bytes() }
            val journalLeaves = state.storage.inventory(JournalLimits.OBJECTS).map { it.name }
            val journalBytes = journalLeaves.map { checkNotNull(state.storage.read(it, JournalLimits.CHECKPOINT_BYTES)) }
            val leafBytes = (journalLeaves + state.objects.keys).map { it.toByteArray() }
            val diagnostics = listOf(outcome.toString()).map { it.toByteArray() } + thrownMessages
            val observations = publicImages + journalBytes + leafBytes + diagnostics + state.objects.values
            for (canary in canaries) assertEquals(canary, 0,
                observations.count { String(it, Charsets.ISO_8859_1).contains(canary) })
            val hmacText = String(expectedHmac, Charsets.ISO_8859_1)
            assertFalse((publicImages + leafBytes).any { String(it, Charsets.ISO_8859_1).contains(hmacText) })
            (publicImages + journalBytes + leafBytes + diagnostics).forEach { it.fill(0) }
            expectedHmac.fill(0); source.fill(0)
        }
    }
    private fun assertSilent(state: BrokerFixture, command: ProductStoreCommand) {
        val before = state.journal.readCheckpoint()
        val writes = state.objectWrites
        val publications = state.projections.publications
        state.storage.events.clear()
        assertEquals(ProtectedMutationStatus.NO_MUTATION,
            state.broker().applyProductStoreCommand(state.snapshot().revision, command).status)
        assertArrayEquals(before, state.journal.readCheckpoint())
        assertEquals(writes, state.objectWrites)
        assertEquals(publications, state.projections.publications)
        assertFalse(state.storage.events.any { it.startsWith("write:") })
        before.fill(0)
    }
    @Test fun probeHistoryCommitsAndFreshReadRetainsExactChronologicalSamples() {
        val state = BrokerFixture(pendingReset = true)
        val earlier = ProbeSample(59, 1, 2, 3, ProbeStability.UNKNOWN, ProductFailureCode.OPERATION_INTERRUPTED)
        val later = ProbeSample(60, 2, 3, 4, ProbeStability.STABLE, null)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(2,
            ProductStoreCommand.RecordProbe("profile-other", StoredProbeHistory(60, listOf(later, earlier)))).status)
        val snapshot = state.snapshot()
        val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
        val read = checkNotNull(ProbeHistoryStore.readOnly(blobs).load("profile-other"))
        assertEquals(60L, read.currentEpochMinutes)
        assertEquals(listOf(earlier, later), read.samples)
    }
    @Test fun identicalProbeHistoryDoesNotWrite() {
        val state = BrokerFixture(pendingReset = true)
        val command = ProductStoreCommand.RecordProbe("profile-other", StoredProbeHistory(60, emptyList()))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(2, command).status)
        assertSilent(state, command)
    }
    @Test fun unknownProbeProfileRejectsBeforeDirty() {
        assertSilent(BrokerFixture(), ProductStoreCommand.RecordProbe("missing", StoredProbeHistory(60, emptyList())))
    }
    @Test fun identicalTrustedRulesDoNotWriteAndWrongSettingsRevisionRejectsBeforeDirty() {
        val state = BrokerFixture()
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(2, 0, ProductSettings()).status)
        TrustedNetworkRule(CatalogId("rule"), ByteArray(32) { 7 }, SafeAlias("Private alias")).use { rule ->
            StoredTrustedNetworks(1, listOf(rule), emptySet()).use { value ->
                val command = ProductStoreCommand.ReplaceTrustedRules(value)
                assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(4, command).status)
                assertSilent(state, command)
            }
            StoredTrustedNetworks(2, listOf(rule), emptySet()).use {
                assertSilent(state, ProductStoreCommand.ReplaceTrustedRules(it))
            }
        }
    }
    @Test fun saturatedAppLockFailureDoesNotWriteAndFreshReadIsStillLockedPolicy() {
        val state = BrokerFixture()
        val privacy = PrivacyPreferences(appLockEnabled = true)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(2, 0,
            ProductSettings(privacy = privacy)).status)
        repeat(10) {
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(state.snapshot().revision,
                ProductStoreCommand.RecordAppLockFailure(1, 99)).status)
        }
        assertSilent(state, ProductStoreCommand.RecordAppLockFailure(1, 99))
        val read = checkNotNull(readStorage(state)).appLock!!
        assertEquals(10, read.failedAttempts); assertEquals(99L, read.nextEligibleEpochMinute)
        assertTrue(read.enabled); assertEquals(privacy.allowedAuthenticators, read.allowedAuthenticators)
    }
    @Test fun disabledAppLockAndWrongSettingsRevisionRejectBeforeDirty() {
        for (enabled in listOf(false, true)) {
            val state = BrokerFixture()
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(2, 0,
                ProductSettings(privacy = PrivacyPreferences(appLockEnabled = enabled))).status)
            assertSilent(state, ProductStoreCommand.RecordAppLockFailure(if (enabled) 2 else 1, 99))
        }
    }
    @Test fun commandBoundaryReportsUnprovenWhenSuccessfulWorkCannotReleaseQuiescence() {
        val policy = ActiveSessionMutationPolicy(acquireQuiescence = { AutoCloseable { error("SYNTHETIC_RELEASE_FAILURE") } },
            monotonicMillis = { 100L })
        val result = protectedCommandResult {
            checkNotNull(policy.reserveMutation()).use { lease ->
                lease.retirePriorOwners()
                BrokerMutation(ProtectedMutationStatus.COMMITTED, Unit)
            }
        }
        assertSame(ProtectedStateApplicationFacade.CommandResult.Unproven, result)
        assertNull(policy.reserveMutation())
    }
    @Test fun commandBoundaryPreservesCancellationAndNeverCallsMissingWriterSuccess() {
        val cancellation = java.util.concurrent.CancellationException("synthetic cancellation")
        assertSame(cancellation, assertThrows(java.util.concurrent.CancellationException::class.java) {
            protectedCommandResult<Unit> { throw cancellation }
        })
        assertSame(ProtectedStateApplicationFacade.CommandResult.Busy, protectedCommandResult<Unit> { null })
        assertEquals(ProtectedStateApplicationFacade.CommandResult.Committed(7),
            protectedCommandResult { BrokerMutation(ProtectedMutationStatus.COMMITTED, 7) })
        assertEquals(ProtectedStateApplicationFacade.CommandResult.Rejected(OperationError.POLICY_REJECTED),
            protectedCommandResult<Unit> { BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.POLICY_REJECTED) })
    }
    private fun readStorage(state: BrokerFixture, id: String? = null,
        closed: () -> Boolean = { false }, afterRead: (() -> Unit)? = null): ProtectedStateApplicationFacade.ProductStorageReadProjection? {
        val reader = ProtectedStateSnapshotReader(state.journal, { checkNotNull(state.objects[it.physicalId]).clone() })
        return readProductStorageProjection(reader, state.projections, { name ->
            state.objects[name]?.clone().also { afterRead?.invoke() }
        }, state.codec, state.key, id, closed)
    }
    @Test fun aggregateReadReconstructsDetachedSingletonsWithoutWrites() {
        val state = BrokerFixture()
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(2, 0, ProductSettings()).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(4,
            ProductStoreCommand.RecordStart(42)).status)
        state.storage.events.clear()
        val writes = state.objectWrites
        val publications = state.projections.publications
        val read = checkNotNull(readStorage(state))
        assertEquals(6L, read.revision)
        assertNull(read.profileId); assertNull(read.profile); assertNull(read.update); assertNull(read.probeHistory)
        assertEquals(1L, read.trustedNetworks!!.settingsRevision)
        assertEquals(0, read.trustedNetworks.ruleCount)
        assertEquals(42L, read.crashSafeMode!!.startedEpochHour)
        assertEquals(1L, read.appLock!!.settingsRevision)
        assertEquals(1L, read.proxyPolicy!!.settingsRevision)
        assertEquals("ProductStorageReadProjection(redacted)", read.toString())
        assertEquals("TrustedNetworkStorageSummary(redacted)", read.trustedNetworks.toString())
        assertThrows(UnsupportedOperationException::class.java) {
            (read.trustedNetworks.selectedRuleIds as MutableSet<CatalogId>).add(CatalogId("injected"))
        }
        assertEquals(writes, state.objectWrites); assertEquals(publications, state.projections.publications)
        assertFalse(state.storage.events.any { it.startsWith("write:") })
    }
    @Test fun aggregateReadRequiresCatalogMembershipButAllowsMissingLegacyProjection() {
        val state = BrokerFixture(pendingReset = true)
        assertNotNull(readStorage(state, "profile-other"))
        assertNull(readStorage(state, "profile-other")!!.profile)
        assertNull(readStorage(state, "missing"))
        assertNull(readStorage(state, "../invalid"))
        assertEquals(0, state.objectWrites)
    }
    @Test fun aggregateReadRejectsClosedOwnerCorruptReferencedObjectsAndMidReadClosure() {
        val state = BrokerFixture()
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(2,
            ProductStoreCommand.RecordStart(42)).status)
        assertNull(readStorage(state, closed = { true }))
        var closed = false
        assertNull(readStorage(state, closed = { closed }, afterRead = { closed = true }))
        val reference = state.snapshot().objects().single { it.dataClass == 29 }
        state.objects.getValue(reference.physicalId)[0] = 0
        assertNull(readStorage(state))
    }
    @Test fun aggregateReadRejectsACommittedRevisionChangeDuringRecordDecode() {
        val state = BrokerFixture()
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(2,
            ProductStoreCommand.RecordStart(42)).status)
        var changed = false
        assertNull(readStorage(state, afterRead = {
            if (!changed) {
                changed = true
                assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(4,
                    ProductStoreCommand.RecordCleanStop(43)).status)
            }
        }))
        assertEquals(6L, checkNotNull(readStorage(state)).revision)
    }
    @Test fun replacingTrustedRulesCannotChangeSettingsSelections() {
        val state = BrokerFixture()
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(2, 0, ProductSettings()).status)
        TrustedNetworkRule(CatalogId("local-rule"), ByteArray(32) { 7 }, SafeAlias("Private alias")).use { rule ->
            StoredTrustedNetworks(1, listOf(rule), setOf(rule.id)).use { requested ->
                val before = state.journal.readCheckpoint()
                val writes = state.objectWrites
                assertEquals(ProtectedMutationStatus.NO_MUTATION, state.broker().applyProductStoreCommand(4,
                    ProductStoreCommand.ReplaceTrustedRules(requested)).status)
                assertArrayEquals(before, state.journal.readCheckpoint())
                assertEquals(writes, state.objectWrites)
                before.fill(0)
            }
        }
    }
    @Test fun trustedSelectionIsEncryptedAndRuleRemovalRequiresSettingsClearFirst() {
        val state = BrokerFixture()
        val broker = state.broker()
        assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductSettings(2, 0, ProductSettings()).status)
        TrustedNetworkRule(CatalogId("selected-rule"), ByteArray(32) { 6 }, SafeAlias("Local label")).use { rule ->
            StoredTrustedNetworks(1, listOf(rule), emptySet()).use {
                assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductStoreCommand(4, ProductStoreCommand.ReplaceTrustedRules(it)).status)
            }
            val requested = ProductSettings(networkTrust = NetworkTrustPreferences(protectedRuleIds = setOf(rule.id)))
            assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductSettings(6, 1, requested).status)
            assertEquals(8L, state.snapshot().revision)
            val image = state.snapshot().settingsBytes()
            try { assertFalse(String(image, Charsets.ISO_8859_1).contains("selected-rule")) } finally { image.fill(0) }
            assertEquals(setOf(rule.id), checkNotNull(readStorage(state)).trustedNetworks!!.selectedRuleIds)
            StoredTrustedNetworks(2, emptyList(), emptySet()).use {
                val before = state.journal.readCheckpoint()
                assertEquals(ProtectedMutationStatus.NO_MUTATION, broker.applyProductStoreCommand(8, ProductStoreCommand.ReplaceTrustedRules(it)).status)
                assertArrayEquals(before, state.journal.readCheckpoint()); before.fill(0)
            }
            assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductSettings(8, 2, ProductSettings()).status)
            StoredTrustedNetworks(3, emptyList(), emptySet()).use {
                assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductStoreCommand(10, ProductStoreCommand.ReplaceTrustedRules(it)).status)
            }
            assertEquals(0, checkNotNull(readStorage(state)).trustedNetworks!!.ruleCount)
            assertEquals(3L, checkNotNull(readStorage(state)).trustedNetworks!!.settingsRevision)
        }
    }
    @Test fun appLockFailuresSurviveEnabledSettingsChangeAndClearOnDisableInOneCommit() {
        val state = BrokerFixture()
        val enabled = ProductSettings(privacy = PrivacyPreferences(appLockEnabled = true))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(2, 0, enabled).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(4,
            ProductStoreCommand.RecordAppLockFailure(1, 99)).status)
        val publications = state.projections.publications
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(6, 1, enabled.copy(highContrast = true)).status)
        val preserved = checkNotNull(readStorage(state)).appLock!!
        assertEquals(2L, preserved.settingsRevision); assertEquals(1, preserved.failedAttempts)
        assertEquals(99L, preserved.nextEligibleEpochMinute)
        assertEquals(publications + 1, state.projections.publications)
        assertEquals(8L, state.snapshot().revision)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(8, 2, ProductSettings()).status)
        val cleared = checkNotNull(readStorage(state)).appLock!!
        assertFalse(cleared.enabled); assertEquals(0, cleared.failedAttempts); assertEquals(0L, cleared.nextEligibleEpochMinute)
    }
    @Test fun aggregateReadRejectsPhysicalWitnessChangeAndDirtyTransition() {
        for (dirty in listOf(false, true)) {
            val state = BrokerFixture()
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(2,
                ProductStoreCommand.RecordStart(42)).status)
            var changed = false
            assertNull(readStorage(state, afterRead = {
                if (!changed) {
                    changed = true
                    if (dirty) {
                        state.projections.beforePublish = { error("SYNTHETIC_INTERRUPTION") }
                        assertEquals(ProtectedMutationStatus.DIRTY, state.broker().applyProductStoreCommand(4,
                            ProductStoreCommand.RecordCleanStop(43)).status)
                    } else {
                        val old = state.projections.current
                        state.projections.current = ProjectionImages(old.catalog(), old.settings(), old.witness, emptyList())
                    }
                }
            }))
        }
    }
    @Test fun aggregateReadReturnsAuthenticatedProfileUpdateAndOperationNotTemporaryState() {
        val state = BrokerFixture(pendingReset = true, productProjectionNative = true)
        val display = DeploymentDisplayMetadata(listOf(DeploymentDisplayEntry(CatalogId("profile-other"), SafeAlias("Local name"),
            0, false, UpdateCategory.NOT_CHECKED)))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(2,
            ProductStoreCommand.SetDeploymentDisplay(display)).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(4,
            ProductStoreCommand.RecordUpdate("profile-other", StoredUpdateState(7uL, 1uL, UpdateCategory.AVAILABLE, 20, 20, 0))).status)
        val read = checkNotNull(readStorage(state, "profile-other"))
        assertEquals(1uL, read.profile!!.profile.generation)
        assertEquals(SafeAlias("Local name"), read.profile.profile.alias)
        assertEquals(7uL, read.update!!.publicationGeneration)
        assertEquals("UPDATE", read.operation!!.kind)
        assertEquals("APPLIED", read.operation.state)
        assertNull(checkNotNull(readStorage(state)).update)
    }
    @Test fun legacyAndCurrentSettingsRejectPresentMismatchedPolicyMirrors() {
        for (migrated in listOf(false, true)) {
            val state = BrokerFixture()
            if (migrated) assertEquals(ProtectedMutationStatus.COMMITTED,
                state.broker().applyProductSettings(2, 0, ProductSettings()).status)
            val snapshot = state.snapshot()
            val base = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
            assertNotNull(readProductSettings(snapshot, base))
            val badTrust = StoredTrustedNetworks(2, emptyList(), emptySet()).use { it.encode() }
            val badLock = StoredAppLockState(2, false, setOf(AllowedAuthenticator.STRONG_BIOMETRIC), 0, 0).encode()
            val badProxy = StoredProxyPolicy(2, LocalProxyPreferences()).encode()
            val policyLock = StoredAppLockState(1, true, setOf(AllowedAuthenticator.STRONG_BIOMETRIC), 0, 0).encode()
            val cases = listOf(Triple(StoredTrustedNetworks.RECORD_ID, SecureDataClass.TRUSTED_NETWORK_RULES, badTrust),
                Triple(StoredAppLockState.RECORD_ID, SecureDataClass.APP_LOCK_STATE, badLock),
                Triple(StoredProxyPolicy.RECORD_ID, SecureDataClass.LOCAL_PROXY_POLICY, badProxy),
                Triple(StoredAppLockState.RECORD_ID, SecureDataClass.APP_LOCK_STATE, policyLock))
            try {
                for ((id, role, bytes) in cases) {
                    val altered = object : SecureBlobReadAccess {
                        override fun exists(localRecordId: String, dataClass: SecureDataClass) =
                            (localRecordId == id && dataClass == role) || base.exists(localRecordId, dataClass)
                        override fun reopen(localRecordId: String, dataClass: SecureDataClass) =
                            if (localRecordId == id && dataClass == role) bytes.clone() else base.reopen(localRecordId, dataClass)
                    }
                    assertThrows(IllegalStateException::class.java) { readProductSettings(snapshot, altered) }
                }
            } finally { cases.forEach { it.third.fill(0) } }
        }
    }
    @Test fun aliasedFavoriteProfileCanBeSupersededByImportAndRestoreWithoutLosingMetadata() {
        for (restore in listOf(false, true)) {
            val state = BrokerFixture(productProjectionNative = true)
            val broker = state.broker()
            val oldPreview = RedactedProfilePreview("synthetic", "synthetic", "public-summary", "lineage-summary", 1uL, 1_900_000_000, false)
            val oldImport = broker.importProfile(ConfirmedProtectedImport.owned(byteArrayOf(31), oldPreview, null, state.snapshot()))
            assertEquals("initial admission", ProtectedMutationStatus.COMMITTED, oldImport.status)
            val oldId = checkNotNull(oldImport.value)
            val display = DeploymentDisplayMetadata(listOf(DeploymentDisplayEntry(CatalogId(oldId), SafeAlias("Preserved alias"), 7, true, UpdateCategory.AVAILABLE)))
            assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductStoreCommand(4, ProductStoreCommand.SetDeploymentDisplay(display)).status)
            val requested = ProductSettings(profiles = ProfilePreferences(favoriteLocalRecordIds = setOf(oldId)))
            assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductSettings(6, 0, requested).status)
            val before = state.snapshot()
            val originalReference = before.objects().single { it.dataClass == 19 && it.logicalId == oldId }
            val newerPreview = oldPreview.copy(contentFingerprint = "new-public-summary", generation = 2uL)
            val outcome = if (restore) {
                val payload = BackupPayloadCodec.encode(listOf(BackupProfileRecord("newer-source", 2uL, byteArrayOf(65))))
                try { broker.restoreBackup(payload).status } finally { payload.fill(0) }
            } else broker.importProfile(ConfirmedProtectedImport.owned(byteArrayOf(65), newerPreview, null, before)).status
            assertEquals("supersession restore=$restore", ProtectedMutationStatus.COMMITTED, outcome)
            val snapshot = state.snapshot()
            val catalogBytes = snapshot.catalogBytes()
            val rows = try { org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec.decode(catalogBytes) } finally { catalogBytes.fill(0) }
            assertEquals(org.kurdistanvpn.data.metadata.CatalogHealth.SUPERSEDED.name, rows.single { it.localRecordId == oldId }.health)
            assertEquals(1, rows.count { it.health == org.kurdistanvpn.data.metadata.CatalogHealth.AVAILABLE.name })
            val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
            val preserved = checkNotNull(ProfileProjectionStore.readOnly(blobs).load(oldId))
            assertEquals(SafeAlias("Preserved alias"), preserved.profile.alias)
            assertEquals(1uL, preserved.profile.generation)
            assertEquals(ProjectionStatus.VERIFIED, preserved.profile.status)
            assertEquals(originalReference.physicalId, snapshot.objects().single { it.dataClass == 19 && it.logicalId == oldId }.physicalId)
            assertArrayEquals(display.encode(), checkNotNull(DeploymentDisplayMetadataStore.readOnly(blobs).load()).encode())
            assertEquals(setOf(oldId), readProductSettings(snapshot, blobs).profiles.favoriteLocalRecordIds)
            assertEquals(ProtectedMutationStatus.NO_MUTATION, state.broker().applyProductStoreCommand(snapshot.revision, ProductStoreCommand.RecordCleanStop(100)).status)
            assertEquals(state.verificationHandles, state.verificationReleases)
        }
    }
    @Test fun displayAliasDerivesOnlyVerifiedProfileFieldsAndClearingRemovesProjection() {
        val state = BrokerFixture(pendingReset = true, productProjectionNative = true)
        val display = DeploymentDisplayMetadata(listOf(DeploymentDisplayEntry(CatalogId("profile-other"), SafeAlias("Local name"),
            0, true, UpdateCategory.AVAILABLE)))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(2,
            ProductStoreCommand.SetDeploymentDisplay(display)).status)
        val snapshot = state.snapshot()
        val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
        val projection = checkNotNull(ProfileProjectionStore.readOnly(blobs).load("profile-other"))
        assertEquals(SafeAlias("Local name"), projection.profile.alias)
        assertEquals(1uL, projection.profile.generation)
        assertEquals(1_900_000_000L, projection.profile.expiresAtEpochSeconds)
        assertEquals(ProjectionStatus.UNAVAILABLE, projection.deployment!!.node.status)
        assertEquals(state.verificationHandles, state.verificationReleases)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(4,
            ProductStoreCommand.SetDeploymentDisplay(DeploymentDisplayMetadata(emptyList()))).status)
        assertFalse(state.snapshot().objects().any { it.dataClass == 19 })
    }
    @Test fun settingsApplyStagesAllMirrorsAndUsageDisableRemovesAggregates() {
        val state = BrokerFixture()
        val enabled = ProductSettings(privacy = PrivacyPreferences(collectUsageAggregates = true))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(2, 0, enabled).status)
        assertTrue(state.snapshot().objects().map { it.dataClass }.containsAll(listOf(23, 25, 28)))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(4,
            ProductStoreCommand.RecordUsage(StoredUsageAggregates(10, listOf(UsageAggregate(10, 12, 13, 14))))).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductSettings(6, 1, ProductSettings()).status)
        assertFalse(state.snapshot().objects().any { it.dataClass == 24 })
    }
    @Test fun liveRolesExcludeTemporaryAndUnknownRoles() {
        val accepted = (1..13).toSet() + setOf(19, 20, 21, 22, 23, 24, 25, 26, 28, 29, 30)
        for (role in -1..256) assertEquals("role $role", role in accepted, isLiveProtectedRole(role))
        assertEquals(JournalLimits.CHECKPOINT_BYTES, ProductOperationState.MAX_SNAPSHOT)
    }
    @Test fun crashObservationCommitsThenCleanStopNoOpWritesNothing() {
        val state = BrokerFixture()
        val broker = state.broker()
        assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100)).status)
        assertEquals(4L, state.snapshot().revision)
        assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductStoreCommand(4, ProductStoreCommand.RecordCleanStop(101)).status)
        val before = state.journal.readCheckpoint()
        val writes = state.objectWrites
        state.storage.events.clear()
        assertEquals(ProtectedMutationStatus.NO_MUTATION, broker.applyProductStoreCommand(6, ProductStoreCommand.RecordCleanStop(102)).status)
        assertEquals(writes, state.objectWrites)
        assertFalse(state.storage.events.any { it.startsWith("write:") })
        assertArrayEquals(before, state.journal.readCheckpoint())
    }
    @Test fun unknownProfileAndDisabledUsageAreRejectedWithoutWrites() {
        val state = BrokerFixture()
        val broker = state.broker()
        val commands = listOf(ProductStoreCommand.RecordUpdate("missing", StoredUpdateState(null, null, UpdateCategory.NOT_CHECKED, 0, 0, 0)),
            ProductStoreCommand.RecordUsage(StoredUsageAggregates(1, emptyList())))
        for (command in commands) {
            state.storage.events.clear()
            assertNotEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductStoreCommand(2, command).status)
            assertFalse(state.storage.events.any { it.startsWith("write:") })
            assertEquals(0, state.objectWrites)
        }
    }
    @Test fun removingProfileRemovesItsProductRecordsInTheSameTransaction() {
        val state = BrokerFixture(pendingReset = true)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(2,
            ProductStoreCommand.RecordUpdate("profile-other", StoredUpdateState(2uL, 4uL, UpdateCategory.AVAILABLE, 10, 10, 0))).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().deleteProfile("profile-other").status)
        assertFalse(state.snapshot().objects().any { it.logicalId == "profile-other" })
    }
    @Test fun knownUnsignedGenerationsCannotDecreaseOrBeForgotten() {
        val state = BrokerFixture(pendingReset = true)
        val broker = state.broker()
        assertEquals(ProtectedMutationStatus.COMMITTED, broker.applyProductStoreCommand(2,
            ProductStoreCommand.RecordUpdate("profile-other", StoredUpdateState(ULong.MAX_VALUE, 4uL, UpdateCategory.AVAILABLE, 10, 10, 0))).status)
        for ((publication, profile) in listOf(null to 4uL, 1uL to 4uL, ULong.MAX_VALUE to null, ULong.MAX_VALUE to 3uL)) {
            state.storage.events.clear()
            assertEquals(ProtectedMutationStatus.NO_MUTATION, broker.applyProductStoreCommand(4,
                ProductStoreCommand.RecordUpdate("profile-other", StoredUpdateState(publication, profile, UpdateCategory.AVAILABLE, 10, 10, 0))).status)
            assertFalse(state.storage.events.any { it.startsWith("write:") })
        }
    }
}
