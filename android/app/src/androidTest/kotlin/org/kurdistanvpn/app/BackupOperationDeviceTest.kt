// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.secure.BackupPayloadCodec

@RunWith(AndroidJUnit4::class)
class BackupOperationDeviceTest {
    @Test fun protectedAdaptersImportThenRestoreARealEncryptedBackupInAnIsolatedStore(): Unit = runBlocking {
        val target = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val parent = java.nio.file.Files.createTempDirectory(target.cacheDir.toPath(), "task13-operation-").toFile().canonicalFile
        android.system.Os.chmod(parent.path, 448)
        val info = android.content.pm.ApplicationInfo(target.applicationInfo).apply {
            dataDir = parent.path
            javaClass.getField("credentialProtectedDataDir").set(this, parent.path)
        }
        val context = object : android.content.ContextWrapper(target) {
            override fun getApplicationContext(): android.content.Context = this
            override fun getApplicationInfo(): android.content.pm.ApplicationInfo = info
        }
        val root = ProductCompositionRoot.create(context, org.kurdistanvpn.data.protectedstate.ProtectedStateProcessOwner(
            monotonicMillis = android.os.SystemClock::elapsedRealtime), settingsRuntime = {
                object : org.kurdistanvpn.data.settings.SettingsRuntimePort {
                    override suspend fun prepare(): org.kurdistanvpn.data.settings.SettingsPortResult<org.kurdistanvpn.data.settings.SettingsRuntimeIntent> =
                        error("Backup fixture must not operate a runtime")
                    override suspend fun apply(intent: org.kurdistanvpn.data.settings.SettingsRuntimeIntent,
                        committed: org.kurdistanvpn.data.settings.SettingsStoreState): org.kurdistanvpn.data.settings.SettingsPortResult<Unit> =
                        error("Backup fixture must not operate a runtime")
                }
            })
        val password = "task13-isolated-native-round-trip".encodeToByteArray()
        var encrypted: ByteArray? = null
        var primaryFailure: Throwable? = null
        try {
            assertTrue(root.initializeProtectedStateForExplicitUserAction())
            val facade = checkNotNull(root.protectedStateFacade())
            val enrollment = facade.createEnrollment(24 * 60 * 60, System.currentTimeMillis() / 1000)
                as org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed
            val request = checkNotNull(facade.enrollmentRequest(enrollment.value.localRecordId))
            val artifact = try { org.kurdistanvpn.core.nativejni.Task7InstalledFixtureNative()
                .issueForPublicEnrollment(java.io.File(parent, "task7-installed-v1").absolutePath, request) }
                finally { request.fill(0) }
            val preview = root.importOperations.prepare(org.kurdistanvpn.platform.importing.ImportCandidate(
                org.kurdistanvpn.platform.importing.IngressKind.FILE,
                org.kurdistanvpn.platform.importing.ArtifactClass.DEVICE_RECIPIENT, listOf(artifact)),
                org.kurdistanvpn.core.model.ImportSource.FILE) as NativeResult.Success
            val admitted = root.importOperations.confirm(preview.value.id) as NativeResult.Success
            assertTrue(root.importOperations.confirm(preview.value.id) is NativeResult.Failure)
            val original = checkNotNull(facade.readProjection()).profiles.single()
            assertEquals(org.kurdistanvpn.core.model.CatalogId(original.localRecordId), admitted.value)
            encrypted = (root.backupOperations.create(null, password.clone()) as NativeResult.Success).value
            assertTrue(facade.deleteProfile(original.localRecordId) is
                org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
            assertTrue(checkNotNull(facade.readProjection()).profiles.isEmpty())
            val opened = (root.backupOperations.open(encrypted.clone(), password.clone()) as NativeResult.Success).value
            val restoredResult = root.backupOperations.restore(opened.id)
            assertTrue("restore category=${(restoredResult as? NativeResult.Failure)?.error}", restoredResult is NativeResult.Success)
            assertEquals(1, (restoredResult as NativeResult.Success).value)
            val restored = checkNotNull(facade.readProjection()).profiles.single()
            assertEquals(original.generation, restored.generation)
            assertEquals(original.trust, restored.trust)
            assertEquals(original.expiresAtEpochSeconds, restored.expiresAtEpochSeconds)
        } catch (error: Throwable) {
            primaryFailure = error
            throw error
        } finally {
            encrypted?.fill(0); password.fill(0)
            try {
                try {
                    if (root.protectedStateFacade() != null) {
                        val resetStarted = android.os.SystemClock.elapsedRealtime()
                        var reset = root.resetProtectedStateConfirmed()
                        val firstReset = reset.javaClass.simpleName.uppercase(java.util.Locale.ROOT)
                        val firstMillis = android.os.SystemClock.elapsedRealtime() - resetStarted
                        // Bounded reset may pause with its authenticated manifest intact. Resume
                        // that operation once; never start a replacement or accept partial cleanup.
                        if (reset is org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Unproven)
                            reset = root.resetProtectedStateConfirmed(recoverPending = true)
                        if (reset !is org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed) {
                            val totalMillis = android.os.SystemClock.elapsedRealtime() - resetStarted
                            // Failure evidence only. Do not read key material, dump paths or
                            // treat absence as proof that authenticated cleanup completed.
                            val keyPresent = runCatching {
                                java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                                    .containsAlias("kurdistan-phase9-availability-kek-v1")
                            }.fold({ if (it) "1" else "0" }, { "UNKNOWN" })
                            val state = java.io.File(parent, "no_backup/protected-state-v1")
                            val manifest = if (java.io.File(state, "journal-reset.blob").isFile) 1 else 0
                            val ready = if (java.io.File(state, "journal-reset-ready.blob").isFile) 1 else 0
                            fail("KURDISTAN_TEST_SETUP expected=COMMITTED actual=${reset.javaClass.simpleName.uppercase(java.util.Locale.ROOT)} " +
                                "setup=BACKUP_RESET,FIRST_$firstReset,FIRST_MS_$firstMillis,TOTAL_MS_$totalMillis," +
                                "KEY_PRESENT_$keyPresent,MANIFEST_$manifest,READY_$ready")
                        }
                    }
                } finally { root.close() }
            } catch (cleanup: Throwable) {
                val primary = primaryFailure ?: throw cleanup
                primary.addSuppressed(cleanup)
                throw primary
            }
            check(checkNotNull(parent.parentFile).canonicalFile == target.cacheDir.canonicalFile && parent.name.startsWith("task13-operation-"))
            check(parent.deleteRecursively())
        }
    }

    @Test fun realEncryptedBackupPreviewCancelAndConsumeLeaveApplicationStorageUntouched(): Unit = runBlocking {
        val core = NativeBridge()
        val payload = BackupPayloadCodec.encode(emptyList())
        val password = "task13-owned-synthetic-backup".encodeToByteArray()
        val encrypted = try { (core.createBackup(payload, password) as NativeResult.Success).value }
            finally { payload.fill(0) }
        // No facade is supplied: this proves the native parent lifecycle without restoring data.
        val owner = ProductBackupOperations(core, { null }, android.os.SystemClock::elapsedRealtime)
        try {
            val preview = (owner.open(encrypted.clone(), password.clone()) as NativeResult.Success).value
            assertEquals(0, preview.display.recordCount)
            assertTrue(owner.cancel(preview.id) is NativeResult.Success)
            assertEquals(OperationError.CANCELLED, (owner.restore(preview.id) as NativeResult.Failure).error)
            val again = (owner.open(encrypted.clone(), password.clone()) as NativeResult.Success).value
            assertEquals(OperationError.RECOVERY_REQUIRED, (owner.restore(again.id) as NativeResult.Failure).error)
            assertEquals(OperationError.CANCELLED, (owner.restore(again.id) as NativeResult.Failure).error)
        } finally { encrypted.fill(0); password.fill(0) }
    }
}
