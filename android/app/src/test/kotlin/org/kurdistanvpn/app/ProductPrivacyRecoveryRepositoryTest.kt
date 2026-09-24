// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import java.lang.reflect.Proxy
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.domain.*
import org.kurdistanvpn.core.model.SensitiveAction as PrivacyAction

class ProductPrivacyRecoveryRepositoryTest {
    private class Fixture {
        var reads = 0
        var releases = 0
        var releaseFails = false
        val core = Proxy.newProxyInstance(KurdNativeCore::class.java.classLoader,
            arrayOf(KurdNativeCore::class.java)) { _, method, _ -> when (method.name) {
                "openBackup" -> NativeResult.Success(BackupPreviewHandle(7, byteArrayOf(75, 66, 86, 49) + ByteArray(12)))
                "releaseBackup" -> { releases++; if (releaseFails) NativeResult.Failure(OperationError.RECOVERY_REQUIRED) else NativeResult.Success(Unit) }
                else -> error("Unexpected native call: ${method.name}")
            } } as KurdNativeCore
        val backups = ProductBackupOperations(core, { null }, { 0L })
        val diagnostics = ProductDiagnosticsRepository(ProductDiagnosticOperations(core), { emptyList() }, { false },
            { 0 }, { DiagnosticPreferences() }, { error("Unexpected settings write") }, { _, _ -> false })
        val system = Proxy.newProxyInstance(SystemPolicyRepository::class.java.classLoader,
            arrayOf(SystemPolicyRepository::class.java)) { _, method, _ -> error("Unexpected platform call: ${method.name}") } as SystemPolicyRepository
        val repository = ProductPrivacyRecoveryRepository({ reads++; null }, { error("Unexpected settings write") },
            backups, diagnostics, system, { _, _ -> error("Unexpected authentication") }, { _, _ -> false },
            { error("Unexpected reset") }, { error("Unexpected migration") })
    }

    @Test fun emergencyActionsNeverReadStorageOrRequestAuthentication() = runBlocking {
        val f = Fixture()
        assertEquals(DomainResult.Success(UnlockResult.NOT_REQUIRED), f.repository.unlock(PrivacyAction.DISCONNECT))
        assertEquals(DomainResult.Success(UnlockResult.NOT_REQUIRED), f.repository.unlock(PrivacyAction.RECOVER_INTERNET))
        assertEquals(0, f.reads)
        assertTrue(f.repository.reset(CatalogId("missing")) is DomainResult.Rejected)
        assertEquals(0, f.reads)
    }

    @Test fun unprovedReplacementCleanupCannotLeaveAConfirmablePreview() = runBlocking {
        val f = Fixture()
        val id = (f.backups.open(byteArrayOf(1), byteArrayOf(2)) as NativeResult.Success).value.id
        assertTrue(f.repository.previewRestore(id) is DomainResult.Success)
        f.releaseFails = true
        assertTrue(f.repository.previewReset(ResetScope.EVERYTHING) is DomainResult.Rejected)
        assertTrue(f.repository.observeOperation().value is OperationState.Failed)
        assertTrue(f.repository.restore(id) is DomainResult.Rejected)
        assertEquals(1, f.releases)
        assertEquals(0, f.reads)
    }
}
