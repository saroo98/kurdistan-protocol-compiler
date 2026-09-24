// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.feature.settingsrecovery

import androidx.lifecycle.SavedStateHandle
import java.lang.reflect.Proxy
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class PrivacyRecoveryViewModelTest {
    @Test fun replacementFailureAndRestorationNeverRetainResetConsent() = runBlocking {
        var previews = 0
        var resets = 0
        var cancellations = 0
        val id = CatalogId("reset-review")
        val repository = Proxy.newProxyInstance(PrivacyRecoveryRepository::class.java.classLoader,
            arrayOf(PrivacyRecoveryRepository::class.java)) { _, method, _ ->
            when (method.name) {
                "observeOperation" -> flowOf(OperationState.Idle)
                "observeBackup" -> flowOf(BackupWorkflowState.Idle)
                "previewReset" -> if (++previews == 2) DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_DEGRADED))
                    else DomainResult.Success(PendingProductOperation(id, OperationPreview(OperationKind.RESET, 1)))
                "reset" -> { resets++; DomainResult.Success(Unit) }
                "cancel" -> { cancellations++; DomainResult.Success(Unit) }
                else -> error("Unexpected call: ${method.name}")
            }
        } as PrivacyRecoveryRepository
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val saved = SavedStateHandle()
            val vm = PrivacyRecoveryViewModel(repository, saved, scope)
            vm.previewReset(ResetScope.PROFILES_AND_TRUST).join()
            assertTrue(vm.state.value is OperationState.AwaitingConfirmation)
            assertEquals(setOf("privacyOperationId"), saved.keys())
            vm.previewReset(ResetScope.EVERYTHING).join()
            vm.confirmReset(ResetScope.PROFILES_AND_TRUST).join()
            assertEquals(0, resets)
            assertEquals(1, cancellations)
            vm.previewReset(ResetScope.PROFILES_AND_TRUST).join()
            val restored = PrivacyRecoveryViewModel(repository, saved, scope)
            restored.confirmReset(ResetScope.PROFILES_AND_TRUST).join()
            assertEquals(0, resets)
            restored.previewReset(ResetScope.PROFILES_AND_TRUST).join()
            restored.confirmReset(ResetScope.PROFILES_AND_TRUST).join(); restored.confirmReset(ResetScope.PROFILES_AND_TRUST).join()
            assertEquals(1, resets)
            assertTrue(saved.keys().isEmpty())
            restored.previewReset(ResetScope.PROFILES_AND_TRUST).join()
            restored.confirmRestore().join()
            assertEquals("A stale restore button must never confirm reset", 1, resets)
            restored.previewReset(ResetScope.PROFILES_AND_TRUST).join()
            restored.confirmReset(ResetScope.EVERYTHING).join()
            assertEquals("A changed reset scope must require a new review", 1, resets)
        } finally { scope.cancel() }
    }
}
