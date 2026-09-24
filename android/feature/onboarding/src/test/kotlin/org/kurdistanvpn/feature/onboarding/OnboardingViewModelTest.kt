// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.feature.onboarding

import androidx.lifecycle.SavedStateHandle
import java.lang.reflect.Proxy
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class OnboardingViewModelTest {
    @Test fun failedCreationDoesNotPublishAKeyAndRefreshNeverCreatesOne() = runBlocking {
        var creates = 0
        val repository = Proxy.newProxyInstance(ProfileRepository::class.java.classLoader,
            arrayOf(ProfileRepository::class.java)) { _, method, args ->
            when (method.name) {
                "readEnrollment" -> DomainResult.Success(EnrollmentUiState.NoEnrollmentKey)
                "createEnrollment" -> {
                    assertEquals(86400, args!![0]); creates++
                    DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_DEGRADED))
                }
                else -> error("Unexpected action ${method.name}")
            }
        } as ProfileRepository
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val vm = OnboardingViewModel(repository, SavedStateHandle(), scope)
            vm.refresh().join()
            assertEquals(0, creates)
            assertEquals(EnrollmentUiState.NoEnrollmentKey, vm.state.value)
            vm.createEnrollment().join()
            assertEquals(1, creates)
            assertEquals(EnrollmentUiState.RecoveryRequired, vm.state.value)
        } finally { scope.cancel() }
    }
}
