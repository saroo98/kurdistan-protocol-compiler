// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import android.os.SystemClock
import android.system.Os
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewModelScope
import androidx.test.platform.app.InstrumentationRegistry
import java.nio.file.Files
import java.security.KeyStore
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.EnrollmentUiState
import org.kurdistanvpn.core.model.ProtectedRecoveryPresentation
import org.kurdistanvpn.core.nativeapi.DurableCode
import org.kurdistanvpn.core.nativeapi.DurableOwnedDirectory
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.protectedstate.ProtectedStateProcessOwner

/** Real Android construction and scheduling; compile-only during local non-device validation. */
class ProtectedStateStartupDeviceTest {
    @Test fun firstUseViewModelIsDisconnectedAndDoesNotProvisionProtectedState() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        val applicationRoot = (target.applicationContext as KurdistanApplication).compositionRoot
        runBlocking {
            if (applicationRoot.protectedStateFacade() != null) {
                assertTrue(
                    "KURDISTAN_TEST_SETUP expected=RESET_COMMITTED actual=RESET_REJECTED setup=FIRST_USE_ISOLATION",
                    applicationRoot.resetProtectedStateConfirmed() is
                        org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed,
                )
            }
        }
        assertNull(
            "KURDISTAN_TEST_SETUP expected=NO_PROTECTED_FACADE actual=PROTECTED_FACADE_PRESENT setup=FIRST_USE_ISOLATION",
            applicationRoot.protectedStateFacade(),
        )
        val parent = Files.createTempDirectory(target.cacheDir.toPath(), "startup-isolated-").toFile().canonicalFile
        Os.chmod(parent.path, 448)
        val info = ApplicationInfo(target.applicationInfo).apply {
            dataDir = parent.path
            javaClass.getField("credentialProtectedDataDir").set(this, parent.path)
        }
        val context = object : ContextWrapper(target) {
            override fun getApplicationContext(): Context = this
            override fun getApplicationInfo(): ApplicationInfo = info
        }
        fun keyAliases(): Set<String> = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.aliases().toList().toSet()
        val beforeKeys = keyAliases()
        val owner = ProtectedStateProcessOwner(monotonicMillis = SystemClock::elapsedRealtime)
        val store = ViewModelStore()
        var root: Phase9CompositionRoot? = null
        lateinit var model: ProductRootViewModel
        try {
            val openCredentialParent = ProtectedStateApplicationFacade.Companion::class.java
                .getDeclaredMethod("openCredentialParent", Context::class.java).apply { isAccessible = true }
            val parentOwner = openCredentialParent.invoke(ProtectedStateApplicationFacade.Companion, context)
                as? DurableOwnedDirectory
            assertNotNull(
                "KURDISTAN_TEST_SETUP expected=CREDENTIAL_PARENT_AVAILABLE actual=CREDENTIAL_PARENT_UNAVAILABLE setup=ISOLATED_EMPTY_DIRECTORY",
                parentOwner,
            )
            val existingNoBackup = NativeBridge().durableFiles()
                .openChildDirectory(checkNotNull(checkNotNull(parentOwner).borrow()), "no_backup")
            assertEquals(
                "KURDISTAN_TEST_SETUP expected=NO_BACKUP_ABSENT actual=${existingNoBackup.code.name} setup=ISOLATED_EMPTY_DIRECTORY",
                DurableCode.ABSENT,
                existingNoBackup.code,
            )
            assertNull(existingNoBackup.owner)
            assertEquals(
                "KURDISTAN_TEST_SETUP expected=CREDENTIAL_PARENT_CLOSE_OK actual=CREDENTIAL_PARENT_CLOSE_UNPROVEN setup=ISOLATED_EMPTY_DIRECTORY",
                DurableCode.OK,
                parentOwner.closeResult(),
            )
            val opened = Phase9CompositionRoot.create(context, owner)
            root = opened
            assertEquals(
                "KURDISTAN_TEST_SETUP expected=FIRST_USE actual=${opened.storageFailure?.name ?: "AVAILABLE"} setup=ISOLATED_EMPTY_DIRECTORY",
                Phase9CompositionRoot.StorageFailure.FIRST_USE,
                opened.storageFailure,
            )
            assertNull(opened.protectedStateFacade())
            instrumentation.runOnMainSync {
                model = ViewModelProvider(store, ProductRootViewModel.Factory(opened))[ProductRootViewModel::class.java]
            }
            val state = runBlocking {
                withTimeout(10_000) { model.state.first { it != AppState.Booting && it != AppState.CompatibilityCheck } }
            }
            assertSame(AppState.FirstLaunch, state)
            assertSame(ProtectedRecoveryPresentation.NotRequired, model.protectedRecovery.value)
            assertNull(opened.protectedStateFacade())
            assertTrue("First-use presentation must not create protected storage", parent.listFiles()!!.isEmpty())
            assertTrue("First-use presentation must not generate or delete a key", beforeKeys == keyAliases())

            instrumentation.runOnMainSync { model.setHighContrast(true) }
            runBlocking {
                withTimeout(10_000) { model.settings.first { it.highContrast } }
            }
            assertNull(opened.storageFailure)
            assertSame(AppState.NoProfiles, model.state.value)
            assertTrue(
                "Explicit first-use settings mutation must commit through the protected-state broker",
                checkNotNull(opened.protectedStateFacade()?.readProjection()).settings.highContrast,
            )

            assertTrue(
                "KURDISTAN_TEST_SETUP expected=RESET_COMMITTED actual=RESET_REJECTED setup=EXPLICIT_ENROLLMENT_REPROVISION",
                runBlocking { opened.resetProtectedStateConfirmed() } is
                    ProtectedStateApplicationFacade.CommandResult.Committed,
            )
            assertNull(opened.protectedStateFacade())
            assertEquals(Phase9CompositionRoot.StorageFailure.FIRST_USE, opened.storageFailure)
            instrumentation.runOnMainSync { model.createEnrollmentRequest() }
            val enrollment = runBlocking {
                withTimeout(10_000) {
                    model.enrollmentState.first {
                        it != EnrollmentUiState.NoEnrollmentKey && it != EnrollmentUiState.Working
                    }
                }
            }
            assertTrue(
                "Explicit first-use enrollment must provision before issuing the request: $enrollment",
                enrollment is EnrollmentUiState.RequestReady,
            )
            assertNotNull(opened.protectedStateFacade())
            assertNull(opened.storageFailure)
            assertSame(AppState.NoProfiles, model.state.value)
            assertTrue(
                "KURDISTAN_TEST_SETUP expected=FINAL_RESET_COMMITTED actual=RESET_REJECTED setup=ISOLATED_CLEANUP",
                runBlocking { opened.resetProtectedStateConfirmed() } is
                    ProtectedStateApplicationFacade.CommandResult.Committed,
            )
            assertNull(opened.protectedStateFacade())
            assertTrue("Explicit first-use test must retire every generated key", beforeKeys == keyAliases())
        } finally {
            instrumentation.runOnMainSync { store.clear() }
            root?.close() ?: owner.close()
        }
        assertTrue(model.viewModelScope.coroutineContext[Job]!!.isCancelled)
        assertSame(AppState.NoProfiles, model.state.value)
    }
}
