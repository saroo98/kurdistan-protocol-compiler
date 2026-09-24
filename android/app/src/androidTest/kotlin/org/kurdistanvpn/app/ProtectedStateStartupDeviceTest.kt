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
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.EnrollmentUiState
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.ProtectedRecoveryPresentation
import org.kurdistanvpn.core.model.RoutingPreferences
import org.kurdistanvpn.core.nativeapi.DurableCode
import org.kurdistanvpn.core.nativeapi.DurableOwnedDirectory
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.secure.AndroidKeystoreKek
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.protectedstate.ProtectedStateProcessOwner
import org.kurdistanvpn.domain.DomainResult
import org.kurdistanvpn.domain.SettingsDraft
import org.kurdistanvpn.domain.SettingsRevision

/** Real Android construction and scheduling; compile-only during local non-device validation. */
class ProtectedStateStartupDeviceTest {
    // These isolated stores have no runtime or selected profile. Never bind the real application's store.
    private fun isolatedRuntime() = object : org.kurdistanvpn.data.settings.SettingsRuntimePort {
        override suspend fun prepare() = org.kurdistanvpn.data.settings.SettingsPortResult.Success(
            org.kurdistanvpn.data.settings.SettingsRuntimeIntent.ALREADY_STOPPED)
        override suspend fun apply(intent: org.kurdistanvpn.data.settings.SettingsRuntimeIntent,
            committed: org.kurdistanvpn.data.settings.SettingsStoreState): org.kurdistanvpn.data.settings.SettingsPortResult<Unit> {
            check(intent == org.kurdistanvpn.data.settings.SettingsRuntimeIntent.ALREADY_STOPPED)
            return org.kurdistanvpn.data.settings.SettingsPortResult.Success(Unit)
        }
    }
    @Before fun isolateDisposableApplicationStateBeforeFixedAliasFixtures() {
        val application = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KurdistanApplication
        val root = application.compositionRoot
        if (root.protectedStateFacade() != null) {
            assertTrue("test fixture isolation requires a committed explicit reset",
                runBlocking { root.resetProtectedStateConfirmed() } is ProtectedStateApplicationFacade.CommandResult.Committed)
        }
        assertNull("test fixture isolation must not retain an application facade", root.protectedStateFacade())
    }

    @Test fun frameworkParentPreparationRejectsExistingOrAmbiguousStateWithoutChangingPermissions() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val alias = "kurdistan-phase9-availability-kek-v1"
        fun aliases() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.aliases().toList().toSet()
        assertFalse("isolated first-use fixture requires no existing product key", aliases().contains(alias))
        for (case in listOf("legacy-db", "legacy-blobs", "database-symlink", "database-mode",
            "protected-partial", "protected-root-with-private-parent", "parent-symlink", "parent-mode", "wrong-uid", "existing-key")) {
            val parent = Files.createTempDirectory(target.cacheDir.toPath(), "framework-reject-").toFile().canonicalFile
            check(parent.parentFile == target.cacheDir.canonicalFile)
            Os.chmod(parent.path, 448)
            val noBackup = java.io.File(parent, "no_backup")
            val outside = java.io.File(parent, "outside")
            check(outside.mkdir())
            Os.chmod(outside.path, 448)
            if (case == "parent-symlink") Os.symlink(outside.path, noBackup.path) else {
                check(noBackup.mkdir())
                Os.chmod(noBackup.path, if (case == "parent-mode") 511 else 505)
            }
            val databases = java.io.File(parent, "databases")
            if (case != "database-symlink") {
                check(databases.mkdir())
                Os.chmod(databases.path, if (case == "database-mode") 511 else 505)
            }
            when (case) {
                "legacy-db" -> {
                    java.io.File(databases, "phase9-metadata.db").writeText("test-only legacy marker")
                }
                "legacy-blobs" -> check(java.io.File(noBackup, "phase9-v1").mkdir())
                "protected-partial" -> check(java.io.File(noBackup, "protected-state-v1").mkdir())
                "protected-root-with-private-parent" -> {
                    Os.chmod(noBackup.path, 448)
                    check(java.io.File(noBackup, "protected-state-v1").mkdir())
                }
                "database-symlink" -> Os.symlink(outside.path, databases.path)
                "existing-key" -> AndroidKeystoreKek.createForFirstUse(alias, 1, preferStrongBox = false)
            }
            val info = ApplicationInfo(target.applicationInfo).apply {
                dataDir = parent.path
                javaClass.getField("credentialProtectedDataDir").set(this, parent.path)
                if (case == "wrong-uid") uid += 1
            }
            val context = object : ContextWrapper(target) {
                override fun getApplicationContext(): Context = this
                override fun getApplicationInfo(): ApplicationInfo = info
            }
            val parentMode = Os.lstat(noBackup.path).st_mode
            val databaseMode = Os.lstat(databases.path).st_mode
            val beforeKeys = aliases()
            val owner = ProtectedStateProcessOwner(monotonicMillis = SystemClock::elapsedRealtime)
            val root = ProductCompositionRoot.create(context, owner, settingsRuntime = ::isolatedRuntime)
            try {
                assertFalse("$case must fail closed", runBlocking { root.initializeProtectedStateForExplicitUserAction() })
                assertEquals("$case parent mode changed", parentMode, Os.lstat(noBackup.path).st_mode)
                assertEquals("$case database mode changed", databaseMode, Os.lstat(databases.path).st_mode)
                assertEquals("$case outside mode changed", 448, Os.stat(outside.path).st_mode and 511)
                assertEquals("$case changed key ownership", beforeKeys, aliases())
                assertNull("$case published a facade", root.protectedStateFacade())
                if (case == "legacy-db") assertEquals("test-only legacy marker", java.io.File(databases, "phase9-metadata.db").readText())
            } finally {
                root.close()
                if (case == "existing-key") AndroidKeystoreKek.deleteForExplicitReset(alias)
                check(parent.deleteRecursively())
            }
        }
    }

    @Test fun frameworkNoBackupParentCanBePreparedBeforeExplicitFirstUseWithoutRelaxingProtectedModes() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val parent = Files.createTempDirectory(target.cacheDir.toPath(), "framework-parent-").toFile().canonicalFile
        Os.chmod(parent.path, 448)
        val noBackup = java.io.File(parent, "no_backup")
        check(noBackup.mkdir())
        // Android framework-owned app subdirectories can be created as 0771.
        Os.chmod(noBackup.path, 505)
        val databases = java.io.File(parent, "databases")
        check(databases.mkdir())
        Os.chmod(databases.path, 505)
        val info = ApplicationInfo(target.applicationInfo).apply {
            dataDir = parent.path
            javaClass.getField("credentialProtectedDataDir").set(this, parent.path)
        }
        val context = object : ContextWrapper(target) {
            override fun getApplicationContext(): Context = this
            override fun getApplicationInfo(): ApplicationInfo = info
        }
        val owner = ProtectedStateProcessOwner(monotonicMillis = SystemClock::elapsedRealtime)
        var root = ProductCompositionRoot.create(context, owner, settingsRuntime = ::isolatedRuntime)
        try {
            assertEquals("read-only startup must not change the framework parent", 505, Os.stat(noBackup.path).st_mode and 511)
            assertEquals("read-only startup must not change the database parent", 505, Os.stat(databases.path).st_mode and 511)
            assertTrue("read-only startup must not provision protected state", noBackup.listFiles()!!.isEmpty())
            val initialized = runBlocking { root.initializeProtectedStateForExplicitUserAction() }
            assertTrue("explicit first use must prepare the owned framework parent, got ${root.storageFailure}", initialized)
            assertEquals(448, Os.stat(noBackup.path).st_mode and 511)
            assertEquals(448, Os.stat(databases.path).st_mode and 511)
            assertEquals(448, Os.stat(java.io.File(noBackup, "protected-state-v1").path).st_mode and 511)
            assertTrue(requireNotNull(root.protectedStateFacade()?.readProjection()).profiles.isEmpty())
            val protectedIdentity = Os.stat(java.io.File(noBackup, "protected-state-v1").path).st_ino
            assertTrue("repeat explicit interaction must retain the active store", runBlocking { root.initializeProtectedStateForExplicitUserAction() })
            assertEquals(protectedIdentity, Os.stat(java.io.File(noBackup, "protected-state-v1").path).st_ino)
            root.close()
            root = ProductCompositionRoot.create(context, ProtectedStateProcessOwner(monotonicMillis = SystemClock::elapsedRealtime), settingsRuntime = ::isolatedRuntime)
            assertNotNull("read-only reopen must restore the prepared store", root.protectedStateFacade())
            assertTrue(requireNotNull(root.protectedStateFacade()?.readProjection()).profiles.isEmpty())
            assertEquals(protectedIdentity, Os.stat(java.io.File(noBackup, "protected-state-v1").path).st_ino)
            assertTrue(runBlocking { root.resetProtectedStateConfirmed() } is ProtectedStateApplicationFacade.CommandResult.Committed)
            assertTrue("post-reset explicit first use must retain the existing empty-lock contract", runBlocking { root.initializeProtectedStateForExplicitUserAction() })
            assertTrue(runBlocking { root.resetProtectedStateConfirmed() } is ProtectedStateApplicationFacade.CommandResult.Committed)
        } finally {
            root.close()
            // Remove only this test's empty framework fixture after proven protected-state cleanup.
            noBackup.delete()
            databases.delete()
            parent.delete()
        }
    }

    @Test fun routingModeAndPackageChangesUseExactlyOneSettingsTransaction() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        val parent = Files.createTempDirectory(target.cacheDir.toPath(), "routing-adapter-")
            .toFile().canonicalFile
        Os.chmod(parent.path, 448)
        val info = ApplicationInfo(target.applicationInfo).apply {
            dataDir = parent.path
            javaClass.getField("credentialProtectedDataDir").set(this, parent.path)
        }
        val context = object : ContextWrapper(target) {
            override fun getApplicationContext(): Context = this
            override fun getApplicationInfo(): ApplicationInfo = info
        }
        val owner = ProtectedStateProcessOwner(monotonicMillis = SystemClock::elapsedRealtime)
        val root = ProductCompositionRoot.create(context, owner, settingsRuntime = ::isolatedRuntime)
        val store = ViewModelStore()
        var model: ProductRootViewModel? = null
        try {
            assertTrue(runBlocking { root.initializeProtectedStateForExplicitUserAction() })
            val facade = requireNotNull(root.protectedStateFacade())
            val repository = requireNotNull(root.settingsRepository())
            val draft = runBlocking { (repository.openDraft() as DomainResult.Success<SettingsDraft>).value }
            val seeded = runBlocking {
                repository.apply(draft.id, draft.basedOn.revision,
                    draft.basedOn.settings.copy(highContrast = true,
                        connection = draft.basedOn.settings.connection.copy(autoConnectOnLaunch = true)))
            } as DomainResult.Success<SettingsRevision>
            assertTrue("fixture must exercise version-two settings", seeded.value.revision > 0)
            assertEquals(PerAppSelectionMode.ALL_APPS, seeded.value.settings.routing.mode)

            instrumentation.runOnMainSync {
                model = ViewModelProvider(store, ProductRootViewModel.Factory(root))[ProductRootViewModel::class.java]
            }
            val activeModel = requireNotNull(model)
            runBlocking {
                withTimeout(10_000) {
                    activeModel.state.first { it != AppState.Booting && it != AppState.CompatibilityCheck }
                }
            }
            assertSame(AppState.NoProfiles, activeModel.state.value)
            val requests = listOf(
                RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY, setOf("org.synthetic.one")),
                RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY, setOf("org.synthetic.two")),
                RoutingPreferences(PerAppSelectionMode.ALL_APPS),
            )
            for (requested in requests) {
                requested.validated()
                val before = requireNotNull(facade.readProjection())
                val semanticBefore = runBlocking {
                    (repository.appliedRevision() as DomainResult.Success<SettingsRevision>).value.revision
                }
                runBlocking {
                    val edit = (repository.openDraft() as DomainResult.Success).value
                    try { assertTrue(repository.apply(edit.id, edit.basedOn.revision,
                        edit.basedOn.settings.copy(routing = requested)) is DomainResult.Success) }
                    finally { repository.cancel(edit.id) }
                    activeModel.refresh().join()
                }
                val observed = runBlocking {
                    withTimeout(10_000) {
                        combine(activeModel.state, activeModel.settings) { state, settings -> state to settings }
                            .first { (state, settings) ->
                                settings.routing == requested || state == AppState.DegradedStorage ||
                                    state == AppState.FatalRecovery
                            }
                    }
                }
                assertSame(AppState.NoProfiles, observed.first)
                assertEquals(before.settings.copy(routing = requested), observed.second)
                val after = requireNotNull(facade.readProjection())
                val semanticAfter = runBlocking {
                    (repository.appliedRevision() as DomainResult.Success<SettingsRevision>).value.revision
                }
                assertEquals(before.revision + 2, after.revision)
                assertEquals(semanticBefore + 1, semanticAfter)
                assertEquals(before.settings.copy(routing = requested), after.settings)
                assertEquals(before.profiles, after.profiles)
            }
        } finally {
            instrumentation.runOnMainSync { store.clear() }
            runBlocking {
                model?.viewModelScope?.coroutineContext?.get(Job)?.let {
                    withTimeout(10_000) { it.join() }
                }
            }
            try {
                if (root.protectedStateFacade() != null) {
                    assertTrue("isolated fixture reset must commit",
                        runBlocking { root.resetProtectedStateConfirmed() } is
                            ProtectedStateApplicationFacade.CommandResult.Committed)
                }
            } finally { root.close() }
        }
    }

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
        var root: ProductCompositionRoot? = null
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
            val opened = ProductCompositionRoot.create(context, owner, settingsRuntime = ::isolatedRuntime)
            root = opened
            assertEquals(
                "KURDISTAN_TEST_SETUP expected=FIRST_USE actual=${opened.storageFailure?.name ?: "AVAILABLE"} setup=ISOLATED_EMPTY_DIRECTORY",
                ProductCompositionRoot.StorageFailure.FIRST_USE,
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

            lateinit var settingsModel: org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel
            instrumentation.runOnMainSync {
                settingsModel = org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel(
                    opened.settingsRepository(), androidx.lifecycle.SavedStateHandle(), opened.nodeMaintenanceRepository)
                store.put("settings", settingsModel)
            }
            runBlocking { settingsModel.change { it.copy(highContrast = true) }.join(); model.refresh().join() }
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
            assertEquals(ProductCompositionRoot.StorageFailure.FIRST_USE, opened.storageFailure)
            val enrollment = runBlocking {
                val onboarding = org.kurdistanvpn.feature.onboarding.OnboardingViewModel(
                    opened.profileRepository, androidx.lifecycle.SavedStateHandle(), this)
                withTimeout(10_000) { onboarding.createEnrollment().join() }
                onboarding.state.value
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
