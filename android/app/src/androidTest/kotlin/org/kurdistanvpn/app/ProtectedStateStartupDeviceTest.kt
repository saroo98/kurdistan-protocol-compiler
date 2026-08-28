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
import org.kurdistanvpn.core.model.ProtectedRecoveryPresentation
import org.kurdistanvpn.data.protectedstate.ProtectedStateProcessOwner

/** Real Android construction and scheduling; compile-only during local non-device validation. */
class ProtectedStateStartupDeviceTest {
    @Test fun firstUseViewModelIsDisconnectedAndDoesNotProvisionProtectedState() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
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
            val opened = Phase9CompositionRoot.create(context, owner)
            root = opened
            assertEquals(Phase9CompositionRoot.StorageFailure.FIRST_USE, opened.storageFailure)
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
        } finally {
            instrumentation.runOnMainSync { store.clear() }
            root?.close() ?: owner.close()
        }
        assertTrue(model.viewModelScope.coroutineContext[Job]!!.isCancelled)
        assertSame(AppState.FirstLaunch, model.state.value)
    }
}
