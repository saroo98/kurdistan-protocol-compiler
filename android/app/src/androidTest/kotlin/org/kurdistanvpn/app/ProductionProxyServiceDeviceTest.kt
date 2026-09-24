// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.content.*
import android.os.*
import androidx.test.platform.app.InstrumentationRegistry
import java.io.DataInputStream
import java.io.File
import java.net.InetAddress
import java.net.Socket
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.flow.first
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativejni.Task7InstalledFixtureNative
import org.kurdistanvpn.runtime.android.*
import org.kurdistanvpn.runtime.api.*
import org.kurdistanvpn.data.settings.*

/** Separate fresh emulator fixture. The apparent public destination maps exclusively to its local echo server. */
class ProductionProxyServiceDeviceTest {
    @Test fun productionManualPreflightUsesExactProfileAndCompleteSettings() = runBlocking {
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KurdistanApplication
        Task7InstalledFixturePreparation.prepareProxyOrVerify(app)
        val projection = checkNotNull(app.compositionRoot.protectedStateFacade()?.readProjection())
        assertEquals(org.kurdistanvpn.core.model.TunnelMode.TUN_PLUS_PROXY, projection.settings.tunnelMode)
        val target = checkNotNull(projection.runtimeProfile)
        val id = org.kurdistanvpn.core.model.CatalogId(target.profileId)
        assertNull(app.compositionRoot.validateProductionManualStart(id, target.settingsRevision))
        assertEquals(org.kurdistanvpn.core.model.OperationError.POLICY_REJECTED,
            app.compositionRoot.validateProductionManualStart(id, target.settingsRevision + 1))
        assertEquals(org.kurdistanvpn.core.model.OperationError.POLICY_REJECTED,
            app.compositionRoot.validateProductionManualStart(org.kurdistanvpn.core.model.CatalogId("missing-profile"), target.settingsRevision))
        assertEquals(projection, app.compositionRoot.protectedStateFacade()?.readProjection())
    }
    @Test fun authenticatedLoopbackProxyTransfersThroughNativeAndStopsWithSession() = exercise(false)
    @Test fun signedProbeUsesTheActiveServiceWithoutReplacingTheTunnel() = exercise(false, activeProbe = true)
    @Test fun maintenanceRepositoryPersistsActualProbeWithoutReplacingTheTunnel() = exercise(false, repositoryProbe = true)
    @Test fun unsupportedUpdateRetiresMaintenanceAndCanBeCheckedAgainWithoutReplacingTheTunnel() =
        exercise(false, activeUpdate = true)
    @Test fun proxyOnlyTransfersTrafficWithoutClaimingDeviceTunnelProtection() = exercise(false, proxyOnly = true)
    @Test fun manualProductionStartAndActivityRecreationKeepVerifiedPresentation() = exercise(false, activityStart = true)
    @Test fun manualConnectActionTransfersTrafficAndKeepsVerifiedPresentation() =
        exercise(false, activityStart = true, manualAction = true)
    @Test fun encryptedDraftStagingPreservesActiveProxyAndResumesWithNewCoordinator() = exercise(false, draftStaging = true)
    @Test fun consecutiveSessionsRebindTheSamePortsAfterNativeTraffic() {
        exercise(false, rejectClient = true)
        exercise(false)
    }
    @Test fun settingsApplyReconnectsWithFreshAuthorityAndRestoresTheOriginalDraft() = exercise(true)
    @Test fun failedSettingsApplicationRestoresStorageAndTheOriginalNativeSession() = exercise(true, true)
    @Test fun persistedPauseBlocksRuntimeAdmissionUntilExplicitResume() = exercise(false, pauseBeforeStart = true)
    @Test fun stopInvalidatesThePendingSettingsContinuation() = exercise(false, stopRace = true)
    @Test fun foregroundAutomaticStartUsesFreshBootstrapAndRejectsBackgroundEntry() = exercise(false, automatic = true)
    @Test fun killedActiveProcessRestartsWithFreshBootstrapAndProxyCredentials() = exercise(false, automatic = true, restartActive = true)
    @Test fun survivingControllerRestoresKilledProcessAndProxyTraffic() =
        exercise(false, automatic = true, restartActive = true, retainController = true)
    @Test fun killedProcessRestartsWithoutAnySurvivingControlBinding() =
        exercise(false, automatic = true, restartActive = true, releaseObservation = true)
    @Test fun ignoredInvalidStartPreservesActiveRestartEligibility() =
        exercise(false, automatic = true, rejectWhileActive = true)
    @Test fun systemAlwaysOnRestartsTheKilledProcessWithLockdownStillEnabled() {
        org.junit.Assume.assumeTrue(Build.VERSION.SDK_INT == 36)
        exercise(false, automatic = true, restartActive = true, systemAlwaysOn = true, releaseObservation = true)
    }
    @Test fun explicitPauseStopsBeforeCommitAndResumeDoesNotConnect() = exercise(false, pauseActive = true)
    @Test fun proxyRestartKeepsTheTunnelAndReplacesItsCredentials() = exercise(false, restartProxy = true)
    @Test fun foregroundEntryClearsOnlyAnExpiredPause() {
        check(Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk")) { "EMULATOR_ONLY" }
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KurdistanApplication
        runBlocking {
            Task7InstalledFixturePreparation.prepareProxyOrVerify(app)
            val facade = checkNotNull(app.compositionRoot.protectedStateFacade())
            val projection = checkNotNull(facade.readProjection())
            val revision = (checkNotNull(facade.settingsRepository()).appliedRevision() as org.kurdistanvpn.domain.DomainResult.Success).value.revision
            assertTrue(facade.applyPause(projection.revision, revision,
                org.kurdistanvpn.data.secure.StoredPauseState(100000, 10000, 3, 60000)) is
                org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
            val store = androidx.lifecycle.ViewModelStore()
            val model = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                ProductRootViewModel(app.compositionRoot).also { store.put("pause-expiry", it) }
            }
            try {
                kotlinx.coroutines.withTimeout(10000) { model.state.first { it is org.kurdistanvpn.core.model.AppState.Ready } }
                app.compositionRoot.expireForegroundPause(160000, 69999, 3)
                assertNotNull(facade.readProductStorage()?.pause)
                app.compositionRoot.expireForegroundPause(100001, 70000, 3)
                assertNull(facade.readProductStorage()?.pause)
                assertEquals(org.kurdistanvpn.core.model.PausePolicy.NOT_PAUSED, facade.readProjection()?.settings?.pausePolicy)
            } finally { kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) { store.clear() } }
            Task7InstalledFixturePreparation.prepareProxyOrVerify(app)
        }
    }
    private fun exercise(applySettings: Boolean, failFirstApply: Boolean = false, pauseBeforeStart: Boolean = false,
        stopRace: Boolean = false, automatic: Boolean = false, pauseActive: Boolean = false, restartActive: Boolean = false,
        systemAlwaysOn: Boolean = false, restartProxy: Boolean = false, retainController: Boolean = false,
        rejectWhileActive: Boolean = false, releaseObservation: Boolean = false, rejectClient: Boolean = false,
        draftStaging: Boolean = false, activityStart: Boolean = false, proxyOnly: Boolean = false,
        activeProbe: Boolean = false, activeUpdate: Boolean = false, repositoryProbe: Boolean = false,
        manualAction: Boolean = false) {
        check(Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk")) { "EMULATOR_ONLY" }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        fun publicationDiagnostic(): String {
            val adapter = (context.applicationContext as KurdistanApplication).runtimeAuthorityReissue
            val values = (adapter.javaClass.declaredMethods.single {
                it.name.startsWith("responseDiagnosticSnapshot") && it.parameterCount == 1
            }.apply { isAccessible = true }.invoke(adapter, 1) as LongArray).joinToString()
            val facade = (context.applicationContext as KurdistanApplication).compositionRoot.protectedStateFacade()
            val read = facade?.reconstructProductionCapture(object : org.kurdistanvpn.data.protectedstate.ProtectedAuthorityEnvironment {
                override fun isUserUnlocked() = context.getSystemService(UserManager::class.java).isUserUnlocked
                override fun isConsentPrepared() = android.net.VpnService.prepare(context) == null
                override fun isCancelled() = false
                override fun elapsedRealtimeMillis() = SystemClock.elapsedRealtime()
            })
            val category = when (read) {
                is org.kurdistanvpn.data.protectedstate.ProductionCaptureReadResult.Ready -> {
                    read.capture.close(); "READY"
                }
                is org.kurdistanvpn.data.protectedstate.ProductionCaptureReadResult.Rejected -> "${read.category}/${read.error}"
                null -> "UNAVAILABLE"
            }
            val projection = facade?.readProjection()
            val selected = projection?.profiles?.singleOrNull {
                it.localRecordId == projection.settings.profiles.activeLocalRecordId
            }
            val expired = selected?.let { it.expiresAtEpochSeconds <= System.currentTimeMillis() / 1000 }
            return "$values; fresh-capture=$category; selected-expired=$expired"
        }
        if (automatic) {
            // Cold automatic entry must not inherit the previous test's explicit Stop suppression.
            // Kill only this owned emulator application's VPN process, not its stored state.
            val manager = context.getSystemService(android.app.ActivityManager::class.java)
            manager.runningAppProcesses.orEmpty().singleOrNull { it.processName == "${context.packageName}:vpn" }?.let { process ->
                InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(
                    "run-as ${context.packageName} kill -9 ${process.pid}").use { descriptor ->
                    ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes() }
                }
                val diedBy = SystemClock.elapsedRealtime() + 5000
                while (manager.runningAppProcesses.orEmpty().any { it.pid == process.pid } && SystemClock.elapsedRealtime() < diedBy)
                    SystemClock.sleep(25)
                assertFalse(manager.runningAppProcesses.orEmpty().any { it.pid == process.pid })
            }
        }
        runBlocking { Task7InstalledFixturePreparation.prepareProxyOrVerify(context.applicationContext as KurdistanApplication) }
        val facade = checkNotNull((context.applicationContext as KurdistanApplication).compositionRoot.protectedStateFacade())
        val originalModeSettings = if (proxyOnly) checkNotNull(facade.readProjection()).settings else null
        if (originalModeSettings != null) runBlocking {
            val projection = checkNotNull(facade.readProjection())
            val revision = (checkNotNull(facade.settingsRepository()).appliedRevision() as org.kurdistanvpn.domain.DomainResult.Success).value.revision
            assertTrue(facade.applyProductionSettings(projection.revision, revision,
                originalModeSettings.copy(tunnelMode = org.kurdistanvpn.core.model.TunnelMode.PROXY_ONLY)) is
                org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
        }
        fun pause(timer: org.kurdistanvpn.data.secure.StoredPauseState?) = runBlocking {
            val projection = checkNotNull(facade.readProjection())
            val revision = (checkNotNull(facade.settingsRepository()).appliedRevision() as org.kurdistanvpn.domain.DomainResult.Success).value.revision
            assertTrue(facade.applyPause(projection.revision, revision, timer) is org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
        }
        if (pauseBeforeStart) pause(org.kurdistanvpn.data.secure.StoredPauseState(System.currentTimeMillis(), SystemClock.elapsedRealtime(), 0, 0))
        val relay = Task7InstalledFixtureNative()
        assertEquals(0, relay.startRelay(File(context.filesDir, "task12-installed-proxy-v1").absolutePath, 0))
        val ready = CountDownLatch(1)
        val binder = java.util.concurrent.atomic.AtomicReference<IBinder?>()
        val disconnected = java.util.concurrent.atomic.AtomicInteger()
        val bindingDied = java.util.concurrent.atomic.AtomicInteger()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) { binder.set(service); ready.countDown() }
            override fun onServiceDisconnected(name: ComponentName?) { disconnected.incrementAndGet() }
            override fun onBindingDied(name: ComponentName?) { bindingDied.incrementAndGet() }
        }
        var bound = context.bindService(Intent(RuntimeControlBinder.ACTION_BIND).setComponent(ComponentName(context, KurdVpnService::class.java)),
            connection, Context.BIND_AUTO_CREATE)
        var primaryFailure: Throwable? = null
        var survivingController: VpnRuntimeController? = null
        var activity: androidx.test.core.app.ActivityScenario<MainActivity>? = null
        var manualStartedAt = 0L
        try {
            assertTrue(bound && ready.await(10, TimeUnit.SECONDS))
            var control = IRuntimeControl.Stub.asInterface(checkNotNull(binder.get()))
            val version = RuntimeStatusWire.VERSION
            if (systemAlwaysOn) setSystemAlwaysOn(context, context.packageName)
            else if (automatic) runBlocking {
                val controller = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) { VpnRuntimeController(context) }
                try {
                    kotlinx.coroutines.withTimeout(10000) { controller.controlReady.first { it } }
                    controller.startOnForegroundLaunch { false }
                    assertEquals(VpnRuntimeState.IDLE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
                    controller.startOnForegroundLaunch { true }
                } finally {
                    controller.close()
                }
            } else if (activityStart) {
                val target = checkNotNull(facade.readProjection()?.runtimeProfile)
                activity = androidx.test.core.app.ActivityScenario.launch(MainActivity::class.java)
                if (manualAction) {
                    val readyBy = SystemClock.elapsedRealtime() + 30_000
                    var appReady = false
                    do {
                        activity.onActivity { appReady = it.appStateSnapshotForTesting() is org.kurdistanvpn.core.model.AppState.Ready }
                        if (!appReady) SystemClock.sleep(25)
                    } while (!appReady && SystemClock.elapsedRealtime() < readyBy)
                    assertTrue("Manual Connect requires the real ready screen", appReady)
                }
                activity.onActivity {
                    if (manualAction) manualStartedAt = SystemClock.elapsedRealtime()
                    if (manualAction) MainActivity::class.java.getDeclaredMethod("requestManualConnection")
                        .apply { isAccessible = true }.invoke(it)
                    else assertTrue(it.beginConnection(org.kurdistanvpn.core.model.CatalogId(target.profileId), target.settingsRevision))
                }
            } else KurdVpnService.start(context, KurdVpnService.newRequestId())
            val deadline = SystemClock.elapsedRealtime() + 30000
            var state: VpnRuntimeSnapshot
            val openingStates = linkedSetOf<String>()
            do {
                state = RuntimeStatusWire.decode(control.queryStatus(version))
                if (openingStates.size < 64) openingStates.add("${state.state}/${state.failure}/${state.packetDisposition}")
                if (state.state in setOf(VpnRuntimeState.ACTIVE_KURD_LIVE, VpnRuntimeState.BLOCKED, VpnRuntimeState.FAILED)) break
                SystemClock.sleep(25)
            } while (SystemClock.elapsedRealtime() < deadline)
            if (pauseBeforeStart) {
                assertEquals("PAUSED", state.failure)
                assertNotEquals(VpnRuntimeState.ACTIVE_KURD_LIVE, state.state)
                return
            }
            if (state.state != VpnRuntimeState.ACTIVE_KURD_LIVE) {
                // Existing bounded scalar observations only; no authority or exception text.
                fun category(value: String?): String = value?.takeIf { it.matches(Regex("[A-Z0-9_]{1,64}")) } ?: "UNAVAILABLE"
                throw AssertionError("KURDISTAN_TEST_SETUP expected=ACTIVE_KURD_LIVE actual=${state.state.name} setup=PROXY_ACTIVATION,${category(state.failure)},${category(state.packetDisposition)}",
                    AssertionError("Proxy activation: ${state.state}/${state.failure}/${state.packetDisposition}; opening=$openingStates; publication=${publicationDiagnostic()}"))
            }
            val presentation = checkNotNull(state.presentation) { "Production presentation evidence missing" }
            if (manualAction) {
                val observedAt = SystemClock.elapsedRealtime()
                val adapter = (context.applicationContext as KurdistanApplication).runtimeAuthorityReissue
                val arm = checkNotNull(adapter.javaClass.getDeclaredField("arm").apply { isAccessible = true }.get(adapter))
                val lease = arm.javaClass.getDeclaredField("lease").apply { isAccessible = true }.get(arm) as RuntimeProviderRevisionLease
                val leaseReturnedAt = arm.javaClass.getDeclaredField("leaseReturnedAt").apply { isAccessible = true }.getLong(arm)
                val publication = adapter.javaClass.declaredMethods.single {
                    it.name.startsWith("responseDiagnosticSnapshot") && it.parameterCount == 1
                }.apply { isAccessible = true }.invoke(adapter, 1) as LongArray
                val releaseAge = publication[14]
                assertTrue("Final publication was accepted", publication[12] == 7L && publication[13] == 0L && releaseAge >= 0)
                val publicationHeadroom = checkNotNull(lease.publicationDeadlineElapsedMillis) - leaseReturnedAt - releaseAge
                assertTrue("Publication stayed inside the unchanged lease", publicationHeadroom > 0)
                println("MANUAL_CONNECT_MEASUREMENT active_ms=${observedAt - manualStartedAt} publication_headroom_ms=$publicationHeadroom publication=${publication.joinToString(",")}")
            }
            assertEquals(state.runtimeRequestId, presentation.nativeSessionId)
            assertEquals(facade.readProjection()?.settings?.profiles?.activeLocalRecordId, presentation.binding.profileId)
            assertEquals(state.profileGeneration, presentation.binding.profileGeneration)
            assertEquals(state.runtimeRequestId, presentation.proxySessionId)
            if (proxyOnly) {
                assertNull(presentation.tunSessionId)
                assertNull(presentation.routeRevision)
                assertNull(presentation.dnsRevision)
                val current = runBlocking { (context.applicationContext as KurdistanApplication).compositionRoot.readConnectionCurrent() }
                assertFalse(productConnectionPresentation(state, current.profile, current.binding, current.storage,
                    System.currentTimeMillis() / 1000) is org.kurdistanvpn.core.model.ConnectionState.Connected)
            } else {
                assertEquals(state.runtimeRequestId, presentation.tunSessionId)
                assertEquals(presentation.binding.settingsRevision, presentation.routeRevision)
                assertEquals(presentation.binding.settingsRevision, presentation.dnsRevision)
            }
            if (activeProbe || activeUpdate || repositoryProbe) runBlocking {
                val controller = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                    if (repositoryProbe || activeUpdate) (context.applicationContext as KurdistanApplication).runtimeController
                    else VpnRuntimeController(context)
                }
                try {
                    kotlinx.coroutines.withTimeout(10_000) { controller.controlReady.first { it } }
                    val selected = org.kurdistanvpn.core.model.CatalogId(presentation.binding.profileId)
                    if (activeUpdate) {
                        val root = (context.applicationContext as KurdistanApplication).compositionRoot
                        val prior = checkNotNull(facade.readProductStorage(selected.value))
                        try {
                            repeat(2) { attempt ->
                                assertEquals(org.kurdistanvpn.domain.DomainResult.Rejected(org.kurdistanvpn.core.model.ProductFailure(
                                    org.kurdistanvpn.core.model.ProductFailureCode.PROFILE_INCOMPATIBLE)),
                                    root.nodeMaintenanceRepository.checkSignedUpdate(selected))
                                val stored = checkNotNull(facade.readProductStorage(selected.value))
                                assertEquals(org.kurdistanvpn.core.model.UpdateCategory.REJECTED, stored.update?.category)
                                assertEquals(((prior.update?.failureCount ?: 0) + attempt + 1).coerceAtMost(10), stored.update?.failureCount)
                                assertEquals(prior.revision, stored.revision)
                                assertEquals(state.runtimeRequestId, RuntimeStatusWire.decode(control.queryStatus(version)).runtimeRequestId)
                            }
                        } finally {
                            val after = checkNotNull(facade.readProductStorage(selected.value))
                            val restore = prior.update ?: org.kurdistanvpn.data.secure.StoredUpdateState(
                                after.update?.publicationGeneration, after.update?.profileGeneration,
                                org.kurdistanvpn.core.model.UpdateCategory.NOT_CHECKED, 0, 0, 0)
                            assertTrue(facade.recordUpdate(after.revision, selected.value, restore) is
                                org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
                        }
                        return@runBlocking
                    }
                    val request = Task7InstalledFixturePreparation.selectedProbe()
                    if (repositoryProbe) {
                        val root = (context.applicationContext as KurdistanApplication).compositionRoot
                        val repository = root.nodeMaintenanceRepository
                        assertSame(repository, root.nodeMaintenanceRepository)
                        val prior = checkNotNull(facade.readProductStorage(selected.value))
                        val result = repository.probe(selected, request)
                        assertTrue("Repository probe: $result", result is org.kurdistanvpn.domain.DomainResult.Success)
                        val sample = (result as org.kurdistanvpn.domain.DomainResult.Success).value
                        assertNull(sample.failure)
                        assertEquals(sample, repository.observeProbeHistory(selected).first().samples.last())
                        val rejectedProbe = repository.probe(selected, request.copy(method = org.kurdistanvpn.core.model.ProbeMethod.KURD_SESSION))
                        assertTrue(rejectedProbe is org.kurdistanvpn.domain.DomainResult.Success)
                        val failedSample = (rejectedProbe as org.kurdistanvpn.domain.DomainResult.Success).value
                        assertNotNull(failedSample.failure)
                        assertEquals(failedSample, repository.observeProbeHistory(selected).first().samples.last())
                        assertEquals(prior.revision, facade.readProductStorage(selected.value)?.revision)
                        assertTrue(facade.recordProbe(prior.revision, selected.value, prior.probeHistory ?:
                            org.kurdistanvpn.data.secure.StoredProbeHistory(System.currentTimeMillis() / 60_000, emptyList())) is
                            org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
                        assertEquals(state.runtimeRequestId, RuntimeStatusWire.decode(control.queryStatus(version)).runtimeRequestId)
                        return@runBlocking
                    }
                    assertEquals(org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure(
                        org.kurdistanvpn.core.model.ProductFailureCode.PROFILE_INCOMPATIBLE),
                        controller.runSelectedProbe(org.kurdistanvpn.core.model.CatalogId("missing-profile"), request))
                    val result = controller.runSelectedProbe(selected, request)
                    assertTrue("Actual signed probe result: $result", result is org.kurdistanvpn.core.nativeapi.NativeProductResult.Success)
                    val value = (result as org.kurdistanvpn.core.nativeapi.NativeProductResult.Success).value
                    assertEquals(org.kurdistanvpn.core.nativeapi.NativeProbePath.ACTIVE_RELAY_END_TO_END, value.path)
                    assertEquals(1, value.succeeded)
                    assertNotNull(value.meanLatencyMicros)
                    val beforeHistory = checkNotNull(facade.readProductStorage(selected.value))
                    val epochMinute = System.currentTimeMillis() / 60_000
                    val sample = org.kurdistanvpn.core.model.ProbeSample(epochMinute,
                        (checkNotNull(value.meanLatencyMicros).toLong() / 1000).toInt(), 0, 0,
                        org.kurdistanvpn.core.model.ProbeStability.UNKNOWN, null)
                    val history = org.kurdistanvpn.data.secure.StoredProbeHistory(epochMinute, listOf(sample))
                    assertTrue(facade.recordProbe(beforeHistory.revision, selected.value, history) is
                        org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
                    assertEquals(listOf(sample), facade.readProductStorage(selected.value)?.probeHistory?.samples)
                    assertEquals(beforeHistory.revision, facade.readProductStorage(selected.value)?.revision)
                    assertTrue(facade.recordProbe(beforeHistory.revision, selected.value,
                        beforeHistory.probeHistory ?: org.kurdistanvpn.data.secure.StoredProbeHistory(epochMinute, emptyList())) is
                        org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
                    assertEquals(state.runtimeRequestId, RuntimeStatusWire.decode(control.queryStatus(version)).runtimeRequestId)
                } finally { controller.close() }
            }
            if (activityStart) {
                activity?.recreate()
                val app = context.applicationContext as KurdistanApplication
                val categories = linkedSetOf<String>()
                val displayed = runBlocking { kotlinx.coroutines.withTimeoutOrNull(10_000) {
                    app.compositionRoot.connectionRepository.observeState().first {
                        categories.add(it.category.name)
                        it is org.kurdistanvpn.core.model.ConnectionState.Connected
                    }
                } }
                if (displayed == null) {
                    val fresh = facade.readProjection()
                    val selected = fresh?.profiles?.singleOrNull { it.localRecordId == fresh.settings.profiles.activeLocalRecordId }
                    val observed = app.runtimeController.snapshot.value
                    fail("Presentation categories=$categories; trust=${selected?.trust}; health=${fresh?.health}; " +
                        "profileMatches=${fresh?.runtimeProfile?.profileId == observed.presentation?.binding?.profileId}; " +
                        "trustMatches=${fresh?.runtimeProfile?.trustRevision == observed.presentation?.binding?.trustRevision}; " +
                        "settingsMatches=${fresh?.runtimeProfile?.settingsRevision == observed.presentation?.binding?.settingsRevision}; " +
                        "packagesMatch=${currentRuntimePackageRevision(context) == observed.presentation?.binding?.packageRevision}; " +
                        "observed=${observed.state}/${observed.failure}/${observed.ipMode}; proof=${observed.presentation != null}")
                }
                assertTrue(displayed is org.kurdistanvpn.core.model.ConnectionState.Connected)
                assertEquals(state.runtimeRequestId, RuntimeStatusWire.decode(control.queryStatus(version)).runtimeRequestId)
                // The app already owns this PID's one admitted observer; use its credential/action path.
                survivingController = app.runtimeController
                activity?.close(); activity = null
            }
            if (draftStaging) runBlocking {
                val original = checkNotNull(facade.settingsRepository())
                val before = checkNotNull(facade.readProjection())
                val draft = (original.openDraft() as org.kurdistanvpn.domain.DomainResult.Success).value
                val requested = draft.basedOn.settings.copy(highContrast = !draft.basedOn.settings.highContrast)
                assertTrue(original.saveDraft(draft.id, requested) is org.kurdistanvpn.domain.DomainResult.Success)
                val noRuntimeWork = object : SettingsRuntimePort {
                    override suspend fun prepare(): SettingsPortResult<SettingsRuntimeIntent> = error("Editing must not prepare runtime")
                    override suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState): SettingsPortResult<Unit> =
                        error("Editing must not apply runtime")
                }
                val recreated = checkNotNull(facade.settingsRepository(noRuntimeWork))
                val restored = (recreated.resumeDraft(draft.id) as org.kurdistanvpn.domain.DomainResult.Success).value
                assertEquals(requested, restored.requested)
                assertEquals(before, facade.readProjection())
                val stillActive = RuntimeStatusWire.decode(control.queryStatus(version))
                assertEquals(VpnRuntimeState.ACTIVE_KURD_LIVE, stillActive.state)
                assertEquals(state.runtimeRequestId, stillActive.runtimeRequestId)
                assertTrue(recreated.cancel(draft.id) is org.kurdistanvpn.domain.DomainResult.Success)
                assertTrue(original.resumeDraft(draft.id) is org.kurdistanvpn.domain.DomainResult.Rejected)
            }
            if (rejectWhileActive) {
                fun serviceState(): String = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(
                    "dumpsys activity services ${context.packageName}/org.kurdistanvpn.runtime.android.KurdVpnService").use {
                    ParcelFileDescriptor.AutoCloseInputStream(it).use { input -> input.readBytes().toString(Charsets.UTF_8) }
                }
                val startId = Regex("lastStartId=(\\d+)")
                val before = checkNotNull(startId.find(serviceState())).value
                context.startService(Intent(context, KurdVpnService::class.java)
                    .setAction(RuntimeServiceCommand.ACTION_START)
                    .putExtra(RuntimeServiceCommand.MARKER_KEY, -1))
                val until = SystemClock.elapsedRealtime() + 5000
                var dump: String
                do {
                    dump = serviceState()
                    if (startId.find(dump)?.value != before && !dump.contains("executeNesting=")) break
                    SystemClock.sleep(25)
                } while (SystemClock.elapsedRealtime() < until)
                assertNotEquals("Rejected start must have been processed", before, startId.find(dump)?.value)
                assertTrue("Ignored command must preserve active restart eligibility", dump.contains("stopIfKilled=false"))
                val after = RuntimeStatusWire.decode(control.queryStatus(version))
                assertEquals(VpnRuntimeState.ACTIVE_KURD_LIVE, after.state)
                assertEquals(state.runtimeRequestId, after.runtimeRequestId)
            }
            if (systemAlwaysOn) { assertEquals(true, state.alwaysOn); assertEquals(true, state.lockdown) }
            if (restartActive) {
                if (retainController) {
                    androidx.test.core.app.ActivityScenario.launch(MainActivity::class.java).use { screen ->
                        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
                        screen.onActivity { survivingController = (it.application as KurdistanApplication).runtimeController }
                        runBlocking { kotlinx.coroutines.withTimeout(10000) {
                            checkNotNull(survivingController).snapshot.first { it.state == VpnRuntimeState.ACTIVE_KURD_LIVE }
                        } }
                        screen.moveToState(androidx.lifecycle.Lifecycle.State.DESTROYED)
                    }
                    assertFalse("Active session must retain its screen-detached controller", checkNotNull(survivingController).isClosed)
                }
                val retiredBinder = checkNotNull(binder.get())
                val manager = context.getSystemService(android.app.ActivityManager::class.java)
                val process = manager.runningAppProcesses.orEmpty().single { it.processName == "${context.packageName}:vpn" }
                if (releaseObservation || retainController) {
                    check(retainController || survivingController == null)
                    context.unbindService(connection); bound = false; binder.set(null)
                }
                android.util.Log.i("RecoveryObservation", "begin oldPid=${process.pid}")
                InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(
                    if (Build.VERSION.SDK_INT == 36) "su 0 kill -9 ${process.pid}"
                    else "run-as ${context.packageName} kill -9 ${process.pid}").use { descriptor ->
                    ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes() }
                }
                relay.cancel()
                val joinedBy = SystemClock.elapsedRealtime() + 5000
                while (relay.snapshot()[11] != 1L && SystemClock.elapsedRealtime() < joinedBy) SystemClock.sleep(10)
                assertEquals(1L, relay.snapshot()[11]); assertEquals(0, relay.finish())
                assertEquals(0, relay.startRelay(File(context.filesDir, "task12-installed-proxy-v1").absolutePath, 0))
                val restartedBy = SystemClock.elapsedRealtime() + 60000
                var restored: VpnRuntimeSnapshot? = null
                var everNewPid = false
                var everSocksResponse = false
                while (SystemClock.elapsedRealtime() < restartedBy) {
                    val newPid = manager.runningAppProcesses.orEmpty().any {
                        it.processName == "${context.packageName}:vpn" && it.pid != process.pid }
                    everNewPid = everNewPid || newPid
                    if (newPid && bound && binder.get() === retiredBinder && !retiredBinder.pingBinder()) {
                        context.unbindService(connection); bound = false; binder.set(null)
                    }
                    if (!bound && newPid) {
                        // Observe the already restarted listener before adding a control binding.
                        // This unauthenticated local handshake cannot open a native stream or start VPN.
                        val listening = try {
                            Socket().use { socket ->
                                socket.connect(java.net.InetSocketAddress("127.0.0.1", 10808), 100)
                                socket.soTimeout = 100
                                socket.getOutputStream().write(byteArrayOf(5, 1, 2))
                                socket.getInputStream().read() == 5 && socket.getInputStream().read() == 2
                            }
                        } catch (_: java.io.IOException) { false }
                        everSocksResponse = everSocksResponse || listening
                        // Recovery is already proven by a new PID and live listener. Retain
                        // this instance now so terminal cleanup can still be queried after Stop.
                        if (listening) bound = context.bindService(Intent(RuntimeControlBinder.ACTION_BIND)
                            .setComponent(ComponentName(context, KurdVpnService::class.java)), connection, Context.BIND_AUTO_CREATE)
                    }
                    val next = binder.get()
                    if (next != null && next !== retiredBinder && next.isBinderAlive) {
                        control = IRuntimeControl.Stub.asInterface(next)
                        restored = RuntimeStatusWire.decode(control.queryStatus(version))
                        if (restored.state == VpnRuntimeState.ACTIVE_KURD_LIVE) break
                    }
                    SystemClock.sleep(25)
                }
                android.util.Log.i("RecoveryObservation", "end newPid=$everNewPid socks=$everSocksResponse state=${restored?.state}")
                assertEquals("Process restart: ${restored?.state}/${restored?.failure}; newPid=$everNewPid, socks=$everSocksResponse, disconnected=${disconnected.get()}, bindingDied=${bindingDied.get()}; controller=${survivingController?.snapshot?.value?.state}/${survivingController?.snapshot?.value?.failure}/${survivingController?.isClosed}; publication=${publicationDiagnostic()}; relay=${relay.snapshot().joinToString()}", VpnRuntimeState.ACTIVE_KURD_LIVE, restored?.state)
                // No death recipient remains after unbinding; probe the old remote object.
                assertFalse(retiredBinder.pingBinder())
                if (systemAlwaysOn) { assertEquals(true, restored?.alwaysOn); assertEquals(true, restored?.lockdown) }
            }
            val observer = object : IRuntimeObserver.Stub() { override fun onStatus(bytes: ByteArray?) = Unit }
            if (pauseActive) runBlocking {
                survivingController = (context.applicationContext as KurdistanApplication).runtimeController
                kotlinx.coroutines.withTimeout(10000) { checkNotNull(survivingController).controlReady.first { it } }
            }
            if (survivingController == null) assertTrue(control.registerObserver(version, observer))
            try {
                var sequence = 0L
                if (restartProxy) {
                    fun secret(): ByteArray {
                        val bytes = ByteArray(ProxyCredentialLeaseWire.SIZE)
                        try {
                            ParcelFileDescriptor.AutoCloseInputStream(checkNotNull(control.requestProxyCredentials(version, ++sequence, observer))).use {
                                DataInputStream(it).readFully(bytes)
                            }
                            return ProxyCredentialLeaseWire.decode(bytes, SystemClock.elapsedRealtime())
                        } finally { bytes.fill(0) }
                    }
                    val previous = secret()
                    try {
                        assertTrue(control.requestAction(version, ++sequence, 9, observer))
                        val replacedBy = SystemClock.elapsedRealtime() + 5000
                        var changed = false
                        while (!changed && SystemClock.elapsedRealtime() < replacedBy) {
                            val next = try { secret() } catch (_: IllegalStateException) { null }
                            if (next != null) try { changed = !previous.contentEquals(next) } finally { next.fill(0) }
                            if (!changed) SystemClock.sleep(25)
                        }
                        assertTrue("Proxy credentials must be replaced", changed)
                        val after = RuntimeStatusWire.decode(control.queryStatus(version))
                        assertEquals(VpnRuntimeState.ACTIVE_KURD_LIVE, after.state)
                        assertEquals(state.runtimeRequestId, after.runtimeRequestId)
                    } finally { previous.fill(0) }
                }
                if (pauseActive) runBlocking {
                    val repository = (context.applicationContext as KurdistanApplication).compositionRoot.connectionRepository
                    val paused = repository.pause(900000)
                    if (Build.VERSION.SDK_INT < 29) {
                        // Without authoritative system-policy visibility, Pause must fail closed.
                        assertEquals(org.kurdistanvpn.domain.DomainResult.Rejected(org.kurdistanvpn.core.model.ProductFailure(
                            org.kurdistanvpn.core.model.ProductFailureCode.ROUTE_POLICY_REJECTED)), paused)
                        assertEquals(VpnRuntimeState.ACTIVE_KURD_LIVE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
                        assertNull(facade.readProductStorage()?.pause)
                        return@runBlocking
                    }
                    assertTrue(paused is org.kurdistanvpn.domain.DomainResult.Success)
                    assertEquals(VpnRuntimeState.IDLE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
                    assertEquals(900000L, facade.readProductStorage()?.pause?.durationMillis)
                    assertTrue(repository.resume() is org.kurdistanvpn.domain.DomainResult.Success)
                    assertNull(facade.readProductStorage()?.pause)
                    assertEquals(VpnRuntimeState.IDLE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
                }
                if (pauseActive) return
                if (stopRace) {
                    val lease = checkNotNull(control.settingsTransition(version, ++sequence, RuntimeControlBinder.SETTINGS_PREPARE, null, observer))
                    val until = SystemClock.elapsedRealtime() + 15000
                    while (RuntimeStatusWire.decode(control.queryStatus(version)).state != VpnRuntimeState.IDLE && SystemClock.elapsedRealtime() < until)
                        SystemClock.sleep(25)
                    assertEquals(VpnRuntimeState.IDLE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
                    assertTrue(control.requestAction(version, ++sequence, RuntimeAction.STOP.wireCode, observer))
                    assertNull(control.settingsTransition(version, ++sequence, RuntimeControlBinder.SETTINGS_RESUME, lease, observer))
                    return
                }
                if (applySettings) {
                    var resumed = 0
                    var rejectAppliedAcknowledgement = false
                    val transitions = mutableListOf<String>()
                    val port = RuntimeSettingsApplyPort({ operation, token ->
                        if (operation == RuntimeControlBinder.SETTINGS_RESUME) {
                            resumed++
                            relay.cancel()
                            val joinedBy = SystemClock.elapsedRealtime() + 5000
                            while (relay.snapshot()[11] != 1L && SystemClock.elapsedRealtime() < joinedBy) SystemClock.sleep(10)
                            assertEquals(1L, relay.snapshot()[11]); assertEquals(0, relay.finish())
                            assertEquals(0, relay.startRelay(File(context.filesDir, "task12-installed-proxy-v1").absolutePath, 0))
                        }
                        control.settingsTransition(version, ++sequence, operation, token, observer).also {
                            transitions.add("$operation:${it != null}")
                        }
                    }, {
                        val actual = RuntimeStatusWire.decode(control.queryStatus(version))
                        // Fail only the first acknowledgement; all storage, IPC and native work remain real.
                        if (rejectAppliedAcknowledgement && actual.state == VpnRuntimeState.ACTIVE_KURD_LIVE)
                            actual.copy(appliedRevision = actual.appliedRevision + 2) else actual
                    })
                    val tracedPort = object : SettingsRuntimePort by port {
                        override suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState): SettingsPortResult<Unit> {
                            transitions.add("apply:${committed.journalRevision}")
                            rejectAppliedAcknowledgement = failFirstApply
                            return try { port.apply(intent, committed) }
                            finally { rejectAppliedAcknowledgement = false }
                        }
                        override suspend fun restore(intent: SettingsRuntimeIntent, restoredState: SettingsStoreState): SettingsPortResult<Unit> {
                            transitions.add("restore:${restoredState.journalRevision}")
                            return port.restore(intent, restoredState)
                        }
                    }
                    val repository = checkNotNull((context.applicationContext as KurdistanApplication).compositionRoot.settingsRepository(tracedPort))
                    runBlocking {
                        val draft = (repository.openDraft() as org.kurdistanvpn.domain.DomainResult.Success).value
                        val original = draft.basedOn.settings
                        val changed = original.copy(tunnel = original.tunnel.copy(mtu = if (original.tunnel.mtu == 1280) 1400 else 1280))
                        if (!failFirstApply) {
                            val store = androidx.lifecycle.ViewModelStore()
                            val model = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                                org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel(repository,
                                    androidx.lifecycle.SavedStateHandle(), (context.applicationContext as KurdistanApplication).compositionRoot.nodeMaintenanceRepository)
                                    .also { store.put("settings-check", it) }
                            }
                            try {
                                model.change { changed }.join()
                                val failedState = RuntimeStatusWire.decode(control.queryStatus(version))
                                assertNull("Settings start state=${failedState.state}/${failedState.failure}/${failedState.packetDisposition}; publication=${publicationDiagnostic()}; transitions=$transitions", model.changeFailure.value)
                                assertEquals(changed, model.appliedSettings.value)
                                model.change { original }.join()
                                assertNull(model.changeFailure.value)
                                assertEquals(original, model.appliedSettings.value)
                            } finally { kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) { store.clear() } }
                            return@runBlocking
                        }
                        val result = repository.apply(draft.id, draft.basedOn.revision, changed)
                        val failure = (result as? org.kurdistanvpn.domain.DomainResult.Rejected)?.failure?.code
                        if (failFirstApply) {
                            assertEquals("Settings outcome; transitions=$transitions", org.kurdistanvpn.core.model.ProductFailureCode.TUN_ESTABLISH_FAILED, failure)
                            assertEquals(original, (repository.appliedRevision() as org.kurdistanvpn.domain.DomainResult.Success).value.settings)
                            val snapshot = RuntimeStatusWire.decode(control.queryStatus(version))
                            assertEquals("Rollback resumes; state=${snapshot.state}, failure=${snapshot.failure}, revision=${snapshot.appliedRevision}, transitions=$transitions", 2, resumed)
                        } else {
                            assertTrue("Settings apply failure=$failure", result is org.kurdistanvpn.domain.DomainResult.Success)
                            val restore = (repository.openDraft() as org.kurdistanvpn.domain.DomainResult.Success).value
                            assertTrue(repository.apply(restore.id, restore.basedOn.revision, original) is org.kurdistanvpn.domain.DomainResult.Success)
                        }
                    }
                    runBlocking { Task7InstalledFixturePreparation.prepareProxyOrVerify(context.applicationContext as KurdistanApplication) }
                    val lifetime = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(
                        "dumpsys activity services ${context.packageName}/org.kurdistanvpn.runtime.android.KurdVpnService").use {
                        ParcelFileDescriptor.AutoCloseInputStream(it).use { input -> input.readBytes().toString(Charsets.UTF_8) }
                    }
                    assertTrue("Reconnected service must retain its started lifetime after settings completion", lifetime.contains("startRequested=true"))
                }
                val bytes = ByteArray(ProxyCredentialLeaseWire.SIZE)
                val credentials = if (survivingController != null) {
                    val delivered = CountDownLatch(1)
                    val secret = java.util.concurrent.atomic.AtomicReference<ByteArray?>()
                    checkNotNull(survivingController).readProxyCredentials { value ->
                        secret.set(value?.copyOf()); delivered.countDown()
                    }
                    check(delivered.await(5, TimeUnit.SECONDS))
                    checkNotNull(secret.get())
                } else try {
                    val descriptor = control.requestProxyCredentials(version, ++sequence, observer)
                    checkNotNull(descriptor) { RuntimeStatusWire.decode(control.queryStatus(version)).let {
                        "Credential state=${it.state}/${it.failure}/${it.packetDisposition}" } }
                    ParcelFileDescriptor.AutoCloseInputStream(descriptor).use {
                        DataInputStream(it).readFully(bytes); assertEquals(-1, it.read())
                    }
                    ProxyCredentialLeaseWire.decode(bytes, SystemClock.elapsedRealtime())
                } finally { bytes.fill(0) }
                try {
                    if (rejectClient) {
                        for (address in listOf(byteArrayOf(127, 0, 0, 1), ByteArray(16).also { it[15] = 1 })) {
                            java.net.ServerSocket().use { competing ->
                                competing.reuseAddress = true
                                assertThrows(java.io.IOException::class.java) {
                                    competing.bind(java.net.InetSocketAddress(InetAddress.getByAddress(address), 10809))
                                }
                            }
                        }
                        // Server-initiated close leaves TCP TIME_WAIT on its own port.
                        // It must not prevent the next authorized session from binding.
                        Socket(InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 }), 10809).use { rejected ->
                            rejected.soTimeout = 5000
                            rejected.getOutputStream().write("CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nProxy-Authorization: Basic eDp4\r\n\r\n".toByteArray())
                            assertEquals(-1, rejected.getInputStream().read())
                        }
                    }
                    Socket(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 10808).use { client ->
                        client.soTimeout = 5000
                        val auth = byteArrayOf(5, 1, 2, 1, 16) + credentials.copyOfRange(0, 16) + byteArrayOf(43) + credentials.copyOfRange(17, 60)
                        try { client.getOutputStream().write(auth) } finally { auth.fill(0) }
                        client.getOutputStream().write(byteArrayOf(5, 1, 0, 1, 8, 8, 8, 8, 1, -69))
                        val reply = ByteArray(14); DataInputStream(client.getInputStream()).readFully(reply)
                        assertArrayEquals(byteArrayOf(5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0), reply)
                        echo(client)
                    }
                    Socket(InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 }), 10809).use { client ->
                        client.soTimeout = 5000
                        val basic = Base64.getEncoder().encode(credentials)
                        try {
                            client.getOutputStream().write("CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nProxy-Authorization: Basic ".toByteArray())
                            client.getOutputStream().write(basic); client.getOutputStream().write("\r\n\r\n".toByteArray())
                        } finally { basic.fill(0) }
                        val expected = "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray()
                        val reply = ByteArray(expected.size); DataInputStream(client.getInputStream()).readFully(reply)
                        assertArrayEquals(expected, reply); echo(client)
                    }
                } catch (failure: java.io.IOException) {
                    val observed = RuntimeStatusWire.decode(control.queryStatus(version))
                    throw AssertionError("Proxy traffic state=${observed.state}/${observed.failure}; relay=${relay.snapshot().joinToString()}", failure)
                } finally { credentials.fill(0) }
                val retained = survivingController
                if (retained == null) assertTrue(control.requestAction(version, ++sequence, RuntimeAction.RECOVER_INTERNET.wireCode, observer))
                else InstrumentationRegistry.getInstrumentation().runOnMainSync { retained.stop() }
                fun stoppedSnapshot() = retained?.snapshot?.value ?: RuntimeStatusWire.decode(control.queryStatus(version))
                val stopDeadline = SystemClock.elapsedRealtime() + 10000
                while (stoppedSnapshot().state != VpnRuntimeState.IDLE && SystemClock.elapsedRealtime() < stopDeadline)
                    SystemClock.sleep(25)
                val stopped = stoppedSnapshot()
                assertEquals("Proxy stop: ${stopped.state}/${stopped.failure}/${stopped.packetDisposition}", VpnRuntimeState.IDLE, stopped.state)
                survivingController?.let { retained ->
                    val closedBy = SystemClock.elapsedRealtime() + 5000
                    while (!retained.isClosed && SystemClock.elapsedRealtime() < closedBy) SystemClock.sleep(25)
                    assertTrue("Terminal session must release the detached controller", retained.isClosed)
                }
                if (retained == null) assertNull(control.requestProxyCredentials(version, ++sequence, observer))
                assertThrows(java.io.IOException::class.java) { Socket(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 10808).close() }
            } finally { if (survivingController == null) control.unregisterObserver(version, observer) }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            activity?.close()
            survivingController?.close()
            try {
            if (systemAlwaysOn) setSystemAlwaysOn(context, null)
            if (survivingController?.snapshot?.value?.state == VpnRuntimeState.IDLE) {
                assertTrue(checkNotNull(survivingController).isClosed)
            } else if (binder.get()?.isBinderAlive == true) {
                val control = IRuntimeControl.Stub.asInterface(binder.get())
                var stopped = RuntimeStatusWire.decode(control.queryStatus(RuntimeStatusWire.VERSION)).state
                if (stopped != VpnRuntimeState.IDLE) KurdVpnService.stop(context)
                val until = SystemClock.elapsedRealtime() + 10000
                while (stopped != VpnRuntimeState.IDLE && SystemClock.elapsedRealtime() < until) {
                    SystemClock.sleep(25)
                    stopped = RuntimeStatusWire.decode(control.queryStatus(RuntimeStatusWire.VERSION)).state
                }
                assertEquals("Service must retire before the fixture relay", VpnRuntimeState.IDLE, stopped)
                if (pauseBeforeStart) {
                    pause(null)
                    runBlocking { Task7InstalledFixturePreparation.prepareProxyOrVerify(context.applicationContext as KurdistanApplication) }
                }
            } else KurdVpnService.stop(context)
            if (originalModeSettings != null) runBlocking {
                val projection = checkNotNull(facade.readProjection())
                val revision = (checkNotNull(facade.settingsRepository()).appliedRevision() as org.kurdistanvpn.domain.DomainResult.Success).value.revision
                assertTrue(facade.applyProductionSettings(projection.revision, revision, originalModeSettings) is
                    org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
                Task7InstalledFixturePreparation.prepareProxyOrVerify(context.applicationContext as KurdistanApplication)
            }
            } catch (cleanup: Throwable) {
                if (primaryFailure != null) primaryFailure.addSuppressed(cleanup) else throw cleanup
            } finally {
            if (bound) context.unbindService(connection)
            relay.cancel()
            val deadline = SystemClock.elapsedRealtime() + 5000
            while (relay.snapshot()[11] != 1L && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(10)
            assertEquals(1L, relay.snapshot()[11]); assertEquals(0, relay.finish())
            }
        }
    }
    private fun setSystemAlwaysOn(context: Context, packageName: String?) {
        check(Build.VERSION.SDK_INT == 36 && (Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk")))
        check(packageName == null || packageName == "org.kurdistanvpn.app.internal")
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        // Shell does not hold CONTROL_ALWAYS_ON_VPN. Use only the owned root-capable
        // API36 emulator's platform Binder command, resolving its actual transaction ID.
        val transaction = Class.forName("android.net.IVpnManager\$Stub")
            .getDeclaredField("TRANSACTION_setAlwaysOnVpnPackage").apply { isAccessible = true }.getInt(null)
        val encodedPackage = if (packageName == null) "i32 -1" else "s16 $packageName"
        val command = "su 0 service call vpn_management $transaction i32 0 $encodedPackage i32 ${if (packageName == null) 0 else 1} i32 0"
        automation.executeShellCommand(command).use { descriptor ->
            val response = ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes().toString(Charsets.US_ASCII) }
            assertTrue("System always-on command rejected", response.contains("00000000 00000001"))
        }
    }
    private fun echo(client: Socket) {
        val expected = ByteArray(16).also { it[0] = 75; it[1] = 49; it[2] = 50 }
        client.getOutputStream().write(expected)
        val actual = ByteArray(16); DataInputStream(client.getInputStream()).readFully(actual)
        assertArrayEquals(expected, actual)
    }
}
