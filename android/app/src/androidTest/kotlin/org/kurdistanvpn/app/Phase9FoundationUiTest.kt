// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.Manifest
import android.app.ActivityManager
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.net.Uri
import android.net.VpnService
import android.os.Build
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.click
import androidx.core.content.ContextCompat
import androidx.test.espresso.IdlingPolicies
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.BackupWorkflowState
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProtectedRecoveryAction
import org.kurdistanvpn.core.model.ProtectedRecoveryPresentation
import org.kurdistanvpn.core.model.ProtectedRecoveryReason
import org.kurdistanvpn.core.ui.R as UiR
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.secure.AndroidKeystoreKek
import org.kurdistanvpn.data.secure.SecureDataClass
import org.kurdistanvpn.feature.settingsrecovery.SettingsRecoveryScreen
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.android.RuntimeActivationGuard
import org.kurdistanvpn.runtime.android.RuntimeAuthorityReissueClient
import org.kurdistanvpn.runtime.android.RuntimeCleanupState
import org.kurdistanvpn.runtime.android.RuntimeResourceKind
import org.kurdistanvpn.runtime.android.RuntimeServiceCommand
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.VpnRuntimeContract
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig

class Phase9FoundationUiTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Before
    fun configureHostedEmulatorIdlingBudget() {
        IdlingPolicies.setMasterPolicyTimeout(2, TimeUnit.MINUTES)
        IdlingPolicies.setIdlingResourceTimeout(2, TimeUnit.MINUTES)
    }

    @Test
    fun protectedRecoveryUiRequiresCurrentConfirmationAndRejectsUnsupportedRepairActions() {
        val recovery = androidx.compose.runtime.mutableStateOf<ProtectedRecoveryPresentation>(
            ProtectedRecoveryPresentation.Required(
                ProtectedRecoveryReason.RECOVERY_REQUIRED,
                ProtectedRecoveryAction.RECOVER_PRESENTATION,
            ),
        )
        var recovered = 0
        var diagnostics = 0
        val activity = compose.activity
        compose.setContent {
            SettingsRecoveryScreen(
                backupState = BackupWorkflowState.Idle,
                settings = Phase9Settings(),
                onTheme = {},
                onHighContrast = {},
                onReducedMotion = {},
                onCreateBackup = {},
                onOpenBackup = {},
                onConfirmRestore = {},
                onCancelRestore = {},
                onResetAll = {},
                onBack = {},
                protectedRecovery = recovery.value,
                recoveryTitle = activity.getString(R.string.protected_recovery_title),
                recoveryMessage = activity.getString(R.string.protected_recovery_required),
                recoveryPrepareLabel = activity.getString(R.string.prepare_presentation_recovery),
                recoveryConfirmLabel = activity.getString(R.string.confirm_presentation_recovery),
                recoveryDiagnosticsLabel = activity.getString(R.string.open_privacy_safe_diagnostics),
                onConfirmPresentationRecovery = { recovered++ },
                onOpenDiagnostics = { diagnostics++ },
            )
        }
        compose.onNodeWithTag("protected_recovery_status").assertIsDisplayed()
        compose.onNodeWithContentDescription(
            activity.getString(R.string.protected_recovery_title) + ". " +
                activity.getString(R.string.protected_recovery_required),
        ).assertIsDisplayed()
        compose.onNodeWithTag("prepare_presentation_recovery").performScrollTo().performClick()
        compose.onNodeWithTag("cancel_presentation_recovery").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(0, recovered) }
        compose.onNodeWithTag("prepare_presentation_recovery").performScrollTo().performClick()
        compose.onNodeWithTag("confirm_presentation_recovery").performScrollTo().performClick()
        compose.onNodeWithTag("open_recovery_diagnostics").performScrollTo().performClick()
        compose.runOnIdle {
            assertEquals(1, recovered)
            assertEquals(1, diagnostics)
            recovery.value = ProtectedRecoveryPresentation.Required(ProtectedRecoveryReason.QUARANTINED)
        }
        compose.onAllNodesWithTag("prepare_presentation_recovery").assertCountEquals(0)
        compose.onNodeWithTag("open_recovery_diagnostics").assertIsDisplayed()
        compose.runOnIdle {
            recovery.value = ProtectedRecoveryPresentation.Required(
                ProtectedRecoveryReason.MUTATION_UNPROVEN,
            )
        }
        compose.onAllNodesWithTag("prepare_presentation_recovery").assertCountEquals(0)
        compose.onNodeWithTag("open_recovery_diagnostics").assertIsDisplayed()
        compose.runOnIdle {
            recovery.value = ProtectedRecoveryPresentation.Required(
                ProtectedRecoveryReason.RECOVERY_REQUIRED,
                ProtectedRecoveryAction.RECOVER_PRESENTATION,
            )
        }
        compose.onAllNodesWithTag("confirm_presentation_recovery").assertCountEquals(0)
        compose.onNodeWithTag("prepare_presentation_recovery").assertIsDisplayed()
        compose.runOnIdle { recovery.value = ProtectedRecoveryPresentation.NotRequired }
        compose.onAllNodesWithTag("protected_recovery_status").assertCountEquals(0)
    }

    @Test
    fun phase11PresentsOnlyTheTruthfulOwnedLoopbackRuntimeControl() {
        compose.onNodeWithText(compose.activity.getString(UiR.string.product_name))
            .assertIsDisplayed()
        compose.onNodeWithText(compose.activity.getString(UiR.string.disconnected))
            .performScrollTo()
            .assertIsDisplayed()
        compose.onNodeWithText(compose.activity.getString(UiR.string.phase13_external_boundary))
            .performScrollTo()
            .assertIsDisplayed()
        compose.onNodeWithTag("connect_button")
            .performScrollTo()
            .assertIsDisplayed()
    }

    @Test
    fun packagedPhase11NativeRoundTripIsExactAndBounded() {
        val payload = "phase11-packaged-abi".encodeToByteArray()
        val result = NativeBridge().phase11RoundTrip(payload)
        assertTrue("packaged Phase 11 bridge rejected a bounded payload: $result", result is NativeResult.Success)
        assertArrayEquals(payload, (result as NativeResult.Success).value)
        assertTrue(
            "empty payload must fail closed",
            NativeBridge().phase11RoundTrip(byteArrayOf()) is NativeResult.Failure,
        )
    }

    @Test
    fun primaryNavigationSettingsAndDiagnosticControlsAreOperational() {
        val activity = compose.activity
        compose.onNodeWithTag("primary_settings")
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithTag("settings_privacy")
            .performScrollTo()
            .performClick()
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            runCatching {
                compose.onNodeWithText(activity.getString(UiR.string.privacy_recovery))
                    .assertIsDisplayed()
                true
            }.getOrDefault(false)
        }
        compose.onNodeWithText(activity.getString(UiR.string.privacy_recovery))
            .assertIsDisplayed()

        val highContrast = activity.getString(UiR.string.high_contrast)
        compose.onNodeWithContentDescription(highContrast)
            .performScrollTo()
            .assertIsOff()
            .performTouchInput { click() }
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            runCatching {
                compose.onNodeWithContentDescription(highContrast).assertIsOn()
                true
            }.getOrDefault(false)
        }
        compose.onNodeWithContentDescription(highContrast).performTouchInput { click() }
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            runCatching {
                compose.onNodeWithContentDescription(highContrast).assertIsOff()
                true
            }.getOrDefault(false)
        }
        val reducedMotion = activity.getString(UiR.string.reduced_motion)
        compose.onNodeWithContentDescription(reducedMotion)
            .performScrollTo()
            .assertIsOff()
            .performTouchInput { click() }
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            runCatching {
                compose.onNodeWithContentDescription(reducedMotion).assertIsOn()
                true
            }.getOrDefault(false)
        }
        compose.onNodeWithContentDescription(reducedMotion).performTouchInput { click() }
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            runCatching {
                compose.onNodeWithContentDescription(reducedMotion).assertIsOff()
                true
            }.getOrDefault(false)
        }

        compose.onNodeWithText(activity.getString(UiR.string.prepare_reset))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.cancel_reset))
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.prepare_reset))
            .assertIsDisplayed()
        compose.onNodeWithText(activity.getString(UiR.string.back))
            .performScrollTo()
            .performClick()

        compose.onNodeWithTag("settings_diagnostics")
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.phase11_runtime_scope))
            .assertIsDisplayed()
        compose.onNodeWithText(activity.getString(UiR.string.prepare_diagnostics))
            .performScrollTo()
            .performClick()
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            compose.activity.diagnosticStateSnapshotForTesting() !is DiagnosticWorkflowState.Working
        }
        assertTrue(
            "diagnostic preparation did not reach preview: " +
                compose.activity.diagnosticStateSnapshotForTesting(),
            compose.activity.diagnosticStateSnapshotForTesting() is DiagnosticWorkflowState.Preview,
        )
        compose.onNodeWithText(activity.getString(UiR.string.cancel))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.prepare_diagnostics))
            .performScrollTo()
            .assertIsDisplayed()
        compose.onNodeWithText(activity.getString(UiR.string.back))
            .performScrollTo()
            .performClick()
        compose.onNodeWithTag("primary_home")
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.product_name))
            .assertIsDisplayed()
    }

    @Test
    fun clipboardAndOfflineQrControlsFailClosedAndReturnCleanly() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = compose.activity
        compose.onNodeWithTag("primary_profiles")
            .performClick()

        instrumentation.runOnMainSync {
            val clipboard = activity.getSystemService(ClipboardManager::class.java)
            clipboard.setPrimaryClip(ClipData.newPlainText("phase11-test", "not-a-kurd-profile"))
        }
        compose.onNodeWithText(activity.getString(UiR.string.import_clipboard))
            .performScrollTo()
            .performClick()
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            activity.appStateSnapshotForTesting() is AppState.ImportRejected
        }
        compose.onNodeWithText(activity.getString(UiR.string.back))
            .performScrollTo()
            .performClick()
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            runCatching {
                compose.onNodeWithText(activity.getString(UiR.string.dismiss))
                    .performScrollTo()
                    .assertIsDisplayed()
                true
            }.getOrDefault(false)
        }
        compose.onNodeWithText(activity.getString(UiR.string.dismiss))
            .performScrollTo()
            .assertIsDisplayed()
            .performClick()

        compose.onNodeWithTag("primary_profiles")
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.profile_link_label))
            .performScrollTo()
            .performTextInput("not-a-kurd-profile-link")
        compose.onNodeWithText(activity.getString(UiR.string.preview_link))
            .performScrollTo()
            .performClick()
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            activity.appStateSnapshotForTesting() is AppState.ImportRejected
        }
        compose.onNodeWithText(activity.getString(UiR.string.back))
            .performScrollTo()
            .performClick()
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            runCatching {
                compose.onNodeWithText(activity.getString(UiR.string.dismiss))
                    .performScrollTo()
                    .assertIsDisplayed()
                true
            }.getOrDefault(false)
        }
        compose.onNodeWithText(activity.getString(UiR.string.dismiss))
            .performScrollTo()
            .performClick()

        instrumentation.uiAutomation.executeShellCommand(
            "pm grant ${activity.packageName} ${Manifest.permission.CAMERA}",
        ).close()
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            ContextCompat.checkSelfPermission(activity, Manifest.permission.CAMERA) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
        }
        compose.onNodeWithTag("primary_profiles")
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.scan_offline_qr))
            .performScrollTo()
            .performClick()
        waitForText(activity.getString(UiR.string.cancel_scan))
        compose.onNodeWithText(activity.getString(UiR.string.cancel_scan))
            .assertIsDisplayed()
            .performClick()
        waitForText(activity.getString(UiR.string.kurd_profiles))
        compose.onNodeWithText(activity.getString(UiR.string.kurd_profiles))
            .assertIsDisplayed()
    }

    @Test
    fun profileManagementIsReachableByKeyboardAndSemanticsTree() {
        compose.onNodeWithTag("primary_profiles")
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithText(compose.activity.getString(UiR.string.kurd_profiles))
            .assertIsDisplayed()
        compose.onNodeWithText(compose.activity.getString(UiR.string.import_profile_file))
            .performScrollTo()
            .assertIsDisplayed()
        compose.onNodeWithText(compose.activity.getString(UiR.string.scan_offline_qr))
            .performScrollTo()
            .assertIsDisplayed()
    }

    @Test
    fun signedProfileConfirmationEncryptsAndFinalizesWithoutCrashing() {
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            when (compose.activity.appStateSnapshotForTesting()) {
                AppState.Booting,
                AppState.CompatibilityCheck,
                -> false
                else -> true
            }
        }
        assertTrue(
            "import test requires a usable initial state, got ${compose.activity.appStateSnapshotForTesting()}",
            compose.activity.appStateSnapshotForTesting() is AppState.NoProfiles ||
                compose.activity.appStateSnapshotForTesting() is AppState.Ready,
        )
        val existing = compose.activity.appStateSnapshotForTesting()
        if (existing is AppState.Ready && existing.profiles.isNotEmpty()) {
            compose.onNodeWithTag("primary_profiles").performClick()
            compose.onNodeWithText(compose.activity.getString(UiR.string.delete_profile))
                .performScrollTo()
                .performClick()
            compose.onNodeWithText(compose.activity.getString(UiR.string.confirm_delete_profile))
                .performScrollTo()
                .performClick()
            compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
                compose.activity.appStateSnapshotForTesting() is AppState.NoProfiles
            }
            compose.onNodeWithTag("primary_home").performClick()
        }
        val link =
            "kurd://artifact/0oRYfacBJgKDOgABAAA6AAEAAToAAQACA3gmYXBwbGljYXRpb24vdm5kLmt1cmRpc3Rhbi5wcm9maWxlK2Nib3IET2lzc3Vlci1rZXktMDAwMToAAQAAAToAAQABAToAAQACWBykAW1zaWduZWQtcHVibGljAmZwdWJsaWMDQAQAoFi5tAEBAmxjb250ZW50LjAwMDEDbHByb2ZpbGVzLm9uZQRsbGluZWFnZS4wMDAxBW1wcm92aWRlci4wMDAxBngccHJvZHVjdC1wcm9maWxlLWFkbWlzc2lvbi12MQdvcmV2b2NhdGlvbi4wMDAxCG1mdWxsLXNuYXBzaG90CWdpbml0aWFsCgcLAgwYZA0ZA-gOAw8EEGARYBKBanJlbGF5LjAwMDETgW1zdHJhdGVneS4wMDAxFEOhAQFYQIyvXzY5H1CgLKQm26giaBLLV6CAbkQKzkQ1HSviotuUH7d0vG2K_bpRTUPIOG4rLTwtcIO3NyXHKdmzRzbQs9g"
          val intent = Intent(Intent.ACTION_VIEW, Uri.parse(link))
              .addCategory(Intent.CATEGORY_BROWSABLE)
          compose.activity.runOnUiThread {
              MainActivity::class.java
                  .getDeclaredMethod("handleExternalIntent", Intent::class.java)
                  .apply { isAccessible = true }
                  .invoke(compose.activity, intent)
          }

        compose.onNodeWithText(compose.activity.getString(UiR.string.confirm_encrypted_storage))
            .assertIsDisplayed()
            .performClick()
        compose.waitUntil(timeoutMillis = runtimeTimeout(20_000)) {
            when (compose.activity.appStateSnapshotForTesting()) {
                is AppState.ImportPreview,
                is AppState.Importing,
                -> false
                else -> true
            }
        }
        val ready = compose.activity.appStateSnapshotForTesting()
        assertTrue("signed profile confirmation must finalize, got $ready", ready is AppState.Ready)
        assertTrue(
            "signed profile confirmation must publish the stored profile",
            (ready as AppState.Ready).profiles.isNotEmpty(),
        )
    }

    @Test
    fun androidKeystoreWrapsAndUnwrapsADataEncryptionKey() {
        val alias = "phase9-instrumentation-${System.nanoTime()}"
        val plaintext = ByteArray(32) { it.toByte() }
        try {
            val kek = AndroidKeystoreKek.createForFirstUse(
                alias = alias,
                generation = 1,
                preferStrongBox = false,
            )
            val wrapped = kek.wrap(
                recordId = "018f0f47-aaaa-bbbb-cccc-001122334455",
                dataClass = SecureDataClass.IMPORT_REQUEST,
                key = plaintext,
            )
            assertArrayEquals(
                plaintext,
                kek.unwrap(
                    recordId = "018f0f47-aaaa-bbbb-cccc-001122334455",
                    dataClass = SecureDataClass.IMPORT_REQUEST,
                    wrapped = wrapped,
                ),
            )
        } finally {
            plaintext.fill(0)
            AndroidKeystoreKek.deleteForExplicitReset(alias)
        }
    }

    @Test
    fun signedPublicProfileCannotAuthorizeCurrentLiveRuntime() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull("device gate must prepare VPN consent before this test", VpnService.prepare(context))
        val controller = VpnRuntimeController(context)
        try {
            val failure = prepareLegacyAuthorityExpectingRejection(
                VpnRoutingPolicy(
                    perAppMode = PerAppRoutingMode.INCLUDE_ONLY,
                    packages = setOf(InstrumentationRegistry.getInstrumentation().context.packageName),
                ),
            )
            assertEquals("POLICY_REJECTED", failure)
            assertEquals(VpnRuntimeState.IDLE, controller.snapshot.value.state)
            assertEquals(0L, controller.snapshot.value.packetsRead)
            assertEquals(0L, controller.snapshot.value.packetsWritten)
            assertNull(controller.snapshot.value.planDigest)
        } finally {
            controller.stop()
            controller.close()
        }
    }

    @Test
    fun perAppPolicyCannotWidenSignedPublicProfileIntoLiveAuthority() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull("device gate must prepare VPN consent before this test", VpnService.prepare(context))
        val controller = VpnRuntimeController(context)
        try {
            val policy = VpnRoutingPolicy(
                perAppMode = PerAppRoutingMode.EXCLUDE_SELECTED,
                packages = setOf(InstrumentationRegistry.getInstrumentation().context.packageName),
            ).validate()
            val failure = prepareLegacyAuthorityExpectingRejection(policy)
            assertEquals("POLICY_REJECTED", failure)
            assertEquals(VpnRuntimeState.IDLE, controller.snapshot.value.state)
            assertEquals(0L, controller.snapshot.value.packetsRead)
            assertEquals(0L, controller.snapshot.value.packetsWritten)
            assertNull(controller.snapshot.value.planDigest)
        } finally {
            controller.stop()
            controller.close()
        }
    }

    @Test
    fun missingAuthorityTimesOutFailClosed() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        var unbound = 0
        val unavailableContext = object : ContextWrapper(context) {
            override fun bindService(
                service: Intent,
                connection: ServiceConnection,
                flags: Int,
            ): Boolean = true // Model accepted binding whose provider never arrives.
            override fun unbindService(connection: ServiceConnection) { unbound++ }
        }
        val guard = RuntimeActivationGuard()
        val outcome = CompletableDeferred<Boolean>()
        val client = RuntimeAuthorityReissueClient(unavailableContext,
            ComponentName(context, RuntimeAuthorityReissueService::class.java),
            "0123456789abcdef0123456789abcdef", NativeBridge().durableFiles(), guard) {}
        check(guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, client) != null)
        try {
            assertTrue(client.bind { outcome.complete(it) })
            val bound = runBlocking {
                withTimeout(runtimeTimeout(40_000)) { outcome.await() }
            }
            assertEquals(false, bound)
            assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
            assertEquals(false, guard.isActive())
            assertEquals(1, unbound)
        } finally {
            guard.cancel()
        }
    }

    @Test
    fun malformedAuthorityRequestIsRejectedBeforeTunEstablishment() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        resetRuntimeService(context)
        val probe = DirectRuntimeStatusProbe(context, requestId = null)
        try {
            context.startForegroundService(
                Intent(context, KurdVpnService::class.java)
                    .setAction(VpnRuntimeContract.ACTION_START)
                    .putExtra(RuntimeServiceCommand.MARKER_KEY, RuntimeServiceCommand.MARKER_VERSION)
                    .putExtra(VpnRuntimeContract.EXTRA_AUTHORITY_REQUEST, "not-a-valid-request"),
            )
            val terminal = runBlocking {
                probe.await(
                    state = VpnRuntimeState.BLOCKED,
                    failure = "INVALID_REQUEST_ID",
                    timeoutMillis = runtimeTimeout(5_000),
                )
            }
            assertEquals(0L, terminal.packetsRead)
            assertEquals(0L, terminal.packetsWritten)
            assertNull(terminal.planDigest)
        } finally {
            probe.close()
            resetRuntimeService(context)
        }
    }

    @Test
    fun duplicateAuthorityRequestIsRejectedBeforeTunEstablishment() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        ensureLegacySignedProfileIsReady()
        resetRuntimeService(context)
        val requestId = "fedcba9876543210fedcba9876543210"
        val probe = DirectRuntimeStatusProbe(context, requestId = null)
        try {
            val start = Intent(context, KurdVpnService::class.java)
                .setAction(VpnRuntimeContract.ACTION_START)
                .putExtra(RuntimeServiceCommand.MARKER_KEY, RuntimeServiceCommand.MARKER_VERSION)
                .putExtra(VpnRuntimeContract.EXTRA_AUTHORITY_REQUEST, requestId)
            context.startForegroundService(start)
            runBlocking {
                probe.await(
                    state = VpnRuntimeState.BLOCKED,
                    failure = "AUTHORITY_REJECTED",
                    timeoutMillis = runtimeTimeout(40_000),
                )
            }
            context.startForegroundService(Intent(start))
            val terminal = runBlocking {
                probe.await(
                    state = VpnRuntimeState.BLOCKED,
                    failure = "AUTHORITY_REJECTED",
                    timeoutMillis = runtimeTimeout(5_000),
                )
            }
            assertEquals(0L, terminal.packetsRead)
            assertEquals(0L, terminal.packetsWritten)
            assertNull(terminal.planDigest)
        } finally {
            probe.close()
            resetRuntimeService(context)
        }
    }

    private fun ensureLegacySignedProfileIsReady() {
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            compose.activity.appStateSnapshotForTesting() !is AppState.Booting &&
                compose.activity.appStateSnapshotForTesting() !is AppState.CompatibilityCheck
        }
        val current = compose.activity.appStateSnapshotForTesting()
        if (current !is AppState.Ready || current.profiles.isEmpty()) {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(INTERNAL_SIGNED_PROFILE_LINK))
                .addCategory(Intent.CATEGORY_BROWSABLE)
            compose.activity.runOnUiThread {
                MainActivity::class.java
                    .getDeclaredMethod("handleExternalIntent", Intent::class.java)
                    .apply { isAccessible = true }
                    .invoke(compose.activity, intent)
            }
            compose.onNodeWithText(compose.activity.getString(UiR.string.confirm_encrypted_storage))
                .assertIsDisplayed()
                .performClick()
            compose.waitUntil(timeoutMillis = runtimeTimeout(20_000)) {
                val state = compose.activity.appStateSnapshotForTesting()
                state is AppState.Ready && state.profiles.isNotEmpty()
            }
        }
    }

    private fun prepareLegacyAuthorityExpectingRejection(routingPolicy: VpnRoutingPolicy): String {
        ensureLegacySignedProfileIsReady()
        val outcome = CompletableDeferred<String>()
        compose.activity.runOnUiThread {
            compose.activity.prepareManualStartForTesting(
                config = VpnRuntimeConfig(routingPolicy = routingPolicy),
                onReady = {
                    outcome.complete("UNEXPECTED_AUTHORITY")
                },
                onFailure = { error -> outcome.complete(error.name) },
            )
        }
        return runBlocking { withTimeout(runtimeTimeout(20_000)) { outcome.await() } }
    }

    private fun waitForText(text: String) {
        compose.waitUntil(timeoutMillis = runtimeTimeout(10_000)) {
            compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun resetRuntime(controller: VpnRuntimeController) {
        controller.stop()
        runBlocking {
            withTimeout(runtimeTimeout(5_000)) {
                controller.snapshot.first { it.state == VpnRuntimeState.IDLE }
            }
        }
        resetRuntimeService(InstrumentationRegistry.getInstrumentation().targetContext)
    }

    private fun resetRuntimeService(context: Context) {
        context.stopService(Intent(context, KurdVpnService::class.java))
        runBlocking {
            withTimeout(runtimeTimeout(10_000)) {
                while (isKurdVpnServiceRunning(context)) {
                    delay(25)
                }
            }
        }
    }

    private fun runtimeTimeout(baseMillis: Long): Long {
        val emulator = Build.FINGERPRINT.contains("generic", ignoreCase = true) ||
            Build.MODEL.contains("emulator", ignoreCase = true) ||
            Build.PRODUCT.contains("sdk", ignoreCase = true)
        return when {
            emulator -> maxOf(baseMillis, 60_000L)
            Build.VERSION.SDK_INT <= 28 -> maxOf(baseMillis, 30_000L)
            else -> baseMillis
        }
    }
}

private class DirectRuntimeStatusProbe(
    private val context: Context,
    private val requestId: String?,
) : AutoCloseable {
    private val snapshots = Channel<VpnRuntimeSnapshot>(Channel.UNLIMITED)
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != VpnRuntimeContract.ACTION_STATUS) return
            val incomingRequestId = intent.getStringExtra(VpnRuntimeContract.EXTRA_RUNTIME_REQUEST)
            if (requestId != null && incomingRequestId != requestId) return
            val state = intent.getStringExtra(VpnRuntimeContract.EXTRA_STATE)
                ?.let { runCatching { VpnRuntimeState.valueOf(it) }.getOrNull() }
                ?: return
            snapshots.trySend(
                VpnRuntimeSnapshot(
                    state = state,
                    packetsRead = intent.getLongExtra(VpnRuntimeContract.EXTRA_PACKETS, 0),
                    packetsWritten = intent.getLongExtra(VpnRuntimeContract.EXTRA_PACKETS_WRITTEN, 0),
                    failure = intent.getStringExtra(VpnRuntimeContract.EXTRA_FAILURE),
                    planDigest = intent.getStringExtra(VpnRuntimeContract.EXTRA_PLAN_DIGEST),
                    runtimeRequestId = incomingRequestId,
                ),
            )
        }
    }

    init {
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(VpnRuntimeContract.ACTION_STATUS),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    suspend fun await(
        state: VpnRuntimeState,
        failure: String?,
        timeoutMillis: Long,
    ): VpnRuntimeSnapshot = withTimeout(timeoutMillis) {
        while (true) {
            val snapshot = snapshots.receive()
            if (snapshot.state == state && snapshot.failure == failure) return@withTimeout snapshot
        }
        @Suppress("UNREACHABLE_CODE")
        error("unreachable")
    }

    override fun close() {
        runCatching { context.unregisterReceiver(receiver) }
        snapshots.close()
    }
}

@Suppress("DEPRECATION")
private fun isKurdVpnServiceRunning(context: Context): Boolean {
    val activityManager = context.getSystemService(ActivityManager::class.java)
    val component = ComponentName(context, KurdVpnService::class.java)
    return activityManager.getRunningServices(Int.MAX_VALUE).any { it.service == component }
}

private const val INTERNAL_SIGNED_PROFILE_LINK =
    "kurd://artifact/0oRYfacBJgKDOgABAAA6AAEAAToAAQACA3gmYXBwbGljYXRpb24vdm5kLmt1cmRpc3Rhbi5wcm9maWxlK2Nib3IET2lzc3Vlci1rZXktMDAwMToAAQAAAToAAQABAToAAQACWBykAW1zaWduZWQtcHVibGljAmZwdWJsaWMDQAQAoFi5tAEBAmxjb250ZW50LjAwMDEDbHByb2ZpbGVzLm9uZQRsbGluZWFnZS4wMDAxBW1wcm92aWRlci4wMDAxBngccHJvZHVjdC1wcm9maWxlLWFkbWlzc2lvbi12MQdvcmV2b2NhdGlvbi4wMDAxCG1mdWxsLXNuYXBzaG90CWdpbml0aWFsCgcLAgwYZA0ZA-gOAw8EEGARYBKBanJlbGF5LjAwMDETgW1zdHJhdGVneS4wMDAxFEOhAQFYQIyvXzY5H1CgLKQm26giaBLLV6CAbkQKzkQ1HSviotuUH7d0vG2K_bpRTUPIOG4rLTwtcIO3NyXHKdmzRzbQs9g"
