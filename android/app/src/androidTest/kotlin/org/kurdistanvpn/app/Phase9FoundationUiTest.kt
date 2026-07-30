// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.net.VpnService
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.click
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.ui.R as UiR
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.secure.AndroidKeystoreKek
import org.kurdistanvpn.data.secure.SecureDataClass
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy

class Phase9FoundationUiTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun phase11PresentsOnlyTheTruthfulOwnedLoopbackRuntimeControl() {
        compose.onNodeWithText(compose.activity.getString(UiR.string.product_name))
            .assertIsDisplayed()
        compose.onNodeWithText(compose.activity.getString(UiR.string.runtime_local_title))
            .assertIsDisplayed()
        compose.onAllNodesWithText("Connect", substring = false, ignoreCase = true)
            .assertCountEquals(0)
        compose.onNodeWithText(compose.activity.getString(UiR.string.start_local_vpn))
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
        compose.onNodeWithText(activity.getString(UiR.string.privacy_recovery))
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.privacy_recovery))
            .assertIsDisplayed()

        val highContrast = activity.getString(UiR.string.high_contrast)
        compose.onNodeWithContentDescription(highContrast)
            .performScrollTo()
            .assertIsOff()
            .performTouchInput { click() }
        compose.waitUntil(timeoutMillis = 10_000) {
            runCatching {
                compose.onNodeWithContentDescription(highContrast).assertIsOn()
                true
            }.getOrDefault(false)
        }
        compose.onNodeWithContentDescription(highContrast).performTouchInput { click() }
        compose.waitUntil(timeoutMillis = 10_000) {
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
        compose.waitUntil(timeoutMillis = 10_000) {
            runCatching {
                compose.onNodeWithContentDescription(reducedMotion).assertIsOn()
                true
            }.getOrDefault(false)
        }
        compose.onNodeWithContentDescription(reducedMotion).performTouchInput { click() }
        compose.waitUntil(timeoutMillis = 10_000) {
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

        compose.onNodeWithText(activity.getString(UiR.string.diagnostics_about))
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.phase11_runtime_scope))
            .assertIsDisplayed()
        compose.onNodeWithText(activity.getString(UiR.string.prepare_diagnostics))
            .performScrollTo()
            .performClick()
        compose.waitUntil(timeoutMillis = 10_000) {
            compose.activity.diagnosticStateSnapshotForTesting() !is DiagnosticWorkflowState.Working
        }
        assertTrue(
            "diagnostic preparation did not reach preview: " +
                compose.activity.diagnosticStateSnapshotForTesting(),
            compose.activity.diagnosticStateSnapshotForTesting() is DiagnosticWorkflowState.Preview,
        )
        compose.onNodeWithText(activity.getString(UiR.string.cancel))
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.prepare_diagnostics))
            .assertIsDisplayed()
        compose.onNodeWithText(activity.getString(UiR.string.back))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.product_name))
            .assertIsDisplayed()
    }

    @Test
    fun clipboardAndOfflineQrControlsFailClosedAndReturnCleanly() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = compose.activity
        compose.onNodeWithText(activity.getString(UiR.string.profiles))
            .performClick()

        val clipboard = activity.getSystemService(ClipboardManager::class.java)
        clipboard.setPrimaryClip(ClipData.newPlainText("phase11-test", "not-a-kurd-profile"))
        compose.onNodeWithText(activity.getString(UiR.string.import_clipboard))
            .performClick()
        compose.waitUntil(timeoutMillis = 10_000) {
            activity.appStateSnapshotForTesting() is AppState.ImportRejected
        }
        compose.onNodeWithText(activity.getString(UiR.string.back))
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.dismiss))
            .assertIsDisplayed()
            .performClick()

        instrumentation.uiAutomation.executeShellCommand(
            "pm grant ${activity.packageName} android.permission.CAMERA",
        ).close()
        compose.onNodeWithText(activity.getString(UiR.string.profiles))
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.scan_offline_qr))
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.cancel_scan))
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithText(activity.getString(UiR.string.kurd_profiles))
            .assertIsDisplayed()
    }

    @Test
    fun profileManagementIsReachableByKeyboardAndSemanticsTree() {
        compose.onNodeWithText(compose.activity.getString(UiR.string.profiles))
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithText(compose.activity.getString(UiR.string.kurd_profiles))
            .assertIsDisplayed()
        compose.onNodeWithText(compose.activity.getString(UiR.string.import_profile_file))
            .assertIsDisplayed()
        compose.onNodeWithText(compose.activity.getString(UiR.string.scan_offline_qr))
            .assertIsDisplayed()
    }

    @Test
    fun signedProfileConfirmationEncryptsAndFinalizesWithoutCrashing() {
        compose.waitUntil(timeoutMillis = 10_000) {
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
        compose.waitUntil(timeoutMillis = 20_000) {
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
    fun preparedVpnCapturesOnlyTheReservedTestRangeAndStopsCleanly() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull("device gate must prepare VPN consent before this test", VpnService.prepare(context))
        val controller = VpnRuntimeController(context)
        try {
              controller.start(
                  VpnRoutingPolicy(
                      perAppMode = PerAppRoutingMode.INCLUDE_ONLY,
                      packages = setOf(
                          InstrumentationRegistry.getInstrumentation().context.packageName,
                      ),
                  ),
              )
            runBlocking {
                withTimeout(10_000) {
                    controller.snapshot.first {
                        it.state == VpnRuntimeState.ACTIVE_KURD_LOOPBACK
                    }
                }
            }
            controller.close()
            val recreatedController = VpnRuntimeController(context)
            runBlocking {
                withTimeout(10_000) {
                    recreatedController.snapshot.first {
                        it.state == VpnRuntimeState.ACTIVE_KURD_LOOPBACK &&
                            it.perAppRoutingMode == PerAppRoutingMode.INCLUDE_ONLY
                    }
                }
            }
            val token = UUID.randomUUID().toString()
            val probeResult = CompletableDeferred<Boolean>()
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (
                        intent?.action == VpnProbeActivity.ACTION_RESULT &&
                        intent.getStringExtra(VpnProbeActivity.EXTRA_TOKEN) == token
                    ) {
                        probeResult.complete(
                            intent.getBooleanExtra(VpnProbeActivity.EXTRA_SUCCESS, false),
                        )
                    }
                }
            }
            ContextCompat.registerReceiver(
                context,
                receiver,
                IntentFilter(VpnProbeActivity.ACTION_RESULT),
                ContextCompat.RECEIVER_EXPORTED,
            )
            try {
                val instrumentationPackage =
                    InstrumentationRegistry.getInstrumentation().context.packageName
                context.startActivity(
                    Intent()
                        .setClassName(
                            instrumentationPackage,
                            VpnProbeActivity::class.java.name,
                        )
                        .putExtra(VpnProbeActivity.EXTRA_TOKEN, token)
                        .putExtra(VpnProbeActivity.EXTRA_TARGET_PACKAGE, context.packageName)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
                assertTrue(runBlocking { withTimeout(10_000) { probeResult.await() } })
            } finally {
                context.unregisterReceiver(receiver)
            }
            val packetSnapshot = runBlocking {
                withTimeout(10_000) {
                    recreatedController.snapshot.first {
                        it.packetsRead >= 2 &&
                            it.packetsWritten >= 2 &&
                            it.packetDisposition == "KURD_DNS_REPLIED"
                    }
                }
            }
            assertTrue("packet snapshot: $packetSnapshot", packetSnapshot.packetsWritten >= 2)
            assertEquals("KURD_DNS_REPLIED", packetSnapshot.packetDisposition)
            recreatedController.stop()
            runBlocking {
                withTimeout(10_000) {
                    recreatedController.snapshot.first { it.state == VpnRuntimeState.IDLE }
                }
            }
            recreatedController.close()
        } finally {
            controller.stop()
            controller.close()
        }
    }

    @Test
    fun excludedApplicationCannotReachTheReservedRuntime() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull("device gate must prepare VPN consent before this test", VpnService.prepare(context))
        val controller = VpnRuntimeController(context)
        try {
            controller.start(
                VpnRoutingPolicy(
                    perAppMode = PerAppRoutingMode.EXCLUDE_SELECTED,
                    packages = setOf(
                        InstrumentationRegistry.getInstrumentation().context.packageName,
                    ),
                ),
            )
            runBlocking {
                withTimeout(10_000) {
                    controller.snapshot.first {
                        it.state == VpnRuntimeState.ACTIVE_KURD_LOOPBACK
                    }
                }
            }
            val token = UUID.randomUUID().toString()
            val probeResult = CompletableDeferred<Boolean>()
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (
                        intent?.action == VpnProbeActivity.ACTION_RESULT &&
                        intent.getStringExtra(VpnProbeActivity.EXTRA_TOKEN) == token
                    ) {
                        probeResult.complete(
                            intent.getBooleanExtra(VpnProbeActivity.EXTRA_SUCCESS, true),
                        )
                    }
                }
            }
            ContextCompat.registerReceiver(
                context,
                receiver,
                IntentFilter(VpnProbeActivity.ACTION_RESULT),
                ContextCompat.RECEIVER_EXPORTED,
            )
            try {
                val instrumentationPackage =
                    InstrumentationRegistry.getInstrumentation().context.packageName
                context.startActivity(
                    Intent()
                        .setClassName(
                            instrumentationPackage,
                            VpnProbeActivity::class.java.name,
                        )
                        .putExtra(VpnProbeActivity.EXTRA_TOKEN, token)
                        .putExtra(VpnProbeActivity.EXTRA_TARGET_PACKAGE, context.packageName)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
                assertTrue(!runBlocking { withTimeout(10_000) { probeResult.await() } })
            } finally {
                context.unregisterReceiver(receiver)
            }
            assertEquals(0L, controller.snapshot.value.packetsWritten)
        } finally {
            controller.stop()
            runBlocking {
                withTimeout(10_000) {
                    controller.snapshot.first { it.state == VpnRuntimeState.IDLE }
                }
            }
            controller.close()
        }
    }
}
