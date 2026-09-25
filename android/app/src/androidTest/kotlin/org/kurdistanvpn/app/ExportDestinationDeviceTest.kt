// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.view.accessibility.AccessibilityNodeInfo
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.kurdistanvpn.core.model.DiagnosticWorkflowState

@RunWith(AndroidJUnit4::class)
class ExportDestinationDeviceTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @org.junit.Before fun prepareImportedProfile() = compose.prepareImportedProduct(compose.activity)

    private fun openExport() {
        compose.continueFromWelcome(compose.activity)
        compose.onNodeWithTag("home_details").performScrollTo().performClick()
        compose.onNodeWithTag("home_diagnostics").performScrollTo().performClick()
        compose.onNodeWithTag("diagnostic_prepare").performScrollTo().performClick()
        compose.waitUntil(10_000) { compose.activity.diagnosticStateSnapshotForTesting() is DiagnosticWorkflowState.Preview }
        compose.onNodeWithTag("diagnostic_confirm").performScrollTo().performClick()
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        compose.waitUntil(10_000) {
            automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true
        }
    }

    @Test fun cancelledSystemExportReturnsToIdleWithoutWriting() {
        openExport()
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        // Use Android's accessibility Back action, including predictive-back dispatch.
        assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
        automation.waitForIdle(100, 2_000)
        if (automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true) {
            assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
        }
        try {
            compose.waitUntil(10_000) { compose.activity.diagnosticStateSnapshotForTesting() == DiagnosticWorkflowState.Idle }
        } catch (failure: AssertionError) {
            throw AssertionError("cancel state=${compose.activity.diagnosticStateSnapshotForTesting()} foreground=${automation.rootInActiveWindow?.packageName}", failure)
        }
    }

    @Test fun recreatedActivityReceivesExistingPickerAndCompletesExport() {
        openExport()
        val old = compose.activity
        InstrumentationRegistry.getInstrumentation().runOnMainSync { old.recreate() }
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val deadline = android.os.SystemClock.elapsedRealtime() + 10_000
        var save: AccessibilityNodeInfo? = null
        while (save == null && android.os.SystemClock.elapsedRealtime() < deadline) {
            save = automation.rootInActiveWindow?.findAccessibilityNodeInfosByText("SAVE")
                ?.firstOrNull { it.isClickable && it.isEnabled }
            if (save == null) android.os.SystemClock.sleep(50)
        }
        assertNotNull("System destination picker must remain open across recreation", save)
        assertTrue(save!!.performAction(AccessibilityNodeInfo.ACTION_CLICK))
        compose.waitUntil(10_000) { compose.activity !== old &&
            compose.activity.diagnosticStateSnapshotForTesting() == DiagnosticWorkflowState.Completed }
    }

    @Test fun backupPickerRecreationWipesSecretAndCancellationCannotRestore() {
        val old = compose.activity
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        lateinit var password: ByteArray
        instrumentation.runOnMainSync {
            MainActivity::class.java.getDeclaredMethod("launchBackupPicker", String::class.java).apply {
                isAccessible = true
            }.invoke(old, "synthetic-picker-only-password")
            password = MainActivity::class.java.getDeclaredField("backupPassword").apply {
                isAccessible = true
            }.get(old) as ByteArray
        }
        val automation = instrumentation.uiAutomation
        compose.waitUntil(10_000) {
            automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true
        }
        instrumentation.runOnMainSync { old.recreate() }
        // API26 may defer recreation while DocumentsUI keeps this activity stopped.
        // Return from the picker before requiring destruction and secret erasure.
        assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
        automation.waitForIdle(100, 2_000)
        if (automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true) {
            assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
        }
        compose.waitUntil(10_000) { compose.activity !== old && password.all { it == 0.toByte() } }
        compose.waitUntil(10_000) {
            compose.activity.backupStateSnapshotForTesting() ==
                org.kurdistanvpn.core.model.BackupWorkflowState.Failed(org.kurdistanvpn.core.model.OperationError.CANCELLED) }
    }
}
