// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import android.view.accessibility.AccessibilityNodeInfo
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.feature.settingsrecovery.PrivacyRecoveryViewModel

@RunWith(AndroidJUnit4::class)
class PrivacyBackupDeviceTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @org.junit.Before fun prepareImportedProfile() = compose.prepareImportedProduct(compose.activity)

    private fun export(save: Boolean) = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val root = (instrumentation.targetContext.applicationContext as KurdistanApplication).compositionRoot
        val before = checkNotNull(root.protectedStateFacade()?.readProjection())
        lateinit var vm: PrivacyRecoveryViewModel
        instrumentation.runOnMainSync {
            vm = MainActivity::class.java.getDeclaredMethod("getPrivacyViewModel").apply { isAccessible = true }
                .invoke(compose.activity) as PrivacyRecoveryViewModel
        }
        val password = "task13-owned-export-verification".encodeToByteArray()
        root.backupOperations.stageExportPassword(emptySet(), password)
        vm.previewBackup(emptySet()).join()
        assertTrue("A real native backup preview is required", vm.state.value is OperationState.AwaitingConfirmation)
        vm.confirmBackup().join()
        assertTrue(password.all { it == 0.toByte() })
        val automation = instrumentation.uiAutomation
        compose.waitUntil(10_000) { automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true }
        assertEquals(BackupWorkflowState.Working, compose.activity.backupStateSnapshotForTesting())
        assertTrue(root.privacyRepository.observeOperation().value is OperationState.Applying)
        val old = compose.activity
        instrumentation.runOnMainSync { old.recreate() }
        if (save) {
            var button: AccessibilityNodeInfo? = null
            compose.waitUntil(10_000) {
                button = automation.rootInActiveWindow?.findAccessibilityNodeInfosByText("SAVE")?.firstOrNull { it.isClickable && it.isEnabled }
                button != null
            }
            assertTrue(checkNotNull(button).performAction(AccessibilityNodeInfo.ACTION_CLICK))
            compose.waitUntil(10_000) { compose.activity !== old && compose.activity.backupStateSnapshotForTesting() == BackupWorkflowState.Exported }
        } else {
            assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
            automation.waitForIdle(100, 2_000)
            if (automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true)
                assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
            try {
                compose.waitUntil(10_000) { compose.activity !== old && compose.activity.backupStateSnapshotForTesting() == BackupWorkflowState.Idle }
            } catch (error: androidx.compose.ui.test.ComposeTimeoutException) {
                val current = compose.activity
                val actual = current.backupStateSnapshotForTesting().javaClass.simpleName.uppercase(java.util.Locale.ROOT)
                val recreated = if (current !== old) "RECREATED" else "ORIGINAL_ACTIVITY"
                val foreground = when (automation.rootInActiveWindow?.packageName?.toString()) {
                    "com.android.documentsui", "com.google.android.documentsui" -> "PICKER"
                    instrumentation.targetContext.packageName -> "APPLICATION"
                    else -> "OTHER_WINDOW"
                }
                throw AssertionError("KURDISTAN_TEST_SETUP expected=IDLE actual=$actual setup=EXPORT_CANCEL,$recreated,$foreground", error)
            }
        }
        val after = checkNotNull(root.protectedStateFacade()?.readProjection())
        assertEquals(before.revision, after.revision)
        assertEquals(before.settings, after.settings)
        assertEquals(before.profiles, after.profiles)
    }

    @Test fun realEncryptedExportCancellationAfterRecreationDoesNotMutateStorage() = export(false)
    @Test fun realEncryptedExportOnlyCompletesAfterDestinationWrite() = export(true)
}
