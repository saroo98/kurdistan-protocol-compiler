// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import android.content.Intent
import android.net.Uri
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performScrollTo
import kotlinx.coroutines.runBlocking
import org.kurdistanvpn.domain.DomainResult
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.ui.R as UiR

class ProfileImportDeviceTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @org.junit.Before fun prepareImportedProfile() = compose.prepareImportedProduct(compose.activity)

    @Test fun signedPreviewSurvivesRotationAndCancelLeavesExistingStorageUntouched() {
        val root = (compose.activity.application as KurdistanApplication).compositionRoot
        val before = checkNotNull(root.protectedStateFacade()?.readProjection())
        compose.waitUntil(15_000) { compose.activity.appStateSnapshotForTesting() is AppState.Ready }
        compose.runOnIdle {
            MainActivity::class.java.getDeclaredMethod("handleExternalIntent", Intent::class.java)
                .apply { isAccessible = true }
                .invoke(compose.activity, Intent(Intent.ACTION_VIEW, Uri.parse(INTERNAL_SIGNED_PROFILE_LINK)))
        }
        compose.waitUntil(15_000) { compose.activity.appStateSnapshotForTesting() is AppState.ImportPreview }
        compose.activityRule.scenario.recreate()
        compose.waitUntil(15_000) { compose.activity.appStateSnapshotForTesting() is AppState.ImportPreview }
        compose.onNodeWithText(compose.activity.getString(UiR.string.cancel)).performClick()
        compose.waitUntil(15_000) { compose.activity.appStateSnapshotForTesting() is AppState.Ready }
        val after = checkNotNull(root.protectedStateFacade()?.readProjection())
        assertEquals(before.revision, after.revision)
        assertEquals(before.settings, after.settings)
        assertEquals(before.profiles, after.profiles)
    }

    @Test fun favoriteUsesTheSharedSettingsOwnerAndRestoresTheOriginalValue() {
        val app = compose.activity.application as KurdistanApplication
        val root = app.compositionRoot
        val facade = checkNotNull(root.protectedStateFacade())
        val before = checkNotNull(facade.readProjection())
        val id = checkNotNull(before.settings.profiles.activeLocalRecordId)
        compose.waitUntil(15_000) { compose.activity.appStateSnapshotForTesting() is AppState.Ready }
        compose.onNodeWithTag("primary_profiles").performClick()
        try {
            compose.onNodeWithTag("profile_favorite_$id").performScrollTo().performClick()
            compose.waitUntil(15_000) {
                val current = facade.readProjection()
                current != null && (id in current.settings.profiles.favoriteLocalRecordIds) !=
                    (id in before.settings.profiles.favoriteLocalRecordIds)
            }
            assertEquals(before.profiles, facade.readProjection()?.profiles)
        } finally {
            runBlocking {
                if (facade.readProjection()?.settings != before.settings)
                    assertTrue(root.applySettingsChange { before.settings } is DomainResult.Success)
                assertEquals(before.settings, facade.readProjection()?.settings)
                Task7InstalledFixturePreparation.prepareProxyOrVerify(app)
            }
        }
    }

    @Test fun cancellingEnrollmentFileExportDoesNotMarkTheRequestExported() {
        val root = (compose.activity.application as KurdistanApplication).compositionRoot
        val facade = checkNotNull(root.protectedStateFacade())
        val before = checkNotNull(facade.readProjection())
        val keys = checkNotNull(facade.enrollmentSummaries())
        assertEquals(1, keys.size)
        compose.waitUntil(15_000) { compose.activity.appStateSnapshotForTesting() is AppState.Ready }
        compose.onNodeWithTag("primary_profiles").performClick()
        compose.onNodeWithText(compose.activity.getString(UiR.string.device_enrollment_export_file)).performScrollTo().performClick()
        compose.onNodeWithText(compose.activity.getString(UiR.string.confirm)).performScrollTo().performClick()
        val automation = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().uiAutomation
        val previousFlags = automation.serviceInfo.flags
        try {
            automation.serviceInfo = automation.serviceInfo.apply {
                flags = flags or android.accessibilityservice.AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            }
            compose.waitUntil(15_000) { automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true }
            val initialIme = automation.windows.any { it.type == android.view.accessibility.AccessibilityWindowInfo.TYPE_INPUT_METHOD }
            assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
            // Back dismisses the IME asynchronously. Do not send the picker Back to the closing IME.
            compose.waitUntil(5_000) {
                automation.windows.none { it.type == android.view.accessibility.AccessibilityWindowInfo.TYPE_INPUT_METHOD }
            }
            automation.waitForIdle(100, 2_000)
            // Accessibility can still report the old picker after our window regains focus.
            val secondBack = !compose.activity.hasWindowFocus() &&
                automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true
            if (secondBack)
                assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
            try {
                compose.waitUntil(15_000) { compose.activity.hasWindowFocus() }
            } catch (failure: androidx.compose.ui.test.ComposeTimeoutException) {
                val foreground = when (automation.rootInActiveWindow?.packageName?.toString()) {
                    "com.android.documentsui", "com.google.android.documentsui" -> "PICKER"
                    compose.activity.packageName -> "APPLICATION"
                    null -> "UNAVAILABLE"
                    else -> "OTHER"
                }
                val ime = automation.windows.any { it.type == android.view.accessibility.AccessibilityWindowInfo.TYPE_INPUT_METHOD }
                val setup = "EXPORT_CANCEL,INITIAL_IME_${if (initialIme) 1 else 0},SECOND_BACK_${if (secondBack) 1 else 0},FINAL_IME_${if (ime) 1 else 0}"
                throw AssertionError("KURDISTAN_TEST_SETUP expected=APPLICATION_FOCUS actual=$foreground setup=$setup", failure)
            }
        } finally {
            automation.serviceInfo = automation.serviceInfo.apply { flags = previousFlags }
        }
        assertEquals(before.revision, facade.readProjection()?.revision)
        assertEquals(keys, facade.enrollmentSummaries())
    }
}
