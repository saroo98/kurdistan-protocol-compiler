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
        compose.waitUntil(15_000) { automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true }
        assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
        automation.waitForIdle(100, 2_000)
        if (automation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true)
            assertTrue(automation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
        compose.waitUntil(15_000) { compose.activity.hasWindowFocus() }
        assertEquals(before.revision, facade.readProjection()?.revision)
        assertEquals(keys, facade.enrollmentSummaries())
    }
}
