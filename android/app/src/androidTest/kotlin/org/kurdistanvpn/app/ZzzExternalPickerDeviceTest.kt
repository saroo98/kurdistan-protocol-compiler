// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.kurdistanvpn.core.ui.R as UiR

/**
 * Runs after the in-app interaction suite so the external DocumentsUI activity
 * cannot invalidate a Compose ActivityScenario required by a subsequent test.
 */
@RunWith(AndroidJUnit4::class)
class ZzzExternalPickerDeviceTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun profileFileImportLaunchesTheSystemDocumentPickerWithoutCrashing() {
        compose.continueFromWelcome(compose.activity)
        compose.waitUntil(10_000) {
            compose.activity.lifecycle.currentState == androidx.lifecycle.Lifecycle.State.RESUMED &&
                compose.activity.hasWindowFocus()
        }
        compose.onNodeWithTag("primary_profiles")
            .performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("profiles_add").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("profiles_add").performScrollTo().performClick()
        compose.onNodeWithText(compose.activity.getString(UiR.string.import_profile_file))
            .performScrollTo()
            .performClick()

        compose.waitUntil(timeoutMillis = 10_000) {
            !compose.activity.hasWindowFocus()
        }
        val automation = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().uiAutomation
        try {
            compose.waitUntil(10_000) {
                automation.rootInActiveWindow?.packageName?.toString()?.endsWith("documentsui") == true
            }
        } catch (failure: androidx.compose.ui.test.ComposeTimeoutException) {
            val foreground = when (automation.rootInActiveWindow?.packageName?.toString()) {
                "com.android.documentsui", "com.google.android.documentsui" -> "PICKER"
                compose.activity.packageName -> "APPLICATION"
                "com.android.systemui", "com.android.settings" -> "SYSTEM"
                null -> "UNAVAILABLE"
                else -> "OTHER"
            }
            val focused = if (compose.activity.hasWindowFocus()) 1 else 0
            val state = compose.activity.lifecycle.currentState.name
            throw AssertionError("KURDISTAN_TEST_SETUP expected=DOCUMENT_PICKER actual=$foreground setup=IMPORT_PICKER,APP_FOCUS_$focused,LIFECYCLE_$state", failure)
        }
        org.junit.Assert.assertTrue(automation.performGlobalAction(
            android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
        compose.waitUntil(10_000) { compose.activity.hasWindowFocus() }
        compose.onNodeWithTag("primary_profiles").performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("profiles_add").fetchSemanticsNodes().isNotEmpty()
        }
    }
}
