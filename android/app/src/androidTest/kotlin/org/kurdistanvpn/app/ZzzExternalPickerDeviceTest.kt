// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
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
        compose.onNodeWithTag("primary_profiles")
            .performClick()
        compose.onNodeWithText(compose.activity.getString(UiR.string.import_profile_file))
            .performScrollTo()
            .performClick()

        compose.waitUntil(timeoutMillis = 10_000) {
            !compose.activity.hasWindowFocus()
        }
    }
}
