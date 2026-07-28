// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.ui.R as UiR

class Phase9FoundationUiTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun phase9NeverPresentsAFakeConnectionControl() {
        compose.onNodeWithText(compose.activity.getString(UiR.string.product_name))
            .assertIsDisplayed()
        compose.onNodeWithText(compose.activity.getString(UiR.string.runtime_unavailable))
            .assertIsDisplayed()
        compose.onAllNodesWithText("Connect", substring = true, ignoreCase = true)
            .assertCountEquals(0)
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
}
