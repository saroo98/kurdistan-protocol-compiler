// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test

class Phase14LongevityDeviceTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun repeatedPrimaryNavigationRemainsResponsiveWithoutProcessFailure() {
        repeat(50) {
            compose.onNodeWithTag("primary_profiles").performClick()
            compose.onNodeWithTag("primary_profiles").assertIsDisplayed()
            compose.onNodeWithTag("primary_settings").performClick()
            compose.onNodeWithTag("settings_search").assertIsDisplayed()
            compose.onNodeWithTag("primary_home").performClick()
            compose.onNodeWithTag("connection_hero").assertIsDisplayed()
        }
    }
}
