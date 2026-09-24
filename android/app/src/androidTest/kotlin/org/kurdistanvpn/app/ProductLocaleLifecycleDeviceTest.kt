// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.app.LocaleManager
import android.os.LocaleList
import android.view.View
import android.view.WindowInsets
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import androidx.lifecycle.Lifecycle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Rule
import org.junit.Test
import kotlin.math.abs
import org.kurdistanvpn.core.ui.R as UiR

/** Exercises the real Activity owner, not a composition-only locale override. */
@SdkSuppress(minSdkVersion = 33)
class ProductLocaleLifecycleDeviceTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun applicationLocaleRecreationKeepsRealActivityAndFilterModalInTheSameLanguage() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val manager = context.getSystemService(LocaleManager::class.java)
        val previous = manager.applicationLocales
        val previousLanguage = compose.activity.resources.configuration.locales[0].language
        try {
            // Keyboard mode survives Activity recreation and can asynchronously focus
            // the Settings search field. This fixture exercises touch navigation.
            instrumentation.setInTouchMode(true)
            androidx.test.espresso.Espresso.closeSoftKeyboard()
            listOf("en", "ckb", "en").forEach { locale ->
                val previousActivity = compose.activity
                val requested = LocaleList.forLanguageTags(locale)
                // An explicit override can recreate the Activity even when its effective language is unchanged.
                val changed = manager.applicationLocales != requested
                compose.runOnIdle { manager.applicationLocales = requested }
                compose.waitUntil(timeoutMillis = 20_000) {
                    runCatching {
                        compose.activity.resources.configuration.locales[0].language == locale &&
                            compose.activity.lifecycle.currentState == Lifecycle.State.RESUMED &&
                            compose.activity.hasWindowFocus() &&
                            (!changed || compose.activity !== previousActivity)
                    }.getOrDefault(false)
                }
                val activity = compose.activity
                if (changed) assertNotSame(previousActivity, activity)
                val ownerConfiguration = activity.window.decorView.context.resources.configuration
                assertEquals(locale, ownerConfiguration.locales[0].language)
                assertEquals(if (locale == "ckb") View.LAYOUT_DIRECTION_RTL else View.LAYOUT_DIRECTION_LTR,
                    ownerConfiguration.layoutDirection)

                awaitTouchViewport()
                compose.onNodeWithTag("primary_settings").performClick()
                awaitTouchViewport()
                compose.onNodeWithTag("settings_diagnostics").performScrollTo()
                compose.onNodeWithTag("settings_diagnostics").assertIsDisplayed()
                compose.onNodeWithTag("settings_diagnostics").performClick()
                compose.waitUntil(timeoutMillis = 20_000) {
                    runCatching { compose.onNodeWithTag("diagnostic_filters").assertExists(); true }.getOrDefault(false)
                }
                compose.onNodeWithTag("diagnostic_filters").performScrollTo().performClick()
                compose.onNodeWithTag("diagnostic_level_all").assertIsDisplayed()
                    .assertTextContains(activity.getString(UiR.string.all_levels))
                compose.onNodeWithTag("diagnostic_component_all").performScrollTo().assertIsDisplayed()
                    .assertTextContains(activity.getString(UiR.string.all_components))
                compose.onNodeWithTag("diagnostic_filter_apply").performScrollTo().assertIsDisplayed()
                    .assertTextContains(activity.getString(UiR.string.apply))
                compose.onNodeWithTag("diagnostic_filter_cancel").performScrollTo().assertIsDisplayed()
                    .assertTextContains(activity.getString(UiR.string.cancel)).performClick()
                compose.onNodeWithTag("primary_home").performClick()
            }
        } finally {
            val previousActivity = compose.activity
            val changed = manager.applicationLocales != previous
            compose.runOnIdle { manager.applicationLocales = previous }
            compose.waitUntil(timeoutMillis = 20_000) {
                runCatching {
                    manager.applicationLocales == previous &&
                        (!changed || compose.activity !== previousActivity) &&
                        compose.activity.resources.configuration.locales[0].language == previousLanguage &&
                        compose.activity.lifecycle.currentState == Lifecycle.State.RESUMED && compose.activity.hasWindowFocus()
                }.getOrDefault(false)
            }
        }
    }

    private fun awaitTouchViewport() {
        compose.waitUntil(timeoutMillis = 20_000) {
            runCatching {
                val activity = compose.activity
                val decor = activity.window.decorView
                val insets = decor.rootWindowInsets
                val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                val frame = android.graphics.Rect().also(decor::getWindowVisibleDisplayFrame)
                val origin = IntArray(2).also(decor::getLocationOnScreen)
                val root = compose.onRoot().fetchSemanticsNode().boundsInRoot
                val navigation = compose.onNodeWithTag("primary_navigation_bar").fetchSemanticsNode().boundsInRoot
                // Compose idleness alone does not wait for the platform's pending IME
                // and window-inset layout. Compare actual native and Compose viewports.
                activity.hasWindowFocus() && decor.isInTouchMode && !decor.isLayoutRequested &&
                    !insets.isVisible(WindowInsets.Type.ime()) && insets.getInsets(WindowInsets.Type.ime()).bottom == 0 &&
                    abs(root.height - decor.height) <= 1f &&
                    frame.bottom == origin[1] + decor.height - safe.bottom &&
                    abs(navigation.bottom - (decor.height - safe.bottom)) <= 1f
            }.getOrDefault(false)
        }
    }
}
