// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.res.Configuration
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.DeviceConfigurationOverride
import androidx.compose.ui.test.Locales
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontSynthesis
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.intl.LocaleList
import androidx.compose.ui.text.style.ResolvedTextDirection
import androidx.compose.ui.unit.sp
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.ui.KurdistanTheme
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsAboutScreen
import org.kurdistanvpn.core.ui.R as UiR

/** Exercises real Compose styles and navigation. Synthetic text only; no runtime effects. */
class SoraniPresentationDeviceTest {
    @get:Rule val compose = createComposeRule()

    @Composable
    private fun InLocale(locale: String, content: @Composable () -> Unit) {
        DeviceConfigurationOverride(DeviceConfigurationOverride.Locales(LocaleList(locale))) {
            KurdistanTheme(reducedMotion = true, content = content)
        }
    }

    private fun layout(tag: String): TextLayoutResult {
        val results = mutableListOf<TextLayoutResult>()
        compose.onNodeWithTag(tag, useUnmergedTree = true)
            .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(results) }
        return results.single()
    }

    @Test
    fun soraniRegularFacesDoNotSynthesizeWeightAndPreserveExistingMetrics() {
        compose.setContent {
            InLocale("ckb") {
                Column {
                    Text("سەرەکی", Modifier.testTag("heading"), style = MaterialTheme.typography.headlineMedium)
                    Text("پەیوەندی", Modifier.testTag("body"), style = MaterialTheme.typography.bodyLarge)
                    Text("پەیوەندی", Modifier.testTag("secondary"), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        val heading = layout("heading").layoutInput.style
        val body = layout("body").layoutInput.style
        val secondary = layout("secondary").layoutInput.style
        listOf(heading, body, secondary).forEach {
            assertEquals(FontWeight.Normal, it.fontWeight)
            assertEquals(FontSynthesis.None, it.fontSynthesis)
            assertEquals(0.sp, it.letterSpacing)
        }
        assertEquals(FontFamily(Font(UiR.font.sorani_magroon)), heading.fontFamily)
        assertEquals(FontFamily(Font(UiR.font.sorani_body)), body.fontFamily)
        assertEquals(FontFamily(Font(UiR.font.sorani_midya)), secondary.fontFamily)
        assertEquals(22.sp, heading.fontSize)
        assertEquals(32.sp, heading.lineHeight)
        assertEquals(16.sp, body.fontSize)
        assertEquals(28.sp, body.lineHeight)
        assertEquals(14.sp, secondary.fontSize)
        assertEquals(24.sp, secondary.lineHeight)
    }

    @Test
    fun soraniNavigationUsesRegularHeadingFaceForSelectedAndUnselectedControls() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val configuration = Configuration(context.resources.configuration).apply {
            setLocale(java.util.Locale.forLanguageTag("ckb"))
        }
        val localized = context.createConfigurationContext(configuration)
        compose.setContent { InLocale("ckb") { ProductNavigationChrome(AppDestination.HOME, {}) {} } }
        listOf(UiR.string.home, UiR.string.profiles, UiR.string.settings).forEach { id ->
            val results = mutableListOf<TextLayoutResult>()
            compose.onNodeWithText(localized.getString(id), useUnmergedTree = true)
                .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(results) }
            val style = results.single().layoutInput.style
            assertEquals(FontFamily(Font(UiR.font.sorani_magroon)), style.fontFamily)
            assertEquals(FontWeight.Normal, style.fontWeight)
            assertEquals(FontSynthesis.None, style.fontSynthesis)
            assertEquals(12.sp, style.fontSize)
            assertEquals(20.sp, style.lineHeight)
        }
    }

    @Test
    fun soraniProseAndOpaqueLatinIdentityKeepTheirOwnReadingDirections() {
        compose.setContent {
            InLocale("ckb") {
                Column {
                    Text("پەیوەندی: DNS 123", Modifier.testTag("prose"))
                    Text("DEMO-123.example:443", Modifier.testTag("identity"))
                }
            }
        }
        assertEquals(ResolvedTextDirection.Rtl, layout("prose").getParagraphDirection(0))
        assertEquals(ResolvedTextDirection.Ltr, layout("identity").getParagraphDirection(0))
        assertEquals("DEMO-123.example:443", layout("identity").layoutInput.text.text)
    }

    @Test
    fun diagnosticTechnicalCodesAreIsolatedForSoraniEvenWhenDeviceDefaultIsEnglish() {
        val previous = java.util.Locale.getDefault()
        try {
            java.util.Locale.setDefault(java.util.Locale.ENGLISH)
            compose.setContent {
                InLocale("ckb") {
                    DiagnosticsAboutScreen(
                        DiagnosticWorkflowState.Idle, "synthetic", null,
                        listOf(DiagnosticEvent(1, DiagnosticLogLevel.INFO, DiagnosticComponent.APP, "FIXTURE_EVENT")),
                        {}, {}, {}, {}, {},
                    )
                }
            }
            val nodes = compose.onAllNodesWithText("FIXTURE_EVENT", substring = true, useUnmergedTree = true)
                .fetchSemanticsNodes()
            val category = nodes.single().config[SemanticsProperties.Text].single().text
            assertTrue("Latin category lacks Sorani-context isolation: $category", category.startsWith("\u200f"))
            assertTrue(category.endsWith("\u200f"))
            assertEquals("FIXTURE_EVENT", category.filterNot { it in "\u200e\u200f\u202a\u202b\u202c" })
        } finally {
            java.util.Locale.setDefault(previous)
        }
    }

    @Test
    fun englishHeadingRetainsSystemFaceAndSemiboldMetrics() {
        compose.setContent {
            InLocale("en") { Text("Home", Modifier.testTag("heading"), style = MaterialTheme.typography.headlineMedium) }
        }
        val style = layout("heading").layoutInput.style
        assertEquals(FontFamily.SansSerif, style.fontFamily)
        assertEquals(FontWeight.SemiBold, style.fontWeight)
        assertEquals(22.sp, style.fontSize)
        assertEquals(28.sp, style.lineHeight)
        assertTrue(style.fontSynthesis != FontSynthesis.None)
    }
}
