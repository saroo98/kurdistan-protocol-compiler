// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.ColorPainter
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.DeviceConfigurationOverride
import androidx.compose.ui.test.FontScale
import androidx.compose.ui.test.Locales
import androidx.compose.ui.test.WindowSize
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.then
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.intl.LocaleList
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.test.espresso.Espresso
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.ui.KurdistanOutlinedTextField
import org.kurdistanvpn.core.ui.KurdistanTheme

/** Real shared theme/field rendering only; no runtime, storage, or network effects. */
class ThemeContrastDeviceTest {
    @get:Rule val compose = createComposeRule()

    @After
    fun closeOwnedEditingKeyboard() {
        Espresso.closeSoftKeyboard()
    }

    @Test
    fun defaultTextAndIconsRemainVisibleWhenTheRootHasNoSurface() {
        var dark by mutableStateOf(true)
        var highContrast by mutableStateOf(false)
        var inherited = Color.Unspecified
        compose.setContent {
            KurdistanTheme(darkTheme = dark, highContrast = highContrast) {
                val contentColor = LocalContentColor.current
                SideEffect { inherited = contentColor }
                Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
                    Text("Readable heading", Modifier.testTag("theme_text"))
                    Icon(ColorPainter(Color.White), null, Modifier.size(24.dp).testTag("theme_icon"))
                    Surface(color = Color.Red, contentColor = Color.Green) {
                        Text("Surface override", Modifier.testTag("surface_text"))
                    }
                }
            }
        }
        // Literal palette expectations are independent of the theme's implementation.
        listOf(
            Triple(true, false, Color(0xFFF7F6F2)),
            Triple(true, true, Color.White),
            Triple(false, false, Color(0xFF111318)),
            Triple(false, true, Color.Black),
        ).forEach { (nextDark, nextContrast, expected) ->
            compose.runOnIdle { dark = nextDark; highContrast = nextContrast }
            assertRenderedColor("theme_text", expected)
            assertRenderedColor("theme_icon", expected)
            compose.runOnIdle { assertEquals("Root content color", expected, inherited) }
            assertRenderedColor("surface_text", Color.Green)
        }
    }

    @Test
    fun highContrastFieldDoesNotDrawAnExtraOutlineAroundSupportingText() {
        var value by mutableStateOf("")
        var masked by mutableStateOf(false)
        var minimumStroke = 0
        compose.setContent {
            KurdistanTheme(darkTheme = true, highContrast = true) {
                val strokePixels = with(LocalDensity.current) { 2.dp.roundToPx() }
                SideEffect { minimumStroke = strokePixels - 1 }
                Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
                    // Production secret fields are masked at creation, never toggled in place.
                    key(masked) {
                        KurdistanOutlinedTextField(
                            value = value, onValueChange = { value = it },
                            modifier = Modifier.width(280.dp).testTag("contrast_field"),
                            label = { Text("Search") },
                            supportingText = { Text("Supporting text outside the outline") },
                            singleLine = true,
                            visualTransformation = if (masked) PasswordVisualTransformation() else VisualTransformation.None,
                        )
                    }
                }
            }
        }
        compose.onNodeWithTag("contrast_field").assertTextContains("Search")
        assertSingleFieldOutline(minimumStroke)
        compose.onNodeWithTag("contrast_field").performClick()
        compose.onNodeWithTag("contrast_field").assertIsFocused().performTextInput("scope")
        compose.runOnIdle { assertEquals("scope", value) }
        compose.onNodeWithTag("contrast_field").assertTextContains("scope")
        assertSingleFieldOutline(minimumStroke)
        compose.runOnIdle { masked = true }
        val field = compose.onNodeWithTag("contrast_field")
        field.assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password))
        field.performClick().assertIsFocused().performTextInput("x")
        compose.runOnIdle { assertEquals("scopex", value) }
        val layouts = mutableListOf<TextLayoutResult>()
        val getLayout = field.fetchSemanticsNode().config[SemanticsActions.GetTextLayoutResult].action!!
        compose.runOnIdle {
            assertTrue(getLayout.invoke(layouts))
        }
        assertTrue("Visual transformation must mask the rendered value", layouts.any { it.layoutInput.text.text == "••••••" })
    }

    @Test
    fun actualPrimaryNavigationIconsRemainVisibleInHighContrast() {
        var destination by mutableStateOf(AppDestination.HOME)
        var soraniLarge by mutableStateOf(false)
        compose.setContent {
            DeviceConfigurationOverride(
                DeviceConfigurationOverride.WindowSize(DpSize(360.dp, 800.dp)) then
                    DeviceConfigurationOverride.FontScale(if (soraniLarge) 2f else 1f) then
                    DeviceConfigurationOverride.Locales(LocaleList(if (soraniLarge) "ckb" else "en")),
            ) {
                KurdistanTheme(darkTheme = true, highContrast = true) {
                    ProductNavigationChrome(destination, { destination = it }) {}
                }
            }
        }
        listOf(false, true).forEach { large ->
            compose.runOnIdle { soraniLarge = large }
            listOf(AppDestination.HOME, AppDestination.PROFILES, AppDestination.SETTINGS).forEach { selected ->
                compose.runOnIdle { destination = selected }
                listOf("primary_home", "primary_profiles", "primary_settings").forEach { tag ->
                    val item = compose.onNodeWithTag(tag)
                    val bounds = item.fetchSemanticsNode().boundsInRoot
                    val label = compose.onNode(
                        SemanticsMatcher.keyIsDefined(SemanticsProperties.Text) and hasAnyAncestor(hasTestTag(tag)),
                        useUnmergedTree = true,
                    ).fetchSemanticsNode().boundsInRoot
                    val pixels = item.captureToImage().toPixelMap()
                    val iconBottom = (label.top - bounds.top).toInt().coerceIn(0, pixels.height)
                    val visibleIconPixels = (0 until iconBottom).sumOf { y ->
                        (0 until pixels.width).count { x -> pixels[x, y].toArgb() == Color.White.toArgb() }
                    }
                    assertTrue("$tag icon is invisible with $selected selected (Sorani200%=$large)", visibleIconPixels >= 10)
                }
            }
        }
    }

    private fun assertRenderedColor(tag: String, expected: Color) {
        val pixels = compose.onNodeWithTag(tag).captureToImage().toPixelMap()
        val matches = (0 until pixels.height).sumOf { y ->
            (0 until pixels.width).count { x -> pixels[x, y].toArgb() == expected.toArgb() }
        }
        assertTrue("$tag has no readable foreground pixels for $expected (found $matches)", matches >= 10)
    }

    private fun assertSingleFieldOutline(minimumStroke: Int) {
        val pixels = compose.onNodeWithTag("contrast_field").captureToImage().toPixelMap()
        val whiteOnBottomEdge = (pixels.width / 4 until pixels.width * 3 / 4).count { x ->
            pixels[x, pixels.height - 2].toArgb() == Color.White.toArgb()
        }
        assertEquals("Supporting text must be outside the field's single outline", 0, whiteOnBottomEdge)
        val topEdge = (0 until pixels.height / 2).map { y ->
            pixels[pixels.width * 3 / 4, y].toArgb() == Color.White.toArgb()
        }
        val bands = topEdge.indices.count { index -> topEdge[index] && (index == 0 || !topEdge[index - 1]) }
        assertEquals("A field has exactly one top outline, including its floating-label clearance", 1, bands)
        assertTrue("High-contrast outline retains its 2dp essential boundary", topEdge.count { it } >= minimumStroke)
    }
}
