// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.graphics.Bitmap
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCompositionContext
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.DeviceConfigurationOverride
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.FontScale
import androidx.compose.ui.test.Locales
import androidx.compose.ui.test.WindowSize
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertHeightIsAtLeast
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.assertWidthIsAtLeast
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.then
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.intl.LocaleList
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.ui.KurdistanTheme
import org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsAboutScreen
import org.kurdistanvpn.feature.home.HomeScreen
import org.kurdistanvpn.feature.profiles.ProfilesScreen
import org.kurdistanvpn.feature.settingsrecovery.SettingsIndexScreen
import org.kurdistanvpn.feature.settingsrecovery.SettingsRecoveryScreen
import org.kurdistanvpn.feature.settingsrecovery.TunnelDnsSettingsScreen
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.validatedForDisplay
import org.kurdistanvpn.core.ui.R as UiR

/** Synthetic presentation only: no runtime, storage, import, export or network effects. */
class ProductVisualContractDeviceTest {
    @get:Rule val compose = createComposeRule()
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val first = ProfileSummary("visual-a", "Example profile", ProfileTrust.VERIFIED_NONPRODUCTION, 7u, 4_102_444_800)
    private val second = first.copy(localRecordId = "visual-b", displayAlias = "Example profile")
    private val profiles = listOf(first, second)
    private val settings = ProductSettings(profiles = ProfilePreferences(activeLocalRecordId = first.localRecordId))

    private data class ViewCase(
        val width: Int = 360, val height: Int = 800, val font: Float = 1f,
        val locale: String = "en", val dark: Boolean = false, val contrast: Boolean = false,
        val screen: String = "home",
    ) {
        val id get() = "$screen-$width-$height-$font-$locale-$dark-$contrast"
    }

    @Composable
    private fun View(case: ViewCase, content: @Composable () -> Unit) {
        DeviceConfigurationOverride(
            DeviceConfigurationOverride.WindowSize(DpSize(case.width.dp, case.height.dp)) then
                DeviceConfigurationOverride.FontScale(case.font) then
                DeviceConfigurationOverride.Locales(LocaleList(case.locale)),
        ) {
            val themed: @Composable () -> Unit = {
                KurdistanTheme(darkTheme = case.dark, highContrast = case.contrast, reducedMotion = true) {
                    Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).testTag("visual_root")) { content() }
                }
            }
            if (case.screen in setOf("profile-dialog", "filter-dialog", "destructive")) {
                LocalizedModalOwner(case.locale, themed)
            } else {
                themed()
            }
        }
    }

    /** ModalBottomSheet creates its new owner from LocalView.context, not LocalContext. */
    @Composable
    private fun LocalizedModalOwner(locale: String, content: @Composable () -> Unit) {
        val latestContent by rememberUpdatedState(content)
        val parent = rememberCompositionContext()
        val density = LocalDensity.current
        val direction = LocalLayoutDirection.current
        val window = LocalWindowInfo.current
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { localizedContext ->
                ComposeView(localizedContext).apply {
                    setParentCompositionContext(parent)
                    setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
                    setContent {
                        check(LocalView.current.context.resources.configuration.locales[0].language == locale)
                        CompositionLocalProvider(
                            LocalDensity provides density,
                            LocalLayoutDirection provides direction,
                            LocalWindowInfo provides window,
                        ) { latestContent() }
                    }
                }
            },
        )
    }

    private fun primaryTag(destination: AppDestination) = when (destination) {
        AppDestination.HOME -> "primary_home"
        AppDestination.PROFILES, AppDestination.OPERATOR_PROVIDER -> "primary_profiles"
        else -> "primary_settings"
    }

    private fun assertInside(child: Rect, parent: Rect, name: String) {
        assertTrue("$name exceeds leading bound: $child / $parent", child.left >= parent.left - 1f)
        assertTrue("$name exceeds top bound: $child / $parent", child.top >= parent.top - 1f)
        assertTrue("$name exceeds trailing bound: $child / $parent", child.right <= parent.right + 1f)
        assertTrue("$name exceeds bottom bound: $child / $parent", child.bottom <= parent.bottom + 1f)
    }

    private fun assertNavigation(width: Int, selected: AppDestination) {
        val chrome = if (width < 600) "primary_navigation_bar" else "primary_navigation_rail"
        compose.onNodeWithTag(chrome).assertIsDisplayed()
        val root = compose.onNodeWithTag("visual_root").fetchSemanticsNode().boundsInRoot
        val nav = compose.onNodeWithTag(chrome).fetchSemanticsNode().boundsInRoot
        assertInside(nav, root, chrome)
        val nodes = listOf("primary_home", "primary_profiles", "primary_settings").map { tag ->
            val node = compose.onNodeWithTag(tag)
            node.assertIsDisplayed().assertHeightIsAtLeast(48.dp).assertWidthIsAtLeast(48.dp)
            node.fetchSemanticsNode().boundsInRoot
        }
        nodes.forEachIndexed { i, rect -> assertInside(rect, nav, "navigation item $i") }
        nodes.zipWithNext().forEach { (a, b) ->
            assertFalse("Navigation targets overlap: $a / $b", a.overlaps(b))
        }
        compose.onNodeWithTag(primaryTag(selected)).assertIsSelected()
        val textNodes = compose.onAllNodes(
            SemanticsMatcher.keyIsDefined(SemanticsProperties.Text) and hasAnyAncestor(hasTestTag(chrome)),
            useUnmergedTree = true,
        ).fetchSemanticsNodes()
        textNodes.forEach { node ->
            assertInside(node.boundsInRoot, nav, "navigation label")
            val layouts = mutableListOf<TextLayoutResult>()
            compose.runOnIdle { node.config.getOrNull(SemanticsActions.GetTextLayoutResult)?.action?.invoke(layouts) }
            layouts.forEach {
                assertFalse("Navigation text clipped", it.hasVisualOverflow)
                if (width < 600) assertEquals(
                    "Compact navigation must not split a destination word: ${it.layoutInput.text.text}; " +
                        "width=${it.size.width}, lines=${it.lineCount}",
                    1, it.lineCount,
                )
            }
        }
    }

    private fun reachable(tag: String) {
        compose.onNodeWithTag(tag).performScrollTo().assertIsDisplayed()
            .assertHeightIsAtLeast(48.dp).assertWidthIsAtLeast(48.dp)
    }

    private fun capture(label: String, case: ViewCase) {
        val run = InstrumentationRegistry.getArguments().getString("uiuxEvidenceRun") ?: return
        require(run.matches(Regex("[a-zA-Z0-9_-]{1,80}")))
        compose.waitForIdle()
        val directory = File(context.getExternalFilesDir(null), "uiux-audit/$run").apply { mkdirs() }
        val name = "$label-${case.id}".replace(Regex("[^a-zA-Z0-9_.-]"), "_")
        val bitmap = checkNotNull(instrumentation.uiAutomation.takeScreenshot())
        val target = File(directory, "$name.png")
        check(!target.exists()) { "Refuse to overwrite previous device evidence: $name" }
        target.outputStream().use { check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)) }
        val metadata = JSONObject().put("file", target.name).put("case", case.id)
            .put("widthPx", bitmap.width).put("heightPx", bitmap.height)
            .put("api", android.os.Build.VERSION.SDK_INT).put("testOnly", true)
        File(directory, "manifest.jsonl").appendText(metadata.toString() + "\n")
        bitmap.recycle()
    }

    @Test
    fun navigationAccentsRemainVisibleWhenTheirDestinationIsNotSelected() {
        compose.setContent { View(ViewCase(width = 412)) { ProductNavigationChrome(AppDestination.PROFILES, {}) { } } }
        mapOf("primary_home" to 0xffb73542.toInt(), "primary_settings" to 0xff237345.toInt()).forEach { (tag, expected) ->
            val pixels = compose.onNodeWithTag(tag).captureToImage().toPixelMap()
            var matches = 0
            for (y in 0 until pixels.height) for (x in 0 until pixels.width) {
                if (pixels[x, y].toArgb() == expected) matches++
            }
            assertTrue("$tag must retain its destination accent independently of selection", matches > 10)
        }
        compose.onNodeWithTag("primary_profiles").assertIsSelected()
    }

    @Test fun soraniNavigationRecoveryAndStaleActionsAreReadableAndUsable() {
        var recovery by mutableStateOf(false)
        var actions = 0
        val case = ViewCase(width = 412, height = 915, locale = "ckb", dark = true)
        compose.setContent {
            View(case) {
                if (recovery) ProductNavigationRecovery { actions++ }
                else ProductRouteUnavailable(ProductDestination.ProfileDetail("missing-profile"), true,
                    onBack = { actions++ }, onRoot = { recovery = true })
            }
        }
        compose.onNodeWithText("ئەم بڕگەیە چیتر بەردەست نییە. بگەڕێوە یان بەشە سەرەکییەکەی بکەرەوە.").assertIsDisplayed()
        capture("stale-route", case)
        compose.onNodeWithText("کردنەوەی بەشی سەرەکی").performClick()
        compose.onNodeWithText("گەڕانی پاشەکەوتکراو نەگەڕێندرایەوە. گەڕان لە نوێوە دەست پێ بکەرەوە بەبێ گۆڕینی داتای ئەپەکەت.").assertIsDisplayed()
        capture("navigation-recovery", case)
        compose.onNode(androidx.compose.ui.test.hasText("دەستپێکردنەوەی گەڕان") and
            androidx.compose.ui.test.hasClickAction()).performClick()
        compose.runOnIdle { assertEquals(1, actions) }
    }

    @Test
    fun homeBrandIsCenteredAndDoesNotDuplicateTheProductNameAsText() {
        compose.setContent { View(ViewCase(width = 412, height = 915, locale = "ckb")) { Home() } }
        val mark = compose.onNodeWithTag("home_brand").assertIsDisplayed().fetchSemanticsNode().boundsInRoot
        val root = compose.onNodeWithTag("visual_root").fetchSemanticsNode().boundsInRoot
        assertTrue("Brand must be centered in the content", kotlin.math.abs(mark.center.x - root.center.x) < 2f)
        compose.onNodeWithText(localized("ckb", UiR.string.product_name)).assertDoesNotExist()
        capture("brand", ViewCase(width = 412, height = 915, locale = "ckb"))
    }

    @Test
    fun selectedProfileActionStaysWithItsHeadingAboveTheIdentity() {
        var case by mutableStateOf(ViewCase(width = 412, height = 915))
        compose.setContent { key(case.id) { View(case) { Home() } } }
        listOf("en", "ckb").forEach { locale ->
            compose.runOnIdle { case = ViewCase(width = 412, height = 915, locale = locale) }
            reachable("home_profiles")
            val action = compose.onNodeWithTag("home_profiles").fetchSemanticsNode().boundsInRoot
            val label = compose.onNodeWithText(localized(locale, UiR.string.uiux_selected_profile))
                .fetchSemanticsNode().boundsInRoot
            val identity = compose.onNodeWithText(first.displayAlias).fetchSemanticsNode().boundsInRoot
            assertTrue("Profile heading and action must share a row", kotlin.math.abs(label.center.y - action.center.y) < 2f)
            assertFalse("Profile heading and action overlap", label.overlaps(action))
            assertTrue("Profile identity belongs below its heading and action", identity.top >= maxOf(label.bottom, action.bottom))
        }
    }

    @Test
    fun navigationMapsEveryChildAndStaysInsideTheViewport() {
        var case by mutableStateOf(ViewCase())
        var current by mutableStateOf(AppDestination.HOME)
        compose.setContent { View(case) { ProductNavigationChrome(current, {}) { } } }
        val cases = listOf(360, 412, 599, 600, 700, 839, 840, 1024, 1280, 1600).flatMap { width ->
            listOf(ViewCase(width = width), ViewCase(width = width, font = 2f, locale = "ckb", dark = true))
        }
        cases.forEach { next ->
            compose.runOnIdle { case = next }
            AppDestination.entries.forEach { destination ->
                compose.runOnIdle { current = destination }
                try { assertNavigation(next.width, destination) }
                catch (failure: AssertionError) {
                    throw AssertionError("Navigation case ${next.id}, destination=$destination", failure)
                }
            }
            capture("navigation", next)
        }
    }

    @Test
    fun primaryScreensRetainReachableActionsAcrossLocalesThemesAndTextScale() {
        var case by mutableStateOf(ViewCase())
        compose.setContent {
            key(case.id) {
                View(case) {
                    val destination = when (case.screen) {
                        "home" -> AppDestination.HOME
                        "profiles" -> AppDestination.PROFILES
                        "settings" -> AppDestination.SETTINGS
                        "recovery" -> AppDestination.PRIVACY_RECOVERY
                        else -> AppDestination.DIAGNOSTICS_ABOUT
                    }
                    ProductNavigationChrome(destination, {}) {
                        when (case.screen) {
                            "home" -> Home()
                            "profiles" -> Profiles()
                            "settings" -> Settings()
                            "recovery" -> Recovery()
                            else -> Diagnostics()
                        }
                    }
                }
            }
        }
        val base = listOf(360 to 800, 412 to 915).flatMap { (width, height) ->
            listOf(false, true).flatMap { dark ->
                listOf(1f, 2f).map { font -> ViewCase(width, height, font, dark = dark) }
            }
        } + listOf(
            ViewCase(locale = "ckb"),
            ViewCase(locale = "ckb", dark = true),
            ViewCase(font = 2f, locale = "ckb", dark = true, contrast = true),
            ViewCase(font = 2f, locale = "fa", contrast = true),
            ViewCase(font = 2f, locale = "ar", dark = true),
            ViewCase(locale = "ku-Latn"),
        )
        base.forEach { configuration ->
            listOf("home", "profiles", "settings", "recovery", "diagnostics").forEach { screen ->
                val next = configuration.copy(screen = screen)
                compose.runOnIdle { case = next }
                assertNavigation(next.width, when (screen) {
                    "home" -> AppDestination.HOME
                    "profiles" -> AppDestination.PROFILES
                    else -> AppDestination.SETTINGS
                })
                if (screen == "home" && next.font == 1f && next.locale == "en") {
                    compose.onNodeWithTag("connection_hero").assertIsDisplayed()
                    compose.onNodeWithTag("connect_button").assertIsDisplayed()
                    compose.onNodeWithTag("home_selected_profile").assertIsDisplayed()
                }
                capture("initial", next)
                when (screen) {
                    "home" -> {
                        reachable("home_details")
                        compose.onNodeWithTag("home_details").performClick()
                        reachable("home_diagnostics")
                    }
                    "profiles" -> reachable("profiles_operator")
                    "settings" -> reachable("settings_expert")
                    "recovery" -> reachable("reset_scope_everything")
                    else -> reachable("diagnostic_about")
                }
                capture("lower", next)
            }
        }
    }

    @Test
    fun everyRuntimeStateKeepsItsQualifiedStatusAndCorrectAction() {
        var case by mutableStateOf(ViewCase())
        var runtime by mutableStateOf(VpnRuntimeSnapshot())
        var start = 0; var stop = 0; var openProfiles = 0; var openSettings = 0
        compose.setContent {
            key(case.id, runtime.state) {
                View(case) {
                    HomeScreen(AppState.Ready(profiles), settings, runtime,
                        { start++ }, { stop++ }, { openProfiles++ }, { openSettings++ }, {}, {})
                }
            }
        }
        val variants = listOf(
            ViewCase(), ViewCase(dark = true), ViewCase(contrast = true),
            ViewCase(dark = true, contrast = true),
            ViewCase(font = 2f, locale = "ckb", dark = true, contrast = true),
        )
        variants.forEach { variant ->
            VpnRuntimeState.entries.forEach { state ->
                val snapshot = if (state == VpnRuntimeState.ACTIVE_KURD_LIVE) VpnRuntimeSnapshot(
                    state = state, runtimeRequestId = "1".repeat(32), startedAtElapsedRealtime = 1,
                    profileGeneration = 7uL, planDigest = "2".repeat(64), profileFingerprint = "3".repeat(64),
                    strategyFingerprint = "4".repeat(64), relayFingerprint = "5".repeat(64),
                    alwaysOn = false, lockdown = false,
                ) else VpnRuntimeSnapshot(state, alwaysOn = false, lockdown = false)
                compose.runOnIdle {
                    case = variant.copy(screen = state.name)
                    runtime = snapshot.validatedForDisplay()
                    start = 0; stop = 0; openProfiles = 0; openSettings = 0
                }
                assertEquals(state, runtime.state)
                if (state == VpnRuntimeState.IDLE || state == VpnRuntimeState.ACTIVE_KURD_LIVE) {
                    compose.onNodeWithTag("home_sun", useUnmergedTree = true).assertIsDisplayed()
                } else {
                    compose.onNodeWithTag("home_sun", useUnmergedTree = true).assertDoesNotExist()
                }
                val tag = when (state) {
                    VpnRuntimeState.PREPARING, VpnRuntimeState.AWAITING_VPN_CONSENT, VpnRuntimeState.CONNECTING,
                    VpnRuntimeState.FALLING_BACK, VpnRuntimeState.RECONNECTING, VpnRuntimeState.RECOVERING -> "home_cancel"
                    VpnRuntimeState.ACTIVE_KURD_LIVE, VpnRuntimeState.DEGRADED -> "home_disconnect"
                    VpnRuntimeState.STOPPING -> "home_stopping"
                    VpnRuntimeState.BLOCKED -> "home_review_restriction"
                    VpnRuntimeState.REVOKED -> "home_choose_profile"
                    else -> "connect_button"
                }
                reachable(tag)
                if (state == VpnRuntimeState.STOPPING) compose.onNodeWithTag(tag).assertIsNotEnabled()
                compose.onNodeWithTag(tag).performClick()
                compose.runOnIdle {
                    assertEquals(if (tag == "connect_button") 1 else 0, start)
                    assertEquals(if (tag in listOf("home_cancel", "home_disconnect")) 1 else 0, stop)
                    assertEquals(if (tag == "home_choose_profile") 1 else 0, openProfiles)
                    assertEquals(if (tag == "home_review_restriction") 1 else 0, openSettings)
                }
                capture("state", case)
            }
        }
        val malformed = VpnRuntimeSnapshot(VpnRuntimeState.ACTIVE_KURD_LIVE, packetsRead = -1, lockdown = true).validatedForDisplay()
        compose.runOnIdle { runtime = malformed; case = ViewCase(screen = "malformed") }
        assertEquals(VpnRuntimeState.BLOCKED, malformed.state)
        assertEquals("INVALID_RUNTIME_STATUS", malformed.failure)
        assertEquals(true, malformed.lockdown)
        reachable("home_review_restriction")
        compose.onNodeWithTag("home_disconnect").assertDoesNotExist()
    }

    @Test
    fun noProfileActionsCannotStartAndIncompleteLiveDataIsBlocked() {
        var runtime by mutableStateOf(VpnRuntimeSnapshot())
        var additions = 0
        var starts = 0
        compose.setContent {
            View(ViewCase()) {
                HomeScreen(AppState.NoProfiles, settings, runtime, { starts++ }, {}, { additions++ }, {}, {}, {})
            }
        }
        listOf(VpnRuntimeState.IDLE, VpnRuntimeState.FAILED).forEach { state ->
            compose.runOnIdle { runtime = VpnRuntimeSnapshot(state) }
            reachable("home_add_profile")
            compose.onNodeWithTag("home_add_profile").performClick()
        }
        compose.runOnIdle { assertEquals(2, additions); assertEquals(0, starts) }
        val incomplete = VpnRuntimeSnapshot(VpnRuntimeState.ACTIVE_KURD_LIVE).validatedForDisplay()
        assertEquals(VpnRuntimeState.BLOCKED, incomplete.state)
        assertEquals("INVALID_RUNTIME_STATUS", incomplete.failure)
    }

    @Test
    fun profileSwitchRequiresCurrentApprovalAndNeverConfusesFavoriteWithSelection() {
        var currentProfiles by mutableStateOf(profiles)
        var active by mutableStateOf(first.localRecordId)
        val selected = mutableListOf<String>()
        val favorites = mutableListOf<String>()
        compose.setContent {
            View(ViewCase()) {
                ProfilesScreen(
                    currentProfiles, settings.copy(profiles = ProfilePreferences(activeLocalRecordId = active)),
                    onSelectProfile = { selected += it; active = it },
                    onToggleFavorite = { favorites += it },
                    onImportFile = {}, onImportClipboard = {}, onImportLink = {}, onScanQr = {},
                    onExportProfile = { _, _ -> }, onDeleteProfile = {}, onBack = {},
                    connectionWillStopOnSelection = true,
                )
            }
        }
        reachable("profile_favorite_visual-b")
        compose.onNodeWithTag("profile_favorite_visual-b").performClick()
        compose.runOnIdle { assertEquals(listOf("visual-b"), favorites); assertTrue(selected.isEmpty()) }
        reachable("profile_select_visual-b")
        compose.onNodeWithTag("profile_select_visual-b").performClick()
        compose.runOnIdle { assertTrue(selected.isEmpty()) }
        compose.onNodeWithTag("profile_cancel_selection").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(first.localRecordId, active); assertTrue(selected.isEmpty()) }
        compose.onNodeWithTag("profile_select_visual-b").performScrollTo().performClick()
        compose.runOnIdle { currentProfiles = currentProfiles.reversed() }
        compose.onNodeWithTag("profile_confirm_selection").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(listOf("visual-b"), selected) }
        compose.onNodeWithTag("profile_select_visual-b").assertDoesNotExist()
        reachable("profile_select_visual-a")
        compose.onNodeWithTag("profile_select_visual-a").performClick()
        compose.runOnIdle { currentProfiles = listOf(second) }
        compose.onNodeWithTag("profile_confirm_selection").assertDoesNotExist()
        compose.onNodeWithTag("profile_selection_reason").assertIsDisplayed()
        compose.runOnIdle {
            assertEquals(listOf("visual-b"), selected)
            currentProfiles = listOf(first.copy(expiresAtEpochSeconds = 1), second.copy(trust = ProfileTrust.REJECTED))
        }
        compose.onNodeWithTag("profile_select_visual-a").assertDoesNotExist()
        compose.onNodeWithTag("profile_select_visual-b").assertDoesNotExist()
        reachable("profile_details_visual-a")
        reachable("profile_favorite_visual-a")
    }

    @Test
    fun filterDraftCancelPreservesEventsAndCountUsesTheBoundedOrderedList() {
        val events = (1L..63L).map { i ->
            DiagnosticEvent(i, if (i % 2L == 0L) DiagnosticLogLevel.ERROR else DiagnosticLogLevel.INFO,
                DiagnosticComponent.RUNTIME, "FIXTURE_EVENT")
        }
        var clear = 0
        compose.setContent { View(ViewCase()) { Diagnostics(events = events, onClear = { clear++ }) } }
        compose.onNodeWithTag("diagnostic_count").assertIsDisplayed()
        compose.onNodeWithText(context.getString(UiR.string.uiux_diagnostic_count, 50, 63, 63)).assertIsDisplayed()
        compose.onNodeWithTag("diagnostic_event_13").assertDoesNotExist()
        compose.onNodeWithTag("diagnostic_filters").performClick()
        compose.onNodeWithTag("diagnostic_level_ERROR").performScrollTo().performClick()
        compose.onNodeWithTag("diagnostic_filter_cancel").performScrollTo().performClick()
        compose.onNodeWithTag("diagnostic_event_63").assertIsDisplayed()
        compose.onNodeWithTag("diagnostic_filters").performScrollTo().performClick()
        compose.onNodeWithTag("diagnostic_level_ERROR").performScrollTo().performClick()
        compose.onNodeWithTag("diagnostic_filter_apply").performScrollTo().performClick()
        compose.onNodeWithText(context.getString(UiR.string.uiux_diagnostic_count, 31, 31, 63)).assertIsDisplayed()
        compose.onNodeWithTag("diagnostic_event_63").assertDoesNotExist()
        compose.onNodeWithTag("diagnostic_event_62").assertIsDisplayed()
        val recent = compose.onNodeWithTag("diagnostic_event_62").fetchSemanticsNode().boundsInRoot
        val older = compose.onNodeWithTag("diagnostic_event_60").fetchSemanticsNode().boundsInRoot
        assertTrue("Events are newest first", recent.top < older.top)
        compose.runOnIdle { assertEquals(0, clear) }
        reachable("diagnostic_clear")
        compose.onNodeWithTag("diagnostic_clear").performClick()
        compose.runOnIdle { assertEquals(1, clear) }
    }

    @Test
    fun largeTextRtlDialogsAndDestructiveConfirmationKeepReachableActions() {
        var case by mutableStateOf(ViewCase())
        var screen by mutableStateOf("profiles")
        compose.setContent {
            key(case.id, screen) {
                View(case) {
                    when (screen) {
                        "profiles" -> Profiles(connectionWillStop = true)
                        "diagnostics" -> Diagnostics()
                        else -> Recovery()
                    }
                }
            }
        }
        listOf(false, true).forEach { dark ->
            listOf(false, true).forEach { contrast ->
                listOf("en", "ckb").forEach { locale ->
                    listOf(1f, 2f).forEach { font ->
                        val next = ViewCase(dark = dark, contrast = contrast, locale = locale, font = font)
                        compose.runOnIdle { case = next.copy(screen = "profile-dialog"); screen = "profiles" }
                        reachable("profile_select_visual-b")
                        compose.onNodeWithTag("profile_select_visual-b").performClick()
                        reachable("profile_confirm_selection")
                        reachable("profile_cancel_selection")
                        capture("dialog", case)
                        compose.onNodeWithTag("profile_cancel_selection").performClick()
                        compose.runOnIdle { case = next.copy(screen = "filter-dialog"); screen = "diagnostics" }
                        reachable("diagnostic_filters")
                        compose.onNodeWithTag("diagnostic_filters").performClick()
                        compose.onNodeWithTag("diagnostic_filter_apply")
                            .assertTextEquals(localized(locale, UiR.string.apply))
                        compose.onNodeWithTag("diagnostic_filter_cancel")
                            .assertTextEquals(localized(locale, UiR.string.cancel))
                        compose.onNodeWithTag("diagnostic_level_all")
                            .assertTextEquals(localized(locale, UiR.string.all_levels))
                        compose.onNodeWithTag("diagnostic_component_all")
                            .assertTextEquals(localized(locale, UiR.string.all_components))
                        compose.onNodeWithText(localized(locale, UiR.string.uiux_level)).assertExists()
                        compose.onNodeWithText(localized(locale, UiR.string.uiux_component)).assertExists()
                        reachable("diagnostic_filter_apply")
                        reachable("diagnostic_filter_cancel")
                        capture("dialog", case)
                        compose.onNodeWithTag("diagnostic_filter_cancel").performClick()
                        compose.runOnIdle { case = next.copy(screen = "destructive"); screen = "recovery" }
                        reachable("reset_scope_settings")
                        compose.onNodeWithTag("reset_scope_settings").performClick()
                        compose.onNodeWithText(localized(next.locale, UiR.string.prepare_reset)).performScrollTo().performClick()
                        compose.onNodeWithText(localized(next.locale, UiR.string.confirm_reset)).performScrollTo()
                            .assertIsDisplayed().assertHeightIsAtLeast(48.dp)
                        compose.onNodeWithText(localized(next.locale, UiR.string.cancel_reset)).performScrollTo()
                            .assertIsDisplayed().assertHeightIsAtLeast(48.dp)
                        capture("confirmation", case)
                    }
                }
            }
        }
    }

    @Test
    fun aToggleChangesOnlyTheDraftAndApplyFiresOnce() {
        var saved by mutableStateOf(TunnelPreferences())
        var applications = 0
        compose.setContent {
            View(ViewCase(font = 2f, locale = "en")) {
                TunnelDnsSettingsScreen(saved, { saved = it; applications++ }, {})
            }
        }
        compose.onNodeWithText(context.getString(UiR.string.treat_vpn_metered)).performScrollTo().performClick()
        compose.runOnIdle { assertFalse(saved.metered); assertEquals(0, applications) }
        reachable("settings_cancel")
        compose.onNodeWithTag("settings_cancel").performClick()
        compose.runOnIdle { assertFalse(saved.metered); assertEquals(0, applications) }
        compose.onNodeWithText(context.getString(UiR.string.treat_vpn_metered)).performScrollTo().performClick()
        reachable("settings_apply")
        compose.onNodeWithTag("settings_apply").performClick()
        compose.runOnIdle { assertTrue(saved.metered); assertEquals(1, applications) }
        compose.onNodeWithTag("settings_apply").assertIsNotEnabled().performClick()
        compose.runOnIdle { assertEquals(1, applications) }
    }

    private fun localized(locale: String, id: Int): String {
        val config = android.content.res.Configuration(context.resources.configuration)
        config.setLocale(java.util.Locale.forLanguageTag(locale))
        return context.createConfigurationContext(config).getString(id)
    }

    @Composable private fun Home() = HomeScreen(AppState.Ready(profiles), settings, VpnRuntimeSnapshot(), {}, {}, {}, {}, {}, {})
    @Composable private fun Profiles(connectionWillStop: Boolean = false) = ProfilesScreen(
        profiles, settings, onImportFile = {}, onImportClipboard = {}, onImportLink = {}, onScanQr = {},
        onExportProfile = { _, _ -> }, onDeleteProfile = {}, onBack = {}, showBack = false,
        connectionWillStopOnSelection = connectionWillStop,
    )
    @Composable private fun Settings() = SettingsIndexScreen(
        settings, capabilities(), {}, {}, {}, {}, {}, {}, {}, {}, showBack = false,
    )
    @Composable private fun Recovery() = SettingsRecoveryScreen(
        BackupWorkflowState.Idle, settings, {}, {}, {}, {}, {}, {}, {}, {}, {},
    )
    @Composable private fun Diagnostics(events: List<DiagnosticEvent> = emptyList(), onClear: () -> Unit = {}) =
        DiagnosticsAboutScreen(DiagnosticWorkflowState.Idle, "visual-fixture", null, events, {}, {}, {}, onClear, {})
    private fun capabilities(): ProductCapabilities {
        fun unavailable(id: String) = ProductCapability(id, false, "Unavailable in synthetic presentation evidence")
        return ProductCapabilities(unavailable("vpn"), unavailable("relay"), unavailable("updates"), unavailable("proxy"), unavailable("hotspot"))
    }
}
