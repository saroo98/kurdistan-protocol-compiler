// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.DeviceConfigurationOverride
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.FontScale
import androidx.compose.ui.test.Locales
import androidx.compose.ui.test.WindowSize
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.accessibility.disableAccessibilityChecks
import androidx.compose.ui.test.junit4.accessibility.enableAccessibilityChecks
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.then
import androidx.compose.ui.test.tryPerformAccessibilityChecks
import androidx.compose.ui.text.intl.LocaleList
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.ConnectionPreferences
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.OperatorClientProjection
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProductCapabilities
import org.kurdistanvpn.core.model.ProductCapability
import org.kurdistanvpn.core.model.ProjectionStatus
import org.kurdistanvpn.core.model.SelectionMode
import org.kurdistanvpn.core.ui.R as UiR
import org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsAboutScreen
import org.kurdistanvpn.feature.profiles.OperatorProviderScreen
import org.kurdistanvpn.feature.settingsrecovery.ConnectionSettingsScreen
import org.kurdistanvpn.feature.settingsrecovery.SettingsIndexScreen

class Phase13ProductSurfaceDeviceTest {
    @get:Rule
    val compose = createComposeRule()

    private val context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun settingsIndexRoutesEveryProductAreaAndReportsBoundaries() {
        val invoked = linkedSetOf<String>()
        compose.setContent {
            SettingsIndexScreen(
                settings = Phase9Settings(),
                capabilities = unavailableCapabilities(),
                onConnection = { invoked += "connection" },
                onTunnelDns = { invoked += "tunnel" },
                onRouting = { invoked += "routing" },
                onUpdatesProbes = { invoked += "updates" },
                onExpert = { invoked += "expert" },
                onPrivacyRecovery = { invoked += "privacy" },
                onDiagnostics = { invoked += "diagnostics" },
                onBack = { invoked += "back" },
            )
        }

        listOf(
            UiR.string.open_connection_settings,
            UiR.string.open_tunnel_dns,
            UiR.string.open_routing,
            UiR.string.open_updates_probes,
            UiR.string.open_privacy_recovery,
            UiR.string.open_diagnostics_about,
            UiR.string.open_expert_controls,
            UiR.string.back,
        ).forEach { resource ->
            compose.onNodeWithText(context.getString(resource)).performScrollTo().performClick()
        }
        compose.runOnIdle {
            assertEquals(
                setOf("connection", "tunnel", "routing", "updates", "privacy", "diagnostics", "expert", "back"),
                invoked,
            )
        }
    }

    @Test
    fun settingsSearchFiltersLocallyAndRestoresTheCompleteIndex() {
        compose.setContent { settingsIndex() }

        compose.onNodeWithTag("settings_search").performTextInput("diagnostics")
        compose.onNodeWithTag("settings_diagnostics").assertIsDisplayed()
        compose.onNodeWithTag("settings_connection").assertDoesNotExist()

        compose.onNodeWithTag("settings_search").performTextClearance()
        compose.onNodeWithTag("settings_connection").assertIsDisplayed()
        compose.onNodeWithTag("settings_expert").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun connectionDraftDoesNotPersistUntilApplyAndRecoverInternetIsExplicit() {
        val current = mutableStateOf(ConnectionPreferences())
        var recovered = false
        compose.setContent {
            ConnectionSettingsScreen(
                value = current.value,
                onChange = { current.value = it },
                onRecoverInternet = { recovered = true },
                onBack = {},
            )
        }

        compose.onNodeWithText(SelectionMode.KURD_ONLY.name).performClick()
        compose.runOnIdle { assertEquals(SelectionMode.AUTOMATIC, current.value.selectionMode) }
        compose.onNodeWithTag("safe_reconnect_available").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(context.getString(UiR.string.apply)).performScrollTo().performClick()
        compose.runOnIdle { assertEquals(SelectionMode.KURD_ONLY, current.value.selectionMode) }
        compose.onNodeWithText(context.getString(UiR.string.recover_internet_stop_vpn))
            .performScrollTo().performClick()
        compose.runOnIdle { assertFalse(!recovered) }
    }

    @Test
    fun diagnosticsFilterAndClearOperateOnBoundedCategoricalEvents() {
        var cleared = false
        val events = listOf(
            DiagnosticEvent(1, DiagnosticLogLevel.WARNING, DiagnosticComponent.RUNTIME, "RUNTIME_STOPPED"),
            DiagnosticEvent(2, DiagnosticLogLevel.ERROR, DiagnosticComponent.STORAGE, "STORAGE_FAILURE"),
        )
        compose.setContent {
            DiagnosticsAboutScreen(
                state = DiagnosticWorkflowState.Idle,
                appVersion = "phase13-test",
                compatibility = null,
                events = events,
                onPrepare = {},
                onConfirm = {},
                onCancel = {},
                onClearEvents = { cleared = true },
                onBack = {},
            )
        }

        compose.onNodeWithText(DiagnosticLogLevel.ERROR.name).performScrollTo().performClick()
        compose.onNodeWithText("2 · ERROR · STORAGE · STORAGE_FAILURE").assertIsDisplayed()
        compose.onNodeWithText("1 · WARNING · RUNTIME · RUNTIME_STOPPED").assertDoesNotExist()
        compose.onNodeWithText(context.getString(UiR.string.clear_local_diagnostic_events))
            .performScrollTo().performClick()
        compose.runOnIdle { assertFalse(!cleared) }
    }

    @Test
    fun operatorProjectionIsReadOnlyAndUnavailableEvidenceIsTruthful() {
        compose.setContent {
            OperatorProviderScreen(
                projection = OperatorClientProjection(
                    providerAlias = "No verified provider",
                    publicationGeneration = null,
                    profileGeneration = null,
                    profileExpiryEpochSeconds = null,
                    relayCompatibility = ProjectionStatus.UNAVAILABLE,
                    rotationState = ProjectionStatus.UNAVAILABLE,
                    updateCapability = ProjectionStatus.UNAVAILABLE,
                    lastVerifiedUpdateCategory = null,
                    emergencyDenyState = ProjectionStatus.UNAVAILABLE,
                ),
                onBack = {},
            )
        }

        compose.onNodeWithText(context.getString(UiR.string.provider_publication_unavailable))
            .performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(context.getString(UiR.string.operator_private_data_boundary))
            .performScrollTo().assertIsDisplayed()
    }

    @OptIn(ExperimentalTestApi::class)
    @SdkSuppress(minSdkVersion = 34)
    @Test
    fun api34AutomatedAccessibilityChecksPassForPrimarySettingsSurface() {
        compose.setContent { settingsIndex() }
        assertAccessibilityAtIdle()

        compose.onNodeWithTag("settings_expert").performScrollTo()
        assertAccessibilityAtIdle()
    }

    @OptIn(ExperimentalTestApi::class)
    private fun assertAccessibilityAtIdle() {
        compose.waitForIdle()
        compose.enableAccessibilityChecks()
        try {
            compose.onRoot().tryPerformAccessibilityChecks()
        } finally {
            compose.disableAccessibilityChecks()
        }
    }

    @Test
    fun twoHundredPercentTextAndTabletLandscapeRemainScrollable() {
        compose.setContent {
            DeviceConfigurationOverride(
                DeviceConfigurationOverride.FontScale(2f) then
                    DeviceConfigurationOverride.WindowSize(DpSize(1280.dp, 800.dp)),
            ) {
                settingsIndex()
            }
        }
        compose.onNodeWithTag("settings_connection").assertIsDisplayed()
        compose.onNodeWithTag("settings_expert").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun pseudoEnglishResourcesRemainReachableAtLargeText() {
        compose.setContent {
            DeviceConfigurationOverride(
                DeviceConfigurationOverride.Locales(LocaleList("en-XA")) then
                    DeviceConfigurationOverride.FontScale(2f) then
                    DeviceConfigurationOverride.WindowSize(DpSize(412.dp, 915.dp)),
            ) {
                settingsIndex()
            }
        }
        compose.onNodeWithText(context.getString(UiR.string.open_connection_settings))
            .assertDoesNotExist()
        compose.onNodeWithTag("settings_connection").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("settings_expert").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun pseudoRtlResourcesRemainReachableAtLargeText() {
        compose.setContent {
            DeviceConfigurationOverride(
                DeviceConfigurationOverride.Locales(LocaleList("ar-XB")) then
                    DeviceConfigurationOverride.FontScale(2f) then
                    DeviceConfigurationOverride.WindowSize(DpSize(412.dp, 915.dp)),
            ) {
                settingsIndex()
            }
        }
        compose.onNodeWithText(context.getString(UiR.string.open_connection_settings))
            .assertDoesNotExist()
        compose.onNodeWithTag("settings_connection").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("settings_expert").performScrollTo().assertIsDisplayed()
    }

    @androidx.compose.runtime.Composable
    private fun settingsIndex() {
        SettingsIndexScreen(
            settings = Phase9Settings(),
            capabilities = unavailableCapabilities(),
            onConnection = {},
            onTunnelDns = {},
            onRouting = {},
            onUpdatesProbes = {},
            onExpert = {},
            onPrivacyRecovery = {},
            onDiagnostics = {},
            onBack = {},
        )
    }

    private fun unavailableCapabilities(): ProductCapabilities {
        fun unavailable(id: String) = ProductCapability(id, false, "Unavailable in local Phase 13 evidence")
        return ProductCapabilities(
            vpnRuntime = unavailable("vpn-runtime"),
            publicRelay = unavailable("public-relay"),
            providerNetworkUpdates = unavailable("provider-updates"),
            localProxy = unavailable("local-proxy"),
            hotspotProxy = unavailable("hotspot-proxy"),
        )
    }
}
