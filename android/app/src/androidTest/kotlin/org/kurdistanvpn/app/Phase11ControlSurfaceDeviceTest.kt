// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.espresso.IdlingPolicies
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.BackupWorkflowState
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.EnrollmentKeySummary
import org.kurdistanvpn.core.model.EnrollmentUiState
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.model.ProfileTrust
import org.kurdistanvpn.core.model.ProfilePreferences
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.model.ResetScope
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.ui.R as UiR
import org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsAboutScreen
import org.kurdistanvpn.feature.home.HomeScreen
import org.kurdistanvpn.feature.profiles.ProfilesScreen
import org.kurdistanvpn.feature.profiles.ImportPreviewScreen
import org.kurdistanvpn.feature.settingsrecovery.SettingsRecoveryScreen
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class Phase11ControlSurfaceDeviceTest {
    @get:Rule
    val compose = createComposeRule()

    private val context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun configureHostedEmulatorIdlingBudget() {
        IdlingPolicies.setMasterPolicyTimeout(2, TimeUnit.MINUTES)
        IdlingPolicies.setIdlingResourceTimeout(2, TimeUnit.MINUTES)
    }

    @Test
    fun homeInvokesEveryExposedControl() {
        val profile = ProfileSummary(
            localRecordId = "phase13-home-profile",
            displayAlias = "Phase 13 home profile",
            trust = ProfileTrust.VERIFIED_NONPRODUCTION,
            generation = 7u,
            expiresAtEpochSeconds = 2_000_000_000,
        )
        var appState by mutableStateOf<AppState>(AppState.Ready(listOf(profile)))
        var runtime by mutableStateOf(VpnRuntimeSnapshot())
        val invoked = linkedMapOf<String, Int>()
        fun record(name: String) {
            invoked[name] = invoked.getOrDefault(name, 0) + 1
        }

        compose.setContent {
            HomeScreen(
                state = appState,
                settings = Phase9Settings(profiles = ProfilePreferences(activeLocalRecordId = profile.localRecordId)),
                vpnRuntime = runtime,
                onStartVpn = {
                    record("start")
                    runtime = VpnRuntimeSnapshot(VpnRuntimeState.ACTIVE_KURD_LOOPBACK)
                },
                onStopVpn = {
                    record("stop")
                    runtime = VpnRuntimeSnapshot()
                },
                onOpenProfiles = { record("profiles") },
                onOpenSettings = { record("settings") },
                onOpenDiagnostics = { record("diagnostics") },
                onClearError = {
                    record("dismiss")
                    appState = AppState.Ready(emptyList())
                },
            )
        }

        compose.onNodeWithText(context.getString(UiR.string.connect))
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.disconnect))
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithTag("home_profiles")
            .performScrollTo()
            .performClick()
        compose.onNodeWithTag("home_settings")
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.diagnostics_about))
            .performScrollTo()
            .performClick()
        compose.runOnIdle {
            appState = AppState.ImportRejected(OperationError.TRUST_REJECTED)
        }
        compose.onNodeWithText(context.getString(UiR.string.dismiss))
            .performScrollTo()
            .performClick()

        compose.runOnIdle {
            assertEquals(
                mapOf(
                    "start" to 1,
                    "stop" to 1,
                    "profiles" to 1,
                    "settings" to 1,
                    "diagnostics" to 1,
                    "dismiss" to 1,
                ),
                invoked,
            )
        }
    }

    @Test
    fun profilesInvokesEveryExposedControlAndConfirmationBranch() {
        val profile = ProfileSummary(
            localRecordId = "phase11-control-profile",
            displayAlias = "Phase 11 control profile",
            trust = ProfileTrust.VERIFIED_NONPRODUCTION,
            generation = 7u,
            expiresAtEpochSeconds = 2_000_000_000,
        )
        val invoked = linkedMapOf<String, Int>()
        var importedLink = ""
        var exportedID = ""
        var exportedPassphrase = ""
        var deletedID = ""
        fun record(name: String) {
            invoked[name] = invoked.getOrDefault(name, 0) + 1
        }

        compose.setContent {
            ProfilesScreen(
                profiles = listOf(profile),
                onImportFile = { record("file") },
                onImportClipboard = { record("clipboard") },
                onImportLink = {
                    record("link")
                    importedLink = it
                },
                onScanQr = { record("qr") },
                onExportProfile = { id, passphrase ->
                    record("export")
                    exportedID = id
                    exportedPassphrase = passphrase
                },
                onDeleteProfile = {
                    record("delete")
                    deletedID = it
                },
                onBack = { record("back") },
            )
        }

        compose.onNodeWithText(context.getString(UiR.string.import_profile_file))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.import_clipboard))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.scan_offline_qr))
            .performScrollTo()
            .performClick()
        val link = "kurd://artifact/phase11-control"
        compose.onNodeWithText(context.getString(UiR.string.profile_link_label))
            .performScrollTo()
            .performTextInput(link)
        compose.onNodeWithText(context.getString(UiR.string.preview_link))
            .performScrollTo()
            .performClick()

        compose.onNodeWithText(context.getString(UiR.string.export_encrypted_profile))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.cancel))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.export_encrypted_profile))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.profile_export_passphrase))
            .performScrollTo()
            .performTextInput("phase11-passphrase")
        compose.onNodeWithText(context.getString(UiR.string.confirm_profile_export))
            .performScrollTo()
            .performClick()

        compose.onNodeWithText(context.getString(UiR.string.delete_profile))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.cancel))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.delete_profile))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.confirm_delete_profile))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.back))
            .performScrollTo()
            .performClick()

        compose.runOnIdle {
            assertEquals(link, importedLink)
            assertEquals(profile.localRecordId, exportedID)
            assertEquals("phase11-passphrase", exportedPassphrase)
            assertEquals(profile.localRecordId, deletedID)
            assertEquals(
                mapOf(
                    "file" to 1,
                    "clipboard" to 1,
                    "qr" to 1,
                    "link" to 1,
                    "export" to 1,
                    "delete" to 1,
                    "back" to 1,
                ),
                invoked,
            )
        }
    }

    @Test
    fun enrollmentRequiresExplicitPublicExportConfirmationAndNeverShowsPrivateMaterial() {
        val key = EnrollmentKeySummary(
            localRecordId = "recipient-local-1",
            requestFingerprint = "0123456789abcdef0123456789abcdef",
            createdAtEpochSeconds = 1_800_000_000,
            expiresAtEpochSeconds = 1_800_086_400,
            boundProfileCount = 0,
        )
        var state by mutableStateOf<EnrollmentUiState>(EnrollmentUiState.NoEnrollmentKey)
        var created = 0
        var exported = ""
        var qr = ""
        compose.setContent {
            ProfilesScreen(
                profiles = emptyList(),
                enrollmentState = state,
                onCreateEnrollment = {
                    created++
                    state = EnrollmentUiState.RequestReady(listOf(key))
                },
                onExportEnrollment = { exported = it },
                onShowEnrollmentQr = { qr = it },
                onImportFile = {},
                onImportClipboard = {},
                onImportLink = {},
                onScanQr = {},
                onExportProfile = { _, _ -> },
                onDeleteProfile = {},
                onBack = {},
            )
        }

        compose.onNodeWithTag("create_enrollment_request").performClick()
        compose.onNodeWithText(context.getString(UiR.string.device_enrollment_export_file))
            .performScrollTo().performClick()
        compose.onNodeWithText(context.getString(UiR.string.device_enrollment_public_export_warning))
            .assertIsDisplayed()
        compose.onNodeWithText(context.getString(UiR.string.confirm))
            .performScrollTo().performClick()
        compose.onNodeWithText(context.getString(UiR.string.device_enrollment_show_qr))
            .performScrollTo().performClick()
        compose.onNodeWithText(context.getString(UiR.string.confirm))
            .performScrollTo().performClick()

        compose.runOnIdle {
            assertEquals(1, created)
            assertEquals(key.localRecordId, exported)
            assertEquals(key.localRecordId, qr)
        }
        compose.onNodeWithText("private-enrollment-canary", substring = true)
            .assertDoesNotExist()
    }

    @Test
    fun selfHostedFirstTrustShowsDeploymentAuthorityBeforeConfirmation() {
        var confirmed = 0
        var cancelled = 0
        val fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        compose.setContent {
            ImportPreviewScreen(
                preview = RedactedProfilePreview(
                    artifactClass = "signed-public",
                    audienceClass = "public",
                    contentFingerprint = "abcdef0123456789",
                    lineageFingerprint = "lineage-01234567",
                    generation = 7u,
                    validUntilEpochSeconds = 2_000_000_000,
                    sealed = false,
                    deploymentFingerprint = fingerprint,
                    relayEndpointSummary = "owner-node.example:443",
                    authorityScope = "deployment-local",
                    updateLocation = "",
                    ownerControlled = true,
                    updatesEnabled = false,
                ),
                onConfirm = { confirmed++ },
                onCancel = { cancelled++ },
            )
        }

        compose.onNodeWithTag("deployment_fingerprint")
            .assertIsDisplayed()
        compose.onNodeWithTag("owner_controlled_source_warning")
            .assertIsDisplayed()
        compose.onNodeWithText(context.getString(UiR.string.profile_updates_disabled))
            .assertIsDisplayed()
        compose.onNodeWithText(context.getString(UiR.string.confirm_encrypted_storage))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.cancel))
            .performScrollTo()
            .performClick()
        compose.runOnIdle {
            assertEquals(1, confirmed)
            assertEquals(1, cancelled)
        }
    }

    @Test
    fun settingsAndRecoveryInvokeEveryExposedControlAndBranch() {
        var backupState by mutableStateOf<BackupWorkflowState>(BackupWorkflowState.Idle)
        var settings by mutableStateOf(Phase9Settings())
        val invoked = linkedMapOf<String, Int>()
        fun record(name: String) {
            invoked[name] = invoked.getOrDefault(name, 0) + 1
        }

        compose.setContent {
            SettingsRecoveryScreen(
                backupState = backupState,
                settings = settings,
                onTheme = {
                    record("theme")
                    settings = settings.copy(theme = it)
                },
                onHighContrast = {
                    record("contrast")
                    settings = settings.copy(highContrast = it)
                },
                onReducedMotion = {
                    record("motion")
                    settings = settings.copy(reducedMotion = it)
                },
                onCreateBackup = { record("create-backup") },
                onOpenBackup = {
                    record("open-backup")
                    backupState = BackupWorkflowState.RestorePreview(1, 1)
                },
                onConfirmRestore = {
                    record("confirm-restore")
                    backupState = BackupWorkflowState.Completed(1)
                },
                onCancelRestore = {
                    record("cancel-restore")
                    backupState = BackupWorkflowState.Idle
                },
                onResetAll = { record("reset") },
                onResetScope = { record("reset-${it.name.lowercase()}") },
                onBack = { record("back") },
            )
        }

        compose.onNodeWithText(
            context.getString(UiR.string.theme_value, ThemePreference.SYSTEM.name),
        ).performClick()
        val highContrast = context.getString(UiR.string.high_contrast)
        compose.onNodeWithContentDescription(highContrast)
            .performScrollTo()
            .performClick()
        val reducedMotion = context.getString(UiR.string.reduced_motion)
        compose.onNodeWithContentDescription(reducedMotion)
            .performScrollTo()
            .performClick()

        compose.onNodeWithText(context.getString(UiR.string.backup_passphrase))
            .performScrollTo()
            .performTextInput("phase11-passphrase")
        compose.onNodeWithText(context.getString(UiR.string.create_encrypted_backup))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.backup_passphrase))
            .performScrollTo()
            .performTextInput("phase11-passphrase")
        compose.onNodeWithText(context.getString(UiR.string.open_backup_restore))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.cancel_restore))
            .performScrollTo()
            .performClick()

        compose.runOnIdle {
            backupState = BackupWorkflowState.RestorePreview(1, 1)
        }
        compose.onNodeWithText(context.getString(UiR.string.confirm_restore))
            .performScrollTo()
            .performClick()

        compose.onNodeWithText(context.getString(UiR.string.prepare_reset))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.cancel_reset))
            .performScrollTo()
            .performClick()
        compose.onNodeWithTag("reset_scope_${ResetScope.SETTINGS.name.lowercase()}")
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.prepare_reset))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.confirm_reset))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.back))
            .performScrollTo()
            .performClick()

        compose.runOnIdle {
            assertEquals(ThemePreference.LIGHT, settings.theme)
            assertTrue(settings.highContrast)
            assertTrue(settings.reducedMotion)
            assertEquals(
                mapOf(
                    "theme" to 1,
                    "contrast" to 1,
                    "motion" to 1,
                    "create-backup" to 1,
                    "open-backup" to 1,
                    "cancel-restore" to 1,
                    "confirm-restore" to 1,
                    "reset-settings" to 1,
                    "back" to 1,
                ),
                invoked,
            )
        }
    }

    @Test
    fun diagnosticsInvokePrepareCancelConfirmAndBack() {
        var state by mutableStateOf<DiagnosticWorkflowState>(DiagnosticWorkflowState.Idle)
        val invoked = linkedMapOf<String, Int>()
        fun record(name: String) {
            invoked[name] = invoked.getOrDefault(name, 0) + 1
        }

        compose.setContent {
            DiagnosticsAboutScreen(
                state = state,
                appVersion = "phase11-control",
                compatibility = null,
                events = emptyList(),
                onPrepare = {
                    record("prepare")
                    state = DiagnosticWorkflowState.Preview(1, "1", "1")
                },
                onConfirm = {
                    record("confirm")
                    state = DiagnosticWorkflowState.Completed
                },
                onCancel = {
                    record("cancel")
                    state = DiagnosticWorkflowState.Idle
                },
                onClearEvents = {},
                onBack = { record("back") },
            )
        }

        compose.onNodeWithText(context.getString(UiR.string.prepare_diagnostics))
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.cancel))
            .performScrollTo()
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.prepare_diagnostics))
            .performClick()
        compose.onNodeWithText(context.getString(UiR.string.confirm_export))
            .performScrollTo()
            .performClick()
        compose.runOnIdle {
            state = DiagnosticWorkflowState.Idle
        }
        compose.onNodeWithText(context.getString(UiR.string.back))
            .performScrollTo()
            .performClick()

        compose.runOnIdle {
            assertEquals(
                mapOf(
                    "prepare" to 2,
                    "cancel" to 1,
                    "confirm" to 1,
                    "back" to 1,
                ),
                invoked,
            )
        }
    }
}
