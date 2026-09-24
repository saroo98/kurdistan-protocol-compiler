// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.settingsrecovery

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import org.kurdistanvpn.core.ui.KurdistanOutlinedTextField as OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Switch
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.BackupWorkflowState
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.ProtectedStateMigrationConfirmation
import org.kurdistanvpn.core.model.ProtectedRecoveryConfirmation
import org.kurdistanvpn.core.model.ProtectedRecoveryPresentation
import org.kurdistanvpn.core.model.ResetScope
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.ui.LocalEssentialBoundaryWidth
import org.kurdistanvpn.core.ui.R as UiR


import androidx.compose.foundation.background
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment

@Composable
fun SettingsRecoveryScreen(
    backupState: BackupWorkflowState,
    settings: ProductSettings,
    onTheme: (ThemePreference) -> Unit,
    onHighContrast: (Boolean) -> Unit,
    onReducedMotion: (Boolean) -> Unit,
    onCreateBackup: (String) -> Unit,
    onOpenBackup: (String) -> Unit,
    onConfirmRestore: () -> Unit,
    onCancelRestore: () -> Unit,
    onResetAll: () -> Unit,
    onBack: () -> Unit,
    onResetScope: (ResetScope) -> Unit = { scope ->
        if (scope == ResetScope.EVERYTHING) onResetAll()
    },
    onReviewReset: (ResetScope) -> Unit = {},
    onCancelReset: () -> Unit = {},
    pendingCredentialResetLabel: String? = null,
    pendingCredentialResetHelp: String? = null,
    migrationRequired: Boolean = false,
    migrationLabel: String? = null,
    migrationHelp: String? = null,
    migrationConfirmLabel: String? = null,
    onConfirmMigration: () -> Unit = {},
    protectedRecovery: ProtectedRecoveryPresentation = ProtectedRecoveryPresentation.NotRequired,
    recoveryTitle: String? = null,
    recoveryMessage: String? = null,
    recoveryPrepareLabel: String? = null,
    recoveryConfirmLabel: String? = null,
    recoveryDiagnosticsLabel: String? = null,
    onConfirmPresentationRecovery: () -> Unit = {},
    onOpenDiagnostics: () -> Unit = {},
) {
    var passphrase by remember { mutableStateOf("") }
    var resetArmed by remember { mutableStateOf(false) }
    androidx.compose.runtime.DisposableEffect(Unit) { onDispose { onCancelReset() } }
    var resetScopeName by rememberSaveable { mutableStateOf(ResetScope.EVERYTHING.name) }
    val requestedResetScope = runCatching { ResetScope.valueOf(resetScopeName) }
        .getOrDefault(ResetScope.EVERYTHING)
    val resetScope = if (requestedResetScope == ResetScope.PENDING_CREDENTIALS &&
        (pendingCredentialResetLabel.isNullOrBlank() || pendingCredentialResetHelp.isNullOrBlank())) ResetScope.EVERYTHING else requestedResetScope
    LaunchedEffect(resetScope, requestedResetScope) {
        if (resetScope != requestedResetScope) {
            resetArmed = false
            resetScopeName = resetScope.name
        }
    }
    var migrationConfirmation by remember(migrationRequired) {
        mutableStateOf(ProtectedStateMigrationConfirmation.UNCONFIRMED)
    }
    var recoveryConfirmation by remember(protectedRecovery) {
        mutableStateOf(ProtectedRecoveryConfirmation.UNCONFIRMED)
    }
    val highContrastLabel = stringResource(UiR.string.high_contrast)
    val reducedMotionLabel = stringResource(UiR.string.reduced_motion)
    ProductScreen(stringResource(UiR.string.privacy_recovery), onBack) {
        if (protectedRecovery is ProtectedRecoveryPresentation.Required) {
            val title = checkNotNull(recoveryTitle)
            val message = checkNotNull(recoveryMessage)
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("protected_recovery_status")
                    .semantics { contentDescription = "$title. $message" }
                    .background(MaterialTheme.colorScheme.errorContainer, MaterialTheme.shapes.medium)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(title, style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onErrorContainer)
                Text(message, color = MaterialTheme.colorScheme.onErrorContainer)
                if (protectedRecovery.canRecoverPresentation) {
                    if (!recoveryConfirmation.permits(protectedRecovery)) {
                        RecoveryButton(
                            onClick = {
                                recoveryConfirmation = recoveryConfirmation.prepare(protectedRecovery)
                            },
                            modifier = Modifier.testTag("prepare_presentation_recovery"),
                        ) { Text(checkNotNull(recoveryPrepareLabel)) }
                    } else {
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            RecoveryButton(
                                onClick = {
                                    val confirmed = recoveryConfirmation.permits(protectedRecovery)
                                    recoveryConfirmation = recoveryConfirmation.cancel()
                                    if (confirmed) onConfirmPresentationRecovery()
                                },
                                modifier = Modifier.testTag("confirm_presentation_recovery"),
                            ) { Text(checkNotNull(recoveryConfirmLabel)) }
                            RecoveryTextButton(
                                onClick = { recoveryConfirmation = recoveryConfirmation.cancel() },
                                modifier = Modifier.testTag("cancel_presentation_recovery"),
                            ) { Text(stringResource(UiR.string.cancel)) }
                        }
                    }
                }
                RecoveryTextButton(
                    onClick = onOpenDiagnostics,
                    modifier = Modifier.testTag("open_recovery_diagnostics"),
                ) { Text(checkNotNull(recoveryDiagnosticsLabel)) }
            }
        }
        if (migrationRequired && migrationLabel != null && migrationHelp != null && migrationConfirmLabel != null) {
            Text(migrationHelp)
            if (!migrationConfirmation.permitsMigration(migrationRequired)) {
                RecoveryButton(onClick = { migrationConfirmation = migrationConfirmation.prepare(migrationRequired) },
                    modifier = Modifier.testTag("prepare_protected_state_migration")) { Text(migrationLabel) }
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    RecoveryButton(onClick = {
                        val confirmed = migrationConfirmation.permitsMigration(migrationRequired)
                        migrationConfirmation = migrationConfirmation.cancel()
                        if (confirmed) onConfirmMigration()
                    }, modifier = Modifier.testTag("confirm_protected_state_migration")) { Text(migrationConfirmLabel) }
                    RecoveryTextButton(onClick = { migrationConfirmation = migrationConfirmation.cancel() },
                        modifier = Modifier.testTag("cancel_protected_state_migration")) { Text(stringResource(UiR.string.cancel)) }
                }
            }
        }

        RecoverySection(stringResource(UiR.string.appearance)) {
            AppearanceControls(settings, onTheme, onHighContrast, onReducedMotion)
        }
        RecoverySection(stringResource(UiR.string.uiux_backup_restore)) {
        OutlinedTextField(
            value = passphrase,
            onValueChange = { if (it.encodeToByteArray().size <= 1024) passphrase = it },
            label = { Text(stringResource(UiR.string.backup_passphrase)) },
            supportingText = { Text(stringResource(UiR.string.backup_passphrase_help)) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        RecoveryButton(
            enabled = passphrase.codePointCount(0, passphrase.length) >= 12 &&
                backupState !is BackupWorkflowState.Working,
            onClick = {
                val value = passphrase
                passphrase = ""
                onCreateBackup(value)
            },
        ) {
            Text(stringResource(UiR.string.create_encrypted_backup))
        }
        RecoveryButton(
            enabled = passphrase.isNotEmpty() && backupState !is BackupWorkflowState.Working,
            onClick = {
                val value = passphrase
                passphrase = ""
                onOpenBackup(value)
            },
        ) {
            Text(stringResource(UiR.string.open_backup_restore))
        }
        when (backupState) {
            BackupWorkflowState.Idle -> Unit
            BackupWorkflowState.Working -> Text(stringResource(UiR.string.working_locally))
            is BackupWorkflowState.RestorePreview -> {
                Text(
                    stringResource(
                        UiR.string.restore_preview,
                        backupState.recordCount,
                        backupState.nativeProfileCount,
                    ),
                )
                Text(stringResource(UiR.string.restore_safety))
                RecoveryButton(onClick = onConfirmRestore) {
                    Text(stringResource(UiR.string.confirm_restore))
                }
                RecoveryTextButton(onClick = onCancelRestore) {
                    Text(stringResource(UiR.string.cancel_restore))
                }
            }
            is BackupWorkflowState.Completed ->
                Text(stringResource(UiR.string.restore_complete, backupState.restoredProfiles))
            BackupWorkflowState.Exported -> Text(stringResource(UiR.string.encrypted_backup_saved))
            is BackupWorkflowState.Failed ->
                Text(stringResource(UiR.string.backup_failed,
                    if (backupState.error == org.kurdistanvpn.core.model.OperationError.AUTHORITY_UNAVAILABLE)
                        stringResource(UiR.string.unavailable) else backupState.error.name), color = MaterialTheme.colorScheme.error)
        }
        }
        RecoverySection(stringResource(UiR.string.uiux_remove_reset)) {
        Text(stringResource(UiR.string.reset_limits))
        Text(stringResource(UiR.string.reset_scope), style = MaterialTheme.typography.titleMedium)
        ResetScope.entries.filter { it.unavailableReason == null }.filter { it != ResetScope.PENDING_CREDENTIALS ||
            (!pendingCredentialResetLabel.isNullOrBlank() && !pendingCredentialResetHelp.isNullOrBlank()) }.forEach { scope ->
            val label = when (scope) {
                ResetScope.SETTINGS -> stringResource(UiR.string.reset_scope_settings)
                ResetScope.PROFILES_AND_TRUST -> stringResource(UiR.string.reset_scope_profiles)
                ResetScope.ROUTING -> stringResource(UiR.string.reset_scope_routing)
                ResetScope.DIAGNOSTICS -> stringResource(UiR.string.reset_scope_diagnostics)
                ResetScope.EVERYTHING -> stringResource(UiR.string.reset_scope_everything)
                ResetScope.PENDING_CREDENTIALS -> checkNotNull(pendingCredentialResetLabel)
                ResetScope.LOCAL_CREDENTIALS -> stringResource(UiR.string.unavailable)
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth().heightIn(min = 48.dp)
                    .testTag("reset_scope_${scope.name.lowercase()}")
                    .selectable(
                        selected = resetScope == scope,
                        role = Role.RadioButton,
                        onClick = {
                            onCancelReset()
                            resetScopeName = scope.name
                            resetArmed = false
                        },
                    )
                    .padding(vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = resetScope == scope, onClick = null)
                Text(label, modifier = Modifier.weight(1f))
            }
        }
        if (resetScope == ResetScope.PENDING_CREDENTIALS) {
            Text(checkNotNull(pendingCredentialResetHelp))
        }
        if (!resetArmed || resetScope != requestedResetScope) {
            RecoveryTextButton(onClick = { onReviewReset(resetScope); resetArmed = true }) {
                Text(stringResource(UiR.string.prepare_reset))
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                RecoveryButton(
                    destructive = true,
                    onClick = {
                        val confirmed = resetArmed && (resetScope != ResetScope.PENDING_CREDENTIALS ||
                            (!pendingCredentialResetLabel.isNullOrBlank() && !pendingCredentialResetHelp.isNullOrBlank()))
                        resetArmed = false
                        passphrase = ""
                        if (confirmed) onResetScope(resetScope)
                    },
                ) { Text(stringResource(UiR.string.confirm_reset)) }
                RecoveryTextButton(onClick = { resetArmed = false; onCancelReset() }) {
                    Text(stringResource(UiR.string.cancel_reset))
                }
            }
        }
        }
        RecoverySection(stringResource(UiR.string.uiux_privacy)) {
        Text(stringResource(UiR.string.telemetry_off))
        Text(stringResource(UiR.string.crash_reporting_off))
        Text(stringResource(UiR.string.profiles_encrypted))
        Text(stringResource(UiR.string.cloud_backup_disabled))
        }
    }
}

@Composable
private fun RecoverySection(title: String, content: @Composable () -> Unit) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(title, style = MaterialTheme.typography.titleLarge)
        content()
    }
}

@Composable
private fun RecoveryButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    destructive: Boolean = false,
    content: @Composable RowScope.() -> Unit,
) {
    val colors = if (destructive) ButtonDefaults.buttonColors(
        containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError,
        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
    ) else ButtonDefaults.buttonColors(
        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant)
    Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), onClick = { if (enabled) onClick() }, enabled = enabled,
        modifier = modifier.fillMaxWidth().heightIn(min = 56.dp), shape = MaterialTheme.shapes.small, colors = colors, content = content)
}

@Composable
private fun RecoveryTextButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable RowScope.() -> Unit,
) {
    TextButton(onClick = onClick, modifier = modifier.fillMaxWidth().heightIn(min = 48.dp), content = content)
}


@Composable
internal fun AppearanceControls(settings: ProductSettings, onTheme: (ThemePreference) -> Unit,
    onHighContrast: (Boolean) -> Unit, onReducedMotion: (Boolean) -> Unit) {
    val highContrastLabel = stringResource(UiR.string.high_contrast)
    val reducedMotionLabel = stringResource(UiR.string.reduced_motion)

            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ThemePreference.entries.forEach { theme ->
                    val label = stringResource(when (theme) {
                        ThemePreference.SYSTEM -> UiR.string.uiux_theme_system
                        ThemePreference.LIGHT -> UiR.string.uiux_theme_light
                        ThemePreference.DARK -> UiR.string.uiux_theme_dark
                    })
                    FilterChip(border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), selected = settings.theme == theme, onClick = { onTheme(theme) },
                        label = { Text(label) }, modifier = Modifier.heightIn(min = 48.dp).testTag("theme_${theme.name}"))
                }
            }
        androidx.compose.foundation.layout.Row(
            modifier = Modifier
                .fillMaxWidth().heightIn(min = 56.dp)
                .semantics { contentDescription = highContrastLabel }
                .toggleable(
                    value = settings.highContrast,
                    role = Role.Switch,
                    onValueChange = onHighContrast,
                )
                .padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                highContrastLabel,
                modifier = Modifier.weight(1f),
            )
            Switch(
                checked = settings.highContrast,
                onCheckedChange = null,
            )
        }
        androidx.compose.foundation.layout.Row(
            modifier = Modifier
                .fillMaxWidth().heightIn(min = 56.dp)
                .semantics { contentDescription = reducedMotionLabel }
                .toggleable(
                    value = settings.reducedMotion,
                    role = Role.Switch,
                    onValueChange = onReducedMotion,
                )
                .padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                reducedMotionLabel,
                modifier = Modifier.weight(1f),
            )
            Switch(
                checked = settings.reducedMotion,
                onCheckedChange = null,
            )
        }
}
