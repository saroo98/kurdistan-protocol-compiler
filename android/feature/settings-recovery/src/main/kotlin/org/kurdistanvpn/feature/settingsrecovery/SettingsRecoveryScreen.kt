// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.settingsrecovery

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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Switch
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.BackupWorkflowState
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ResetScope
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.ui.R as UiR

@Composable
fun SettingsRecoveryScreen(
    backupState: BackupWorkflowState,
    settings: Phase9Settings,
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
) {
    var passphrase by remember { mutableStateOf("") }
    var resetArmed by remember { mutableStateOf(false) }
    var resetScope by remember { mutableStateOf(ResetScope.EVERYTHING) }
    val highContrastLabel = stringResource(UiR.string.high_contrast)
    val reducedMotionLabel = stringResource(UiR.string.reduced_motion)
    Column(
        modifier = Modifier
            .fillMaxSize()
            .widthIn(max = 720.dp)
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(UiR.string.privacy_recovery), style = MaterialTheme.typography.headlineMedium)
        Text(stringResource(UiR.string.telemetry_off))
        Text(stringResource(UiR.string.crash_reporting_off))
        Text(stringResource(UiR.string.profiles_encrypted))
        Text(stringResource(UiR.string.cloud_backup_disabled))
        Text(stringResource(UiR.string.appearance))
        Button(
            onClick = {
                onTheme(
                    when (settings.theme) {
                        ThemePreference.SYSTEM -> ThemePreference.LIGHT
                        ThemePreference.LIGHT -> ThemePreference.DARK
                        ThemePreference.DARK -> ThemePreference.SYSTEM
                    },
                )
            },
        ) {
            Text(stringResource(UiR.string.theme_value, settings.theme.name))
        }
        androidx.compose.foundation.layout.Row(
            modifier = Modifier
                .fillMaxWidth()
                .semantics { contentDescription = highContrastLabel }
                .toggleable(
                    value = settings.highContrast,
                    role = Role.Switch,
                    onValueChange = onHighContrast,
                )
                .padding(vertical = 8.dp),
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
                .fillMaxWidth()
                .semantics { contentDescription = reducedMotionLabel }
                .toggleable(
                    value = settings.reducedMotion,
                    role = Role.Switch,
                    onValueChange = onReducedMotion,
                )
                .padding(vertical = 8.dp),
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
        OutlinedTextField(
            value = passphrase,
            onValueChange = { if (it.encodeToByteArray().size <= 1024) passphrase = it },
            label = { Text(stringResource(UiR.string.backup_passphrase)) },
            supportingText = { Text(stringResource(UiR.string.backup_passphrase_help)) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
        )
        Button(
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
        Button(
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
                Button(onClick = onConfirmRestore) {
                    Text(stringResource(UiR.string.confirm_restore))
                }
                TextButton(onClick = onCancelRestore) {
                    Text(stringResource(UiR.string.cancel_restore))
                }
            }
            is BackupWorkflowState.Completed ->
                Text(stringResource(UiR.string.restore_complete, backupState.restoredProfiles))
            is BackupWorkflowState.Failed ->
                Text(stringResource(UiR.string.backup_failed, backupState.error.name))
        }
        Text(stringResource(UiR.string.reset_limits))
        Text(stringResource(UiR.string.reset_scope), style = MaterialTheme.typography.titleMedium)
        ResetScope.entries.forEach { scope ->
            val label = when (scope) {
                ResetScope.SETTINGS -> stringResource(UiR.string.reset_scope_settings)
                ResetScope.PROFILES_PROVIDERS -> stringResource(UiR.string.reset_scope_profiles)
                ResetScope.ROUTING -> stringResource(UiR.string.reset_scope_routing)
                ResetScope.DIAGNOSTICS -> stringResource(UiR.string.reset_scope_diagnostics)
                ResetScope.EVERYTHING -> stringResource(UiR.string.reset_scope_everything)
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("reset_scope_${scope.name.lowercase()}")
                    .selectable(
                        selected = resetScope == scope,
                        role = Role.RadioButton,
                        onClick = {
                            resetScope = scope
                        },
                    )
                    .padding(vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                RadioButton(selected = resetScope == scope, onClick = null)
                Text(label)
            }
        }
        if (!resetArmed) {
            TextButton(onClick = { resetArmed = true }) {
                Text(stringResource(UiR.string.prepare_reset))
            }
        } else {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        resetArmed = false
                        passphrase = ""
                        onResetScope(resetScope)
                    },
                ) { Text(stringResource(UiR.string.confirm_reset)) }
                TextButton(onClick = { resetArmed = false }) {
                    Text(stringResource(UiR.string.cancel_reset))
                }
            }
        }
        TextButton(onClick = onBack) { Text(stringResource(UiR.string.back)) }
    }
}
