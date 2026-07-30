// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.diagnosticsabout

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.CompatibilitySummary
import org.kurdistanvpn.core.ui.R as UiR

@Composable
fun DiagnosticsAboutScreen(
    state: DiagnosticWorkflowState,
    appVersion: String,
    compatibility: CompatibilitySummary?,
    onPrepare: () -> Unit,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
    onBack: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().widthIn(max = 720.dp).verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(UiR.string.diagnostics_about), style = MaterialTheme.typography.headlineMedium)
        Text(stringResource(UiR.string.bridge_check))
        Text(stringResource(UiR.string.phase11_runtime_scope))
        Text(stringResource(UiR.string.app_version, appVersion))
        compatibility?.let { value ->
            Text(stringResource(UiR.string.core_version, value.goCoreVersion))
            Text(stringResource(UiR.string.profile_schema_version, value.profileSchema))
            Text(stringResource(UiR.string.strategy_registry_version, value.strategyRegistry))
            Text(stringResource(UiR.string.relay_schema_version, value.relaySchema))
            Text(stringResource(UiR.string.diagnostic_schema_version, value.diagnosticSchema))
            Text(stringResource(UiR.string.crypto_suite_version, value.cryptoSuite))
        }
        Text(stringResource(UiR.string.diagnostic_confirmation))
        when (state) {
            DiagnosticWorkflowState.Idle ->
                Button(onClick = onPrepare) {
                    Text(stringResource(UiR.string.prepare_diagnostics))
                }
            DiagnosticWorkflowState.Working ->
                Text(stringResource(UiR.string.preparing_locally))
            is DiagnosticWorkflowState.Preview -> {
                Text(
                    stringResource(
                        UiR.string.diagnostic_preview,
                        state.categoryCount,
                        state.entryCount,
                        state.encodedSize,
                    ),
                )
                Text(stringResource(UiR.string.diagnostic_privacy))
                Button(onClick = onConfirm) { Text(stringResource(UiR.string.confirm_export)) }
                TextButton(onClick = onCancel) { Text(stringResource(UiR.string.cancel)) }
            }
            DiagnosticWorkflowState.Completed ->
                Text(stringResource(UiR.string.diagnostic_exported))
            is DiagnosticWorkflowState.Failed ->
                Text(stringResource(UiR.string.diagnostic_failed, state.error.name))
        }
        TextButton(onClick = onBack) { Text(stringResource(UiR.string.back)) }
    }
}
