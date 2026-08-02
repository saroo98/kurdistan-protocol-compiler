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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.CompatibilitySummary
import org.kurdistanvpn.core.ui.R as UiR

@Composable
fun DiagnosticsAboutScreen(
    state: DiagnosticWorkflowState,
    appVersion: String,
    compatibility: CompatibilitySummary?,
    events: List<DiagnosticEvent>,
    onPrepare: () -> Unit,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
    onClearEvents: () -> Unit,
    onBack: () -> Unit,
) {
    var selectedLevel by remember { mutableStateOf<DiagnosticLogLevel?>(null) }
    var selectedComponent by remember { mutableStateOf<DiagnosticComponent?>(null) }
    val visibleEvents = events.filter { event ->
        (selectedLevel == null || event.level == selectedLevel) &&
            (selectedComponent == null || event.component == selectedComponent)
    }.takeLast(50).asReversed()
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
        Text(stringResource(UiR.string.local_diagnostic_events), style = MaterialTheme.typography.titleLarge)
        Text(stringResource(UiR.string.local_diagnostic_privacy))
        androidx.compose.foundation.layout.FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = selectedLevel == null, onClick = { selectedLevel = null }, label = { Text(stringResource(UiR.string.all_levels)) })
            DiagnosticLogLevel.entries.filter { it != DiagnosticLogLevel.NONE }.forEach { level ->
                FilterChip(selected = selectedLevel == level, onClick = { selectedLevel = level }, label = { Text(level.name) })
            }
        }
        androidx.compose.foundation.layout.FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = selectedComponent == null, onClick = { selectedComponent = null }, label = { Text(stringResource(UiR.string.all_components)) })
            DiagnosticComponent.entries.forEach { component ->
                FilterChip(selected = selectedComponent == component, onClick = { selectedComponent = component }, label = { Text(component.name) })
            }
        }
        Text(stringResource(UiR.string.diagnostic_event_count, visibleEvents.size, events.size))
        if (visibleEvents.isEmpty()) {
            Text(stringResource(UiR.string.no_matching_diagnostic_events))
        } else {
            visibleEvents.forEach { event ->
                Text(
                    "${event.sequence} · ${event.level.name} · ${event.component.name} · ${event.category}",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.testTag("diagnostic_event_${event.sequence}"),
                )
            }
        }
        OutlinedButton(onClick = onClearEvents, enabled = events.isNotEmpty(), modifier = Modifier.testTag("diagnostic_clear")) {
            Text(stringResource(UiR.string.clear_local_diagnostic_events))
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
