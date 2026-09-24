// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.diagnosticsabout

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.CompatibilitySummary
import org.kurdistanvpn.core.ui.LocalEssentialBoundaryWidth
import org.kurdistanvpn.core.ui.KurdistanDialogAppearance
import org.kurdistanvpn.core.ui.R as UiR


import org.kurdistanvpn.core.ui.kurdistanBidiFormatter
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.kurdistanvpn.core.ui.KurdistanIcons

@OptIn(ExperimentalMaterial3Api::class)
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

    var selectedLevel by rememberSaveable { mutableStateOf<DiagnosticLogLevel?>(null) }
    var selectedComponent by rememberSaveable { mutableStateOf<DiagnosticComponent?>(null) }
    var filtering by remember { mutableStateOf(false) }
    var draftLevel by remember { mutableStateOf<DiagnosticLogLevel?>(null) }
    var draftComponent by remember { mutableStateOf<DiagnosticComponent?>(null) }
    var aboutExpanded by rememberSaveable { mutableStateOf(false) }
    var submitted by remember(state) { mutableStateOf(false) }
    val bidiFormatter = kurdistanBidiFormatter()
    val sorani = LocalConfiguration.current.locales[0].language == "ckb"
    val matchingEvents = events.filter { event ->
        (selectedLevel == null || event.level == selectedLevel) &&
            (selectedComponent == null || event.component == selectedComponent)
    }
    val visibleEvents = matchingEvents.takeLast(50).asReversed()
    val gutter = if (with(LocalDensity.current) { LocalWindowInfo.current.containerSize.width.toDp() } < 600.dp) 16.dp else 24.dp
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
    Column(
        modifier = Modifier.widthIn(max = 960.dp).fillMaxSize()
            .verticalScroll(rememberScrollState()).padding(horizontal = gutter, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onBack, modifier = Modifier.heightIn(min = 48.dp).testTag("diagnostics_back")) {
                Text(stringResource(UiR.string.back))
            }
            Text(stringResource(UiR.string.diagnostics_about), style = MaterialTheme.typography.headlineMedium)
        }
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(stringResource(UiR.string.local_diagnostic_events), style = MaterialTheme.typography.titleLarge)
            Text(stringResource(UiR.string.local_diagnostic_privacy), color = MaterialTheme.colorScheme.onSurfaceVariant)
            OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.outlinedButtonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline),
                onClick = { draftLevel = selectedLevel; draftComponent = selectedComponent; filtering = true },
                modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("diagnostic_filters"),
                shape = MaterialTheme.shapes.small,
            ) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(UiR.string.uiux_filters), style = MaterialTheme.typography.titleLarge)
                    val levelLabel = selectedLevel?.name ?: stringResource(UiR.string.all_levels)
                    val componentLabel = selectedComponent?.name ?: stringResource(UiR.string.all_components)
                    Text(stringResource(UiR.string.uiux_filter_summary,
                        if (sorani) bidiFormatter.unicodeWrap(levelLabel) else levelLabel,
                        if (sorani) bidiFormatter.unicodeWrap(componentLabel) else componentLabel),
                        style = MaterialTheme.typography.bodyMedium)
                }
                Icon(KurdistanIcons.ChevronForward, null)
            }
            Text(
                stringResource(UiR.string.uiux_diagnostic_count, visibleEvents.size, matchingEvents.size, events.size),
                modifier = Modifier.testTag("diagnostic_count").semantics { liveRegion = LiveRegionMode.Polite },
                style = MaterialTheme.typography.bodyMedium,
            )
            if (visibleEvents.isEmpty()) {
                Text(stringResource(UiR.string.no_matching_diagnostic_events))
            } else {
                visibleEvents.forEachIndexed { index, event ->
                    Column(
                        modifier = Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}
                            .testTag("diagnostic_event_${event.sequence}"),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(stringResource(UiR.string.uiux_event_metadata, event.sequence,
                            bidiFormatter.unicodeWrap(event.level.name),
                            bidiFormatter.unicodeWrap(event.component.name)),
                            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(bidiFormatter.unicodeWrap(event.category), style = MaterialTheme.typography.titleMedium)
                    }
                    if (index < visibleEvents.lastIndex) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
        Card(
            Modifier.fillMaxWidth().testTag("diagnostic_workflow"),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = MaterialTheme.shapes.medium, border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            elevation = CardDefaults.cardElevation(0.dp),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(stringResource(UiR.string.uiux_diagnostic_export), style = MaterialTheme.typography.titleLarge)
        Text(stringResource(UiR.string.diagnostic_confirmation))
        when (state) {
            DiagnosticWorkflowState.Idle ->
                Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.buttonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), onClick = { if (state == DiagnosticWorkflowState.Idle && !submitted) { submitted = true; onPrepare() } }, enabled = !submitted, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("diagnostic_prepare"), shape = MaterialTheme.shapes.small) {
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
                Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.buttonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), onClick = { if (!submitted) { submitted = true; onConfirm() } }, enabled = !submitted, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("diagnostic_confirm"), shape = MaterialTheme.shapes.small) { Text(stringResource(UiR.string.confirm_export)) }
                TextButton(onClick = { if (!submitted) onCancel() }, enabled = !submitted, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("diagnostic_cancel")) { Text(stringResource(UiR.string.cancel)) }
            }
            DiagnosticWorkflowState.Completed ->
                Text(stringResource(UiR.string.diagnostic_exported))
            is DiagnosticWorkflowState.Failed ->
                Text(stringResource(UiR.string.diagnostic_failed, state.error.name), color = MaterialTheme.colorScheme.error)
        }
            }
        }
        OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.outlinedButtonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline),
            onClick = { if (events.isNotEmpty()) onClearEvents() }, enabled = events.isNotEmpty(),
            modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("diagnostic_clear"),
            shape = MaterialTheme.shapes.small,
        ) { Text(stringResource(UiR.string.clear_local_diagnostic_events)) }
        val aboutState = stringResource(if (aboutExpanded) UiR.string.uiux_expanded else UiR.string.uiux_collapsed)
        TextButton(onClick = { aboutExpanded = !aboutExpanded },
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).semantics { stateDescription = aboutState }.testTag("diagnostic_about")) {
            Text(stringResource(UiR.string.uiux_about), Modifier.weight(1f))
            Icon(if (aboutExpanded) KurdistanIcons.ChevronDown else KurdistanIcons.ChevronForward, null)
        }
        if (aboutExpanded) Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
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
        }
    }
    }
    if (filtering) {
        @Composable fun FilterBody() {
                Column(Modifier.verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(stringResource(UiR.string.uiux_filters), style = MaterialTheme.typography.headlineMedium)
                    Text(stringResource(UiR.string.uiux_level), style = MaterialTheme.typography.titleLarge)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), selected = draftLevel == null, onClick = { draftLevel = null },
                            modifier = Modifier.heightIn(min = 48.dp).testTag("diagnostic_level_all"),
                            label = { Text(stringResource(UiR.string.all_levels)) })
                        DiagnosticLogLevel.entries.filter { it != DiagnosticLogLevel.NONE }.forEach { level ->
                            FilterChip(border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), selected = draftLevel == level, onClick = { draftLevel = level },
                                modifier = Modifier.heightIn(min = 48.dp).testTag("diagnostic_level_${level.name}"),
                                label = { Text(level.name) })
                        }
                    }
                    Text(stringResource(UiR.string.uiux_component), style = MaterialTheme.typography.titleLarge)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), selected = draftComponent == null, onClick = { draftComponent = null },
                            modifier = Modifier.heightIn(min = 48.dp).testTag("diagnostic_component_all"),
                            label = { Text(stringResource(UiR.string.all_components)) })
                        DiagnosticComponent.entries.forEach { component ->
                            FilterChip(border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), selected = draftComponent == component, onClick = { draftComponent = component },
                                modifier = Modifier.heightIn(min = 48.dp).testTag("diagnostic_component_${component.name}"),
                                label = { Text(component.name) })
                        }
                    }
                    Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.buttonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), onClick = { selectedLevel = draftLevel; selectedComponent = draftComponent; filtering = false },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("diagnostic_filter_apply"),
                        shape = MaterialTheme.shapes.small) { Text(stringResource(UiR.string.apply)) }
                    TextButton(onClick = { filtering = false }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("diagnostic_filter_cancel")) {
                        Text(stringResource(UiR.string.cancel))
                    }
                }
        }
        if (with(LocalDensity.current) { LocalWindowInfo.current.containerSize.width.toDp() } < 600.dp) {
            ModalBottomSheet(scrimColor = androidx.compose.ui.graphics.Color.Black.copy(alpha = 0.56f), onDismissRequest = { filtering = false },
                sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
                shape = MaterialTheme.shapes.large, containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            ) { FilterBody() }
        } else {
            Dialog(onDismissRequest = { filtering = false }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
                KurdistanDialogAppearance()
                Surface(Modifier.padding(24.dp).widthIn(max = 560.dp).fillMaxWidth(),
                    shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainerHigh) { FilterBody() }
            }
        }
    }
}
