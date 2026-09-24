// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.settingsrecovery

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import org.kurdistanvpn.core.ui.KurdistanOutlinedTextField as OutlinedTextField
import androidx.compose.material3.Switch
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.ConnectionPreferences
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticPreferences
import org.kurdistanvpn.core.model.DiagnosticRetention
import org.kurdistanvpn.core.model.ResolverPolicy
import org.kurdistanvpn.core.model.ExpertPreferences
import org.kurdistanvpn.core.model.InstalledApplication
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.ProbeDisplay
import org.kurdistanvpn.core.model.ProbeExecutionState
import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProductCapabilities
import org.kurdistanvpn.core.model.RoutingPreferences
import org.kurdistanvpn.core.model.SelectionMode
import org.kurdistanvpn.core.model.SettingsValidationException
import org.kurdistanvpn.core.model.TunnelPreferences
import org.kurdistanvpn.core.model.UpdatePreferences
import org.kurdistanvpn.core.ui.LocalEssentialBoundaryWidth
import org.kurdistanvpn.core.ui.R as UiR


import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import org.kurdistanvpn.core.ui.KurdistanIcons

private data class SettingsCategory(
    val title: String,
    val summary: String,
    val tag: String,
    val icon: ImageVector,
    val onClick: () -> Unit,
)

@Composable
fun SettingsIndexScreen(
    settings: ProductSettings,
    capabilities: ProductCapabilities,
    onConnection: () -> Unit,
    onTunnelDns: () -> Unit,
    onRouting: () -> Unit,
    onUpdatesProbes: () -> Unit,
    onExpert: () -> Unit,
    onPrivacyRecovery: () -> Unit,
    onDiagnostics: () -> Unit,

    onBack: () -> Unit,
    showBack: Boolean = true,
    onAppearance: () -> Unit = onPrivacyRecovery,
    proxyCredentials: @Composable () -> Unit = {},
) = ProductScreen(stringResource(UiR.string.settings), onBack, showBack) {
    var query by rememberSaveable { mutableStateOf("") }
    var capabilitiesExpanded by rememberSaveable { mutableStateOf(false) }
    OutlinedTextField(
        value = query,
        onValueChange = { if (it.length <= 96) query = it },
        label = { Text(stringResource(UiR.string.search_settings)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().testTag("settings_search"),
    )
    val groups = listOf(
        stringResource(UiR.string.connection) to listOf(
            SettingsCategory(stringResource(UiR.string.connection), stringResource(UiR.string.connection_settings_summary),
                "settings_connection", KurdistanIcons.Connection, onConnection),
            SettingsCategory(stringResource(UiR.string.routing), stringResource(UiR.string.routing_summary),
                "settings_routing", KurdistanIcons.Route, onRouting),
            SettingsCategory(stringResource(UiR.string.tunnel_dns), stringResource(UiR.string.tunnel_dns_summary),
                "settings_tunnel", KurdistanIcons.Connection, onTunnelDns),
            SettingsCategory(stringResource(UiR.string.profile_updates_probes), stringResource(UiR.string.profile_updates_probes_summary),
                "settings_updates", KurdistanIcons.Refresh, onUpdatesProbes),
        ),
        stringResource(UiR.string.uiux_app_privacy) to listOf(
            SettingsCategory(stringResource(UiR.string.appearance), stringResource(UiR.string.appearance),
                "settings_appearance", KurdistanIcons.Adjustments, onAppearance),
            SettingsCategory(stringResource(UiR.string.privacy_accessibility_recovery), stringResource(UiR.string.privacy_accessibility_recovery_summary),
                "settings_privacy", KurdistanIcons.Lock, onPrivacyRecovery),
        ),
        stringResource(UiR.string.uiux_support) to listOf(
            SettingsCategory(stringResource(UiR.string.diagnostics_about), stringResource(UiR.string.diagnostics_about_summary),
                "settings_diagnostics", KurdistanIcons.Info, onDiagnostics),
        ),
        stringResource(UiR.string.uiux_advanced) to listOf(
            SettingsCategory(stringResource(UiR.string.expert_controls), stringResource(UiR.string.expert_controls_summary),
                "settings_expert", KurdistanIcons.Adjustments, onExpert),
        ),
    )
    var resultCount = 0
    groups.forEach { (groupTitle, categories) ->
        val matching = categories.filter { query.isBlank() || it.title.contains(query, true) || it.summary.contains(query, true) }
        if (matching.isNotEmpty()) {
            resultCount += matching.size
            Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(groupTitle, style = MaterialTheme.typography.titleLarge)
                matching.forEachIndexed { i, category ->
                    CategoryRow(category)
                    if (i < matching.lastIndex) HorizontalDivider(
                        Modifier.padding(start = 40.dp), color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
    if (resultCount == 0) {
        Text(stringResource(UiR.string.no_settings_match), modifier = Modifier.testTag("settings_no_results"))
        TextButton(onClick = { query = "" }, modifier = Modifier.heightIn(min = 48.dp).testTag("settings_clear_search")) {
            Text(stringResource(UiR.string.uiux_clear_search))
        }
    }
    if (query.isBlank()) {
        proxyCredentials()
        val detailState = stringResource(if (capabilitiesExpanded) UiR.string.uiux_expanded else UiR.string.uiux_collapsed)
        TextButton(onClick = { capabilitiesExpanded = !capabilitiesExpanded },
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                .semantics { stateDescription = detailState }.testTag("settings_capabilities")) {
            Text(stringResource(UiR.string.capability_boundary), Modifier.weight(1f))
            Icon(if (capabilitiesExpanded) KurdistanIcons.ChevronDown else KurdistanIcons.ChevronForward, null)
        }
        if (capabilitiesExpanded) CapabilityCard(capabilities)
    }
}

@Composable
private fun CategoryRow(category: SettingsCategory) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 72.dp)
            .clickable(role = Role.Button, onClick = category.onClick)
            .testTag(category.tag).padding(vertical = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Icon(category.icon, null, Modifier.size(24.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(category.title, style = MaterialTheme.typography.titleMedium)
            Text(category.summary, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Icon(KurdistanIcons.ChevronForward, null, Modifier.size(24.dp))
    }
}

@Composable
fun AppearanceSettingsScreen(applied: ProductSettings, editor: SettingsEditorState?,
    onEdit: (ProductSettings) -> Unit, onApply: () -> Unit, onCancel: () -> Unit, onBack: () -> Unit) =
    ProductScreen(stringResource(UiR.string.appearance), onBack) {
        val requested = editor?.requested ?: editor?.applied?.settings ?: applied
        AppearanceControls(requested, { onEdit(requested.copy(theme = it)) },
            { onEdit(requested.copy(highContrast = it)) }, { onEdit(requested.copy(reducedMotion = it)) },
            enabled = (editor?.draft != null && editor.requested != null) || editor?.phase == SettingsEditorPhase.APPLIED)
        DraftActions(requested != applied, onApply, onCancel, editor?.phase)
    }

@Composable
fun ConnectionSettingsScreen(
    value: ConnectionPreferences,
    onChange: (ConnectionPreferences) -> Unit,
    onRecoverInternet: () -> Unit,
    onBack: () -> Unit,
    paused: Boolean = false,
    canPause: Boolean = false,
    onPause: (Long?) -> Unit = {},
    onSystemVpnSettings: () -> Unit = {},
    draftValue: ConnectionPreferences? = null,
    onEdit: ((ConnectionPreferences) -> Unit)? = null,
    onCancelDraft: (() -> Unit)? = null,
    editorPhase: SettingsEditorPhase? = null,
) {
    var localDraft by remember(value) { mutableStateOf(value) }
    val draft = draftValue ?: localDraft
    fun edit(next: ConnectionPreferences) { if (onEdit != null) onEdit(next) else localDraft = next }
    ProductScreen(stringResource(UiR.string.connection), onBack) {
    Section(stringResource(UiR.string.selection_mode), stringResource(UiR.string.selection_mode_explanation)) {
        ChoiceRow(SelectionMode.entries.filter { it != SelectionMode.MANUAL_STRATEGY }, draft.selectionMode) {
            edit(draft.copy(selectionMode = it))
        }
        Text(stringResource(UiR.string.manual_strategy_unavailable))
    }
    ToggleRow(stringResource(UiR.string.auto_connect_launch), stringResource(UiR.string.foreground_auto_connect_help), draft.autoConnectOnLaunch) {
        edit(draft.copy(autoConnectOnLaunch = it))
    }
    ToggleRow(
        stringResource(UiR.string.safe_reconnect),
        stringResource(UiR.string.safe_reconnect_reason),
        draft.reconnectOnFailure,
    ) { edit(draft.copy(reconnectOnFailure = it)) }
    Text(stringResource(UiR.string.system_vpn_policy_help))
    OutlinedButton(onClick = onSystemVpnSettings, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
        Text(stringResource(UiR.string.open_system_vpn_settings))
    }
    if (paused) {
        OutlinedButton(onClick = { onPause(null) }, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("resume_connections")) {
            Text(stringResource(UiR.string.resume_connections))
        }
        Text(stringResource(UiR.string.resume_connections_help))
    } else {
        OutlinedButton(onClick = { onPause(900000) }, enabled = canPause,
            modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("pause_15_minutes")) {
            Text(stringResource(UiR.string.pause_15_minutes))
        }
        OutlinedButton(onClick = { onPause(0) }, enabled = canPause, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
            Text(stringResource(UiR.string.pause_until_resumed))
        }
        if (!canPause) Text(stringResource(UiR.string.pause_system_restriction))
    }
    UnavailableSetting(stringResource(UiR.string.allow_local_network), stringResource(UiR.string.allow_local_network_reason))
    UnavailableSetting(stringResource(UiR.string.trusted_network_auto_connect), stringResource(UiR.string.trusted_network_auto_connect_reason))
    DraftActions(
        changed = draft != value,
        onApply = { onChange(draft) },
        onCancel = { if (onCancelDraft != null) onCancelDraft() else localDraft = value },
        editorPhase = editorPhase,
    )
    OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.outlinedButtonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), onClick = onRecoverInternet, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp), shape = MaterialTheme.shapes.small) {
        Text(stringResource(UiR.string.recover_internet_stop_vpn))
    }
}
}

@Composable
fun TunnelDnsSettingsScreen(
    value: TunnelPreferences,
    onChange: (TunnelPreferences) -> Unit,
    onBack: () -> Unit,
    draftValue: TunnelPreferences? = null,
    onEdit: ((TunnelPreferences) -> Unit)? = null,
    onCancelDraft: (() -> Unit)? = null,
    editorPhase: SettingsEditorPhase? = null,
) {
    var localDraft by remember(value) { mutableStateOf(value) }
    val draft = draftValue ?: localDraft
    fun edit(next: TunnelPreferences) { if (onEdit != null) onEdit(next) else localDraft = next }
    var error by remember(value) { mutableStateOf<String?>(null) }
    ProductScreen(stringResource(UiR.string.tunnel_dns), onBack) {
    Section(stringResource(UiR.string.ip_family), stringResource(UiR.string.ip_family_explanation)) {
        ChoiceRow(listOf(IpMode.AUTO, IpMode.IPV4_ONLY), draft.ipMode) { edit(draft.copy(ipMode = it)) }
        Text(stringResource(UiR.string.ipv6_unavailable_reason))
    }
    Section(stringResource(UiR.string.dns), stringResource(UiR.string.dns_explanation)) {
        ChoiceRow(listOf(ResolverPolicy.INTERNAL), draft.dnsMode) { edit(draft.copy(dnsMode = it, customDns = "")) }
        Text(stringResource(UiR.string.external_dns_unavailable_reason))
    }
    Section(stringResource(UiR.string.mtu), stringResource(UiR.string.mtu_explanation)) {
        NumericStepper(draft.mtu, 1280, 1500, 10) { edit(draft.copy(mtu = it)) }
    }
    ToggleRow(stringResource(UiR.string.treat_vpn_metered), stringResource(UiR.string.treat_vpn_metered_explanation), draft.metered) {
        edit(draft.copy(metered = it))
    }
    UnavailableSetting(stringResource(UiR.string.speed_notification), stringResource(UiR.string.speed_notification_reason))
    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    DraftActions(
        changed = draft != value,
        onApply = {
            runCatching { draft.validated() }
                .onSuccess { valid -> error = null; onChange(valid) }
                .onFailure { failure -> error = validationMessage(failure) }
        },
        onCancel = { if (onCancelDraft != null) onCancelDraft() else localDraft = value; error = null },
        editorPhase = editorPhase,
    )
}
}

@Composable
fun RoutingSettingsScreen(
    value: RoutingPreferences,
    applications: List<InstalledApplication>,
    onChange: (RoutingPreferences) -> Unit,
    onBack: () -> Unit,
    draftValue: RoutingPreferences? = null,
    onEdit: ((RoutingPreferences) -> Unit)? = null,
    onCancelDraft: (() -> Unit)? = null,
    editorPhase: SettingsEditorPhase? = null,
) {
    var localDraft by remember(value) { mutableStateOf(value) }
    val draft = draftValue ?: localDraft
    fun edit(next: RoutingPreferences) { if (onEdit != null) onEdit(next) else localDraft = next }
    var error by remember(value) { mutableStateOf<String?>(null) }
    ProductScreen(stringResource(UiR.string.per_app_routing), onBack) {
    Text(stringResource(UiR.string.launchable_apps_only))
    ChoiceRow(PerAppSelectionMode.entries, draft.mode) { mode ->
        edit(draft.copy(mode = mode, packages = if (mode == PerAppSelectionMode.ALL_APPS) emptySet() else draft.packages))
    }
    var search by rememberSaveable { mutableStateOf("") }
    OutlinedTextField(
        value = search,
        onValueChange = { if (it.length <= 128) search = it },
        label = { Text(stringResource(UiR.string.search_apps)) },
        modifier = Modifier.fillMaxWidth().testTag("routing_search"),
        singleLine = true,
    )
    if (draft.mode == PerAppSelectionMode.ALL_APPS) {
        Text(stringResource(UiR.string.all_apps_eligible))
    } else {
        applications.filter {
            search.isBlank() || it.label.contains(search, true) || it.packageName.contains(search, true)
        }.forEach { app ->
            ToggleRow(app.label, app.packageName, app.packageName in draft.packages) { enabled ->
                val packages = draft.packages.toMutableSet().apply {
                    if (enabled) add(app.packageName) else remove(app.packageName)
                }
                edit(draft.copy(packages = packages))
            }
        }
    }
    Text(stringResource(UiR.string.excluded_apps_warning))
    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    DraftActions(
        changed = draft != value,
        onApply = {
            runCatching { draft.validated() }
                .onSuccess { valid -> error = null; onChange(valid) }
                .onFailure { failure -> error = validationMessage(failure) }
        },
        onCancel = { if (onCancelDraft != null) onCancelDraft() else localDraft = value; error = null },
        editorPhase = editorPhase,
    )
}
}

@Composable
fun UpdatesProbeSettingsScreen(
    updates: UpdatePreferences,
    probes: ProbePreferences,
    probeState: ProbeExecutionState,
    onUpdates: (UpdatePreferences) -> Unit,
    onProbes: (ProbePreferences) -> Unit,
    onRunLocalProbe: () -> Unit,
    onBack: () -> Unit,
) = ProductScreen(stringResource(UiR.string.updates_probes), onBack) {
    UnavailableSetting(
        stringResource(UiR.string.automatic_signed_updates),
        stringResource(UiR.string.automatic_signed_updates_reason),
    )
    Section(stringResource(UiR.string.health_probes), stringResource(UiR.string.health_probes_explanation)) {
        Text(stringResource(UiR.string.probe_method_value))
        Text(stringResource(UiR.string.network_probes_unavailable_reason))
        Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.buttonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), onClick = onRunLocalProbe, modifier = Modifier.fillMaxWidth()) { Text(stringResource(UiR.string.run_signed_tcp_probe)) }
        Text(
            when (probeState) {
                ProbeExecutionState.Idle -> stringResource(UiR.string.probe_not_run)
                ProbeExecutionState.Running -> stringResource(UiR.string.probe_running)
                is ProbeExecutionState.Succeeded -> stringResource(UiR.string.probe_succeeded, probeState.latencyMillis)
                is ProbeExecutionState.Failed -> stringResource(UiR.string.probe_failed)
            },
        )
    }
}

@Composable
fun ExpertSettingsScreen(
    expert: ExpertPreferences,
    diagnostics: DiagnosticPreferences,
    onExpert: (ExpertPreferences) -> Unit,
    onDiagnostics: (DiagnosticPreferences) -> Unit,
    onBack: () -> Unit,
) {
    var diagnosticsDraft by remember(diagnostics) { mutableStateOf(diagnostics) }
    ProductScreen(stringResource(UiR.string.expert_controls), onBack) {
    UnavailableSetting(
        stringResource(UiR.string.runtime_resource_tuning),
        stringResource(UiR.string.runtime_resource_tuning_reason),
    )
    Section(stringResource(UiR.string.local_logs), stringResource(UiR.string.local_logs_explanation)) {
        ChoiceRow(DiagnosticLogLevel.entries, diagnosticsDraft.level) { diagnosticsDraft = diagnosticsDraft.copy(level = it) }
        ChoiceRow(DiagnosticRetention.entries, diagnosticsDraft.retention) { diagnosticsDraft = diagnosticsDraft.copy(retention = it) }
    }
    DraftActions(
        changed = diagnosticsDraft != diagnostics,
        onApply = { onDiagnostics(diagnosticsDraft) },
        onCancel = { diagnosticsDraft = diagnostics },
    )
    Section(stringResource(UiR.string.unavailable_unsafe_controls), stringResource(UiR.string.unavailable_unsafe_controls_explanation)) { }
}
}


@Composable
internal fun ProductScreen(
    title: String,
    onBack: () -> Unit,
    showBack: Boolean = true,
    content: @Composable () -> Unit,
) {
    val gutter = if (with(LocalDensity.current) { LocalWindowInfo.current.containerSize.width.toDp() } < 600.dp) 16.dp else 24.dp
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier.widthIn(max = 720.dp).fillMaxSize()
                .verticalScroll(rememberScrollState()).padding(horizontal = gutter, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (showBack) TextButton(onClick = onBack, modifier = Modifier.heightIn(min = 48.dp).testTag("settings_back")) {
                    Text(stringResource(UiR.string.back))
                }
                Text(title, style = MaterialTheme.typography.headlineMedium)
            }
            content()
        }
    }
}

@Composable
private fun Section(title: String, explanation: String, content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        elevation = CardDefaults.cardElevation(0.dp),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            Text(explanation, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            content()
        }
    }
}

@Composable
private fun ToggleRow(title: String, explanation: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)
            .toggleable(value = checked, role = Role.Switch, onValueChange = onChange).padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(explanation, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = null)
    }
}

@Composable
private fun <T : Enum<T>> ChoiceRow(values: List<T>, selected: T, onSelect: (T) -> Unit) {
    FlowRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)) {
        values.forEach { value ->
            FilterChip(border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), selected = value == selected, onClick = { onSelect(value) },
                modifier = Modifier.heightIn(min = 48.dp), label = { Text(value.name) })
        }
    }
}

@Composable
private fun NumericStepper(value: Int, minimum: Int, maximum: Int, step: Int, onChange: (Int) -> Unit) {
    val decrease = stringResource(UiR.string.uiux_decrease)
    val increase = stringResource(UiR.string.uiux_increase)
    FlowRow(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.outlinedButtonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), onClick = { if (value > minimum) onChange((value - step).coerceAtLeast(minimum)) }, enabled = value > minimum,
            modifier = Modifier.heightIn(min = 48.dp).semantics { contentDescription = decrease }, shape = MaterialTheme.shapes.small) { Text("−") }
        Text(value.toString(), modifier = Modifier.padding(vertical = 12.dp))
        OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.outlinedButtonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), onClick = { if (value < maximum) onChange((value + step).coerceAtMost(maximum)) }, enabled = value < maximum,
            modifier = Modifier.heightIn(min = 48.dp).semantics { contentDescription = increase }, shape = MaterialTheme.shapes.small) { Text("+") }
    }
}

@Composable
private fun DraftActions(changed: Boolean, onApply: () -> Unit, onCancel: () -> Unit, editorPhase: SettingsEditorPhase? = null) {
    val canApply = changed && (editorPhase == null || editorPhase == SettingsEditorPhase.SAVED)
    val canCancel = changed || editorPhase == SettingsEditorPhase.FAILED || editorPhase == SettingsEditorPhase.SAVING
    if (editorPhase != null) Text(stringResource(when (editorPhase) {
        SettingsEditorPhase.SAVING, SettingsEditorPhase.LOADING -> UiR.string.settings_draft_saving
        SettingsEditorPhase.SAVED -> UiR.string.settings_draft_saved
        SettingsEditorPhase.FAILED -> UiR.string.settings_draft_failed
        SettingsEditorPhase.APPLYING -> UiR.string.settings_draft_applying
        else -> UiR.string.settings_draft_unapplied
    }), modifier = Modifier.testTag("settings_draft_status"))
    val largeText = LocalConfiguration.current.fontScale >= 1.5f
    @Composable fun ApplyButton(modifier: Modifier) {
        Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.buttonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), onClick = { if (canApply) onApply() }, enabled = canApply, shape = MaterialTheme.shapes.small,
            modifier = modifier.heightIn(min = 56.dp).testTag("settings_apply")) { Text(stringResource(UiR.string.apply)) }
    }
    @Composable fun CancelButton(modifier: Modifier) {
        OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), colors = ButtonDefaults.outlinedButtonColors(disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), onClick = { if (canCancel) onCancel() }, enabled = canCancel, shape = MaterialTheme.shapes.small,
            modifier = modifier.heightIn(min = 56.dp).testTag("settings_cancel")) { Text(stringResource(UiR.string.cancel_changes)) }
    }
    if (largeText) {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            ApplyButton(Modifier.fillMaxWidth())
            CancelButton(Modifier.fillMaxWidth())
        }
    } else {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ApplyButton(Modifier.weight(1f))
            CancelButton(Modifier.weight(1f))
        }
    }
}

@Composable
private fun UnavailableSetting(title: String, explanation: String) {
    Card(modifier = Modifier.fillMaxWidth().testTag("unavailable_${title.hashCode()}")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            Text(stringResource(UiR.string.unavailable), color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(explanation, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun AvailableSetting(title: String, explanation: String, tag: String) {
    Card(modifier = Modifier.fillMaxWidth().testTag(tag)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            Text(stringResource(UiR.string.available), color = MaterialTheme.colorScheme.primary)
            Text(explanation, style = MaterialTheme.typography.bodySmall)
        }
    }
}

private fun validationMessage(failure: Throwable): String = when (failure) {
    is SettingsValidationException -> "${failure.field.name}: ${failure.category}"
    else -> "SETTINGS: INVALID_VALUE"
}

@Composable
private fun CapabilityCard(capabilities: ProductCapabilities) {
    Section(stringResource(UiR.string.capability_boundary), stringResource(UiR.string.capability_boundary_explanation)) {
        listOf(
            capabilities.vpnRuntime,
            capabilities.publicRelay,
            capabilities.providerNetworkUpdates,
            capabilities.localProxy,
            capabilities.hotspotProxy,
        ).forEach { capability ->
            Text(
                stringResource(
                    UiR.string.capability_status,
                    if (capability.available) stringResource(UiR.string.available) else stringResource(UiR.string.unavailable),
                    capability.id,
                ),
            )
            Text(capability.explanation, style = MaterialTheme.typography.bodySmall)
        }
    }
}
