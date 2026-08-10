// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.settingsrecovery

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
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.ConnectionPreferences
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticPreferences
import org.kurdistanvpn.core.model.DiagnosticRetention
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.ExpertPreferences
import org.kurdistanvpn.core.model.InstalledApplication
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProbeDisplay
import org.kurdistanvpn.core.model.ProbeMethod
import org.kurdistanvpn.core.model.ProbeExecutionState
import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProductCapabilities
import org.kurdistanvpn.core.model.RoutingPreferences
import org.kurdistanvpn.core.model.SelectionMode
import org.kurdistanvpn.core.model.SettingsValidationException
import org.kurdistanvpn.core.model.TunnelPreferences
import org.kurdistanvpn.core.model.UpdatePreferences
import org.kurdistanvpn.core.ui.R as UiR

@Composable
fun SettingsIndexScreen(
    settings: Phase9Settings,
    capabilities: ProductCapabilities,
    onConnection: () -> Unit,
    onTunnelDns: () -> Unit,
    onRouting: () -> Unit,
    onUpdatesProbes: () -> Unit,
    onExpert: () -> Unit,
    onPrivacyRecovery: () -> Unit,
    onDiagnostics: () -> Unit,
    onBack: () -> Unit,
) = ProductScreen(stringResource(UiR.string.settings), onBack) {
    var query by remember { mutableStateOf("") }
    OutlinedTextField(
        value = query,
        onValueChange = { if (it.length <= 96) query = it },
        label = { Text(stringResource(UiR.string.search_settings)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().testTag("settings_search"),
    )
    val connectionTitle = stringResource(UiR.string.connection)
    val connectionSummary = stringResource(UiR.string.connection_settings_summary)
    val tunnelTitle = stringResource(UiR.string.tunnel_dns)
    val tunnelSummary = stringResource(UiR.string.tunnel_dns_summary)
    val routingTitle = stringResource(UiR.string.routing)
    val routingSummary = stringResource(UiR.string.routing_summary)
    val updateTitle = stringResource(UiR.string.profile_updates_probes)
    val updateSummary = stringResource(UiR.string.profile_updates_probes_summary)
    val privacyTitle = stringResource(UiR.string.privacy_accessibility_recovery)
    val privacySummary = stringResource(UiR.string.privacy_accessibility_recovery_summary)
    val diagnosticsTitle = stringResource(UiR.string.diagnostics_about)
    val diagnosticsSummary = stringResource(UiR.string.diagnostics_about_summary)
    val expertTitle = stringResource(UiR.string.expert_controls)
    val expertSummary = stringResource(UiR.string.expert_controls_summary)
    fun matches(title: String, summary: String): Boolean = query.isBlank() ||
        title.contains(query, ignoreCase = true) || summary.contains(query, ignoreCase = true)
    var resultCount = 0
    if (matches(connectionTitle, connectionSummary)) {
        resultCount++
        Section(connectionTitle, connectionSummary) {
        FullButton(stringResource(UiR.string.open_connection_settings), onConnection, "settings_connection")
    }
    }
    if (matches(tunnelTitle, tunnelSummary)) {
        resultCount++
        Section(tunnelTitle, tunnelSummary) {
        Text(stringResource(UiR.string.tunnel_dns_value, settings.tunnel.ipMode.name, settings.tunnel.dnsMode.name, settings.tunnel.mtu))
        FullButton(stringResource(UiR.string.open_tunnel_dns), onTunnelDns, "settings_tunnel")
    }
    }
    if (matches(routingTitle, routingSummary)) {
        resultCount++
        Section(routingTitle, routingSummary) {
        Text(stringResource(UiR.string.routing_value, settings.routing.mode.name, settings.routing.packages.size))
        FullButton(stringResource(UiR.string.open_routing), onRouting, "settings_routing")
    }
    }
    if (matches(updateTitle, updateSummary)) {
        resultCount++
        Section(updateTitle, updateSummary) {
        Text(stringResource(UiR.string.update_probe_value, if (settings.updates.automatic) stringResource(UiR.string.enabled) else stringResource(UiR.string.manual), settings.probes.method.name))
        FullButton(stringResource(UiR.string.open_updates_probes), onUpdatesProbes, "settings_updates")
    }
    }
    if (matches(privacyTitle, privacySummary)) {
        resultCount++
        Section(privacyTitle, privacySummary) {
        FullButton(stringResource(UiR.string.open_privacy_recovery), onPrivacyRecovery, "settings_privacy")
    }
    }
    if (matches(diagnosticsTitle, diagnosticsSummary)) {
        resultCount++
        Section(diagnosticsTitle, diagnosticsSummary) {
        FullButton(stringResource(UiR.string.open_diagnostics_about), onDiagnostics, "settings_diagnostics")
    }
    }
    if (matches(expertTitle, expertSummary)) {
        resultCount++
        Section(expertTitle, expertSummary) {
        FullButton(stringResource(UiR.string.open_expert_controls), onExpert, "settings_expert")
    }
    }
    if (resultCount == 0) {
        Card(modifier = Modifier.fillMaxWidth().testTag("settings_no_results")) {
            Text(
                stringResource(UiR.string.no_settings_match),
                modifier = Modifier.padding(20.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
    if (query.isBlank()) CapabilityCard(capabilities)
}

@Composable
fun ConnectionSettingsScreen(
    value: ConnectionPreferences,
    onChange: (ConnectionPreferences) -> Unit,
    onRecoverInternet: () -> Unit,
    onBack: () -> Unit,
) {
    var draft by remember(value) { mutableStateOf(value) }
    ProductScreen(stringResource(UiR.string.connection), onBack) {
    Section(stringResource(UiR.string.selection_mode), stringResource(UiR.string.selection_mode_explanation)) {
        ChoiceRow(SelectionMode.entries.filter { it != SelectionMode.MANUAL_STRATEGY }, draft.selectionMode) {
            draft = draft.copy(selectionMode = it)
        }
        Text(stringResource(UiR.string.manual_strategy_unavailable))
    }
    UnavailableSetting(stringResource(UiR.string.auto_connect_launch), stringResource(UiR.string.auto_connect_launch_reason))
    AvailableSetting(
        stringResource(UiR.string.safe_reconnect),
        stringResource(UiR.string.safe_reconnect_reason),
        "safe_reconnect_available",
    )
    UnavailableSetting(stringResource(UiR.string.auto_connect_boot), stringResource(UiR.string.auto_connect_boot_reason))
    UnavailableSetting(stringResource(UiR.string.kill_switch), stringResource(UiR.string.kill_switch_reason))
    UnavailableSetting(stringResource(UiR.string.allow_local_network), stringResource(UiR.string.allow_local_network_reason))
    UnavailableSetting(stringResource(UiR.string.trusted_network_auto_connect), stringResource(UiR.string.trusted_network_auto_connect_reason))
    DraftActions(
        changed = draft != value,
        onApply = { onChange(draft) },
        onCancel = { draft = value },
    )
    OutlinedButton(onClick = onRecoverInternet, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(UiR.string.recover_internet_stop_vpn))
    }
}
}

@Composable
fun TunnelDnsSettingsScreen(
    value: TunnelPreferences,
    onChange: (TunnelPreferences) -> Unit,
    onBack: () -> Unit,
) {
    var draft by remember(value) { mutableStateOf(value) }
    var error by remember(value) { mutableStateOf<String?>(null) }
    ProductScreen(stringResource(UiR.string.tunnel_dns), onBack) {
    Section(stringResource(UiR.string.ip_family), stringResource(UiR.string.ip_family_explanation)) {
        ChoiceRow(listOf(IpMode.AUTO, IpMode.IPV4_ONLY), draft.ipMode) { draft = draft.copy(ipMode = it) }
        Text(stringResource(UiR.string.ipv6_unavailable_reason))
    }
    Section(stringResource(UiR.string.dns), stringResource(UiR.string.dns_explanation)) {
        ChoiceRow(listOf(DnsMode.INTERNAL_TUN), draft.dnsMode) { draft = draft.copy(dnsMode = it, customDns = "") }
        Text(stringResource(UiR.string.external_dns_unavailable_reason))
    }
    Section(stringResource(UiR.string.mtu), stringResource(UiR.string.mtu_explanation)) {
        NumericStepper(draft.mtu, 1280, 1500, 10) { draft = draft.copy(mtu = it) }
    }
    ToggleRow(stringResource(UiR.string.treat_vpn_metered), stringResource(UiR.string.treat_vpn_metered_explanation), draft.metered) {
        draft = draft.copy(metered = it)
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
        onCancel = { draft = value; error = null },
    )
}
}

@Composable
fun RoutingSettingsScreen(
    value: RoutingPreferences,
    applications: List<InstalledApplication>,
    onChange: (RoutingPreferences) -> Unit,
    onBack: () -> Unit,
) {
    var draft by remember(value) { mutableStateOf(value) }
    var error by remember(value) { mutableStateOf<String?>(null) }
    ProductScreen(stringResource(UiR.string.per_app_routing), onBack) {
    Text(stringResource(UiR.string.launchable_apps_only))
    ChoiceRow(PerAppSelectionMode.entries, draft.mode) { mode ->
        draft = draft.copy(mode = mode, packages = if (mode == PerAppSelectionMode.ALL_APPS) emptySet() else draft.packages)
    }
    var search by remember { mutableStateOf("") }
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
                draft = draft.copy(packages = packages)
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
        onCancel = { draft = value; error = null },
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
        Text(stringResource(UiR.string.probe_method_value, ProbeMethod.KURD_SESSION.name))
        Text(stringResource(UiR.string.network_probes_unavailable_reason))
        Button(onClick = onRunLocalProbe, modifier = Modifier.fillMaxWidth()) { Text(stringResource(UiR.string.run_kurd_loopback_probe)) }
        Text(
            when (probeState) {
                ProbeExecutionState.Idle -> stringResource(UiR.string.probe_not_run)
                ProbeExecutionState.Running -> stringResource(UiR.string.probe_running)
                is ProbeExecutionState.Succeeded -> stringResource(UiR.string.probe_succeeded, probeState.latencyMillis)
                is ProbeExecutionState.Failed -> stringResource(UiR.string.probe_failed, probeState.category.name)
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
private fun ProductScreen(
    title: String,
    onBack: () -> Unit,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().widthIn(max = 840.dp).verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TextButton(onClick = onBack, modifier = Modifier.heightIn(min = 48.dp)) {
                Text(stringResource(UiR.string.back))
            }
            Text(
                title,
                style = MaterialTheme.typography.headlineMedium,
                modifier = Modifier.weight(1f),
            )
        }
        content()
    }
}

@Composable
private fun Section(title: String, explanation: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(explanation, color = MaterialTheme.colorScheme.onSurfaceVariant)
            content()
        }
    }
}

@Composable
private fun ToggleRow(title: String, explanation: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Column(Modifier.weight(1f)) {
            Text(title)
            Text(explanation, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun <T : Enum<T>> ChoiceRow(values: List<T>, selected: T, onSelect: (T) -> Unit) {
    FlowRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        values.forEach { value ->
            FilterChip(selected = value == selected, onClick = { onSelect(value) }, label = { Text(value.name) })
        }
    }
}

@Composable
private fun NumericStepper(value: Int, minimum: Int, maximum: Int, step: Int, onChange: (Int) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedButton(onClick = { onChange((value - step).coerceAtLeast(minimum)) }, enabled = value > minimum) { Text("−") }
        Text(value.toString(), modifier = Modifier.padding(vertical = 12.dp))
        OutlinedButton(onClick = { onChange((value + step).coerceAtMost(maximum)) }, enabled = value < maximum) { Text("+") }
    }
}

@Composable
private fun FullButton(label: String, onClick: () -> Unit, tag: String) {
    Button(onClick = onClick, modifier = Modifier.fillMaxWidth().testTag(tag)) { Text(label) }
}

@Composable
private fun DraftActions(
    changed: Boolean,
    onApply: () -> Unit,
    onCancel: () -> Unit,
) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Button(
            onClick = onApply,
            enabled = changed,
            modifier = Modifier.weight(1f).testTag("settings_apply"),
        ) { Text(stringResource(UiR.string.apply)) }
        OutlinedButton(
            onClick = onCancel,
            enabled = changed,
            modifier = Modifier.weight(1f).testTag("settings_cancel"),
        ) { Text(stringResource(UiR.string.cancel_changes)) }
    }
}

@Composable
private fun UnavailableSetting(title: String, explanation: String) {
    Card(modifier = Modifier.fillMaxWidth().testTag("unavailable_${title.hashCode()}")) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(stringResource(UiR.string.unavailable), color = MaterialTheme.colorScheme.error)
            Text(explanation, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun AvailableSetting(title: String, explanation: String, tag: String) {
    Card(modifier = Modifier.fillMaxWidth().testTag(tag)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
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
