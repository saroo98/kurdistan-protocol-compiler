// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.home

import android.os.SystemClock
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.ui.R as UiR
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

@Composable
fun HomeScreen(
    state: AppState,
    settings: Phase9Settings = Phase9Settings(),
    vpnRuntime: VpnRuntimeSnapshot,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit,
    onOpenProfiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenDiagnostics: () -> Unit,
    onClearError: () -> Unit,
) {
    val profiles = (state as? AppState.Ready)?.profiles.orEmpty()
    val activeProfile = profiles.firstOrNull {
        it.localRecordId == settings.profiles.activeLocalRecordId
    } ?: profiles.firstOrNull()
    val active = vpnRuntime.state == VpnRuntimeState.ACTIVE_LOCAL_ONLY ||
        vpnRuntime.state == VpnRuntimeState.ACTIVE_KURD_LOOPBACK ||
        vpnRuntime.state == VpnRuntimeState.ACTIVE_KURD_LIVE
    val busy = vpnRuntime.state == VpnRuntimeState.PREPARING ||
        vpnRuntime.state == VpnRuntimeState.AWAITING_VPN_CONSENT ||
        vpnRuntime.state == VpnRuntimeState.CONNECTING ||
        vpnRuntime.state == VpnRuntimeState.RECONNECTING ||
        vpnRuntime.state == VpnRuntimeState.RECOVERING ||
        vpnRuntime.state == VpnRuntimeState.STOPPING

    Scaffold { padding ->
        Box(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentAlignment = Alignment.TopCenter,
        ) {
            Column(
                modifier = Modifier
                    .widthIn(max = 840.dp)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    stringResource(UiR.string.product_name),
                    style = MaterialTheme.typography.headlineLarge,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.semantics { heading() },
                )
                Text(
                    stringResource(UiR.string.product_tagline),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                ConnectionHero(
                    snapshot = vpnRuntime,
                    active = active,
                    busy = busy,
                    canStart = activeProfile != null,
                    onStart = onStartVpn,
                    onStop = onStopVpn,
                )
                ActiveProfileCard(activeProfile, settings, vpnRuntime)
                RuntimeDetails(vpnRuntime)
                RecoveryStatusCard(state, onOpenSettings)
                if (state is AppState.ImportRejected) {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                stringResource(UiR.string.import_rejected, state.error.name),
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                            TextButton(onClick = onClearError) {
                                Text(stringResource(UiR.string.dismiss))
                            }
                        }
                    }
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Button(
                        onClick = onOpenProfiles,
                        modifier = Modifier.weight(1f).testTag("home_profiles"),
                    ) { Text(stringResource(UiR.string.profiles)) }
                    OutlinedButton(
                        onClick = onOpenSettings,
                        modifier = Modifier.weight(1f).testTag("home_settings"),
                    ) { Text(stringResource(UiR.string.settings)) }
                }
                OutlinedButton(
                    onClick = onOpenDiagnostics,
                    modifier = Modifier.fillMaxWidth().testTag("home_diagnostics"),
                ) { Text(stringResource(UiR.string.diagnostics_about)) }
                Text(
                    stringResource(UiR.string.phase13_external_boundary),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun RecoveryStatusCard(state: AppState, onOpenRecovery: () -> Unit) {
    val detail = when (state) {
        AppState.LockedStorage -> stringResource(UiR.string.recovery_storage_locked)
        AppState.MigrationRequired -> stringResource(UiR.string.recovery_migration_required)
        AppState.KeyInvalidated -> stringResource(UiR.string.recovery_key_invalidated)
        AppState.DegradedStorage -> stringResource(UiR.string.recovery_storage_degraded)
        AppState.Quarantined -> stringResource(UiR.string.recovery_quarantined)
        AppState.FatalRecovery -> stringResource(UiR.string.recovery_fatal)
        else -> null
    } ?: return
    Card(
        modifier = Modifier.fillMaxWidth().testTag("recovery_status"),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(UiR.string.recovery_required), style = MaterialTheme.typography.titleMedium)
            Text(detail, color = MaterialTheme.colorScheme.onErrorContainer)
            OutlinedButton(onClick = onOpenRecovery) { Text(stringResource(UiR.string.open_recovery_settings)) }
        }
    }
}

@Composable
private fun ConnectionHero(
    snapshot: VpnRuntimeSnapshot,
    active: Boolean,
    busy: Boolean,
    canStart: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (active) {
                MaterialTheme.colorScheme.primaryContainer
            } else {
                MaterialTheme.colorScheme.surfaceVariant
            },
        ),
        modifier = Modifier.fillMaxWidth().testTag("connection_hero"),
    ) {
        Column(Modifier.padding(22.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                connectionTitle(snapshot.state),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Text(connectionExplanation(snapshot))
            if (active) {
                Button(onClick = onStop, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(UiR.string.disconnect))
                }
            } else {
                Button(
                    onClick = onStart,
                    enabled = canStart && !busy,
                    modifier = Modifier.fillMaxWidth().testTag("connect_button"),
                ) {
                    Text(if (busy) stringResource(UiR.string.working_locally) else stringResource(UiR.string.connect))
                }
                if (!canStart) Text(stringResource(UiR.string.profile_required_for_vpn))
            }
        }
    }
}

@Composable
private fun ActiveProfileCard(
    profile: ProfileSummary?,
    settings: Phase9Settings,
    snapshot: VpnRuntimeSnapshot,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(UiR.string.active_profile), style = MaterialTheme.typography.titleMedium)
            if (profile == null) {
                Text(stringResource(UiR.string.no_active_profile))
                return@Column
            }
            Text(profile.displayAlias, style = MaterialTheme.typography.titleLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(UiR.string.protocol_kurd),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
                Text(
                    settings.connection.selectionMode.name,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(stringResource(UiR.string.profile_generation_value, profile.generation.toString()))
            Text(stringResource(UiR.string.profile_trust, profile.trust.name))
            val digest = snapshot.planDigest
            if (digest == null) {
                Text(stringResource(UiR.string.session_plan_unavailable))
            } else {
                Text(stringResource(UiR.string.session_plan_digest, digest.take(16)))
                snapshot.strategyFingerprint?.let {
                    Text(stringResource(UiR.string.selected_strategy_fingerprint, it.take(16)))
                }
                snapshot.relayFingerprint?.let {
                    Text(stringResource(UiR.string.selected_relay_fingerprint, it.take(16)))
                }
                Text(
                    stringResource(
                        UiR.string.fallback_status_value,
                        snapshot.packetDisposition ?: "NOT_USED",
                    ),
                )
            }
        }
    }
}

@Composable
private fun RuntimeDetails(snapshot: VpnRuntimeSnapshot) {
    val durationSeconds = if (snapshot.startedAtElapsedRealtime > 0) {
        ((SystemClock.elapsedRealtime() - snapshot.startedAtElapsedRealtime) / 1000).coerceAtLeast(0)
    } else 0
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text(stringResource(UiR.string.connection_details), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(UiR.string.runtime_state, snapshot.state.name))
            Text(stringResource(UiR.string.connected_duration, formatDuration(durationSeconds)))
            Text(stringResource(UiR.string.runtime_packets, snapshot.packetsRead))
            Text(stringResource(UiR.string.runtime_replies, snapshot.packetsWritten))
            Text(stringResource(UiR.string.runtime_dns, snapshot.dnsMode.name))
            Text(stringResource(UiR.string.runtime_ip_mtu, snapshot.ipMode.name, snapshot.mtu))
            Text(stringResource(UiR.string.runtime_protection, snapshot.alwaysOn, snapshot.lockdown))
            snapshot.packetDisposition?.let { Text(stringResource(UiR.string.last_strategy_result, it)) }
            snapshot.failure?.let {
                Text(stringResource(UiR.string.runtime_failure, it), color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun connectionTitle(state: VpnRuntimeState): String = when (state) {
    VpnRuntimeState.IDLE -> stringResource(UiR.string.disconnected)
    VpnRuntimeState.PREPARING,
    VpnRuntimeState.AWAITING_VPN_CONSENT,
    VpnRuntimeState.CONNECTING,
    -> stringResource(UiR.string.connecting)
    VpnRuntimeState.ACTIVE_LOCAL_ONLY, VpnRuntimeState.ACTIVE_KURD_LOOPBACK ->
        stringResource(UiR.string.connected_local)
    VpnRuntimeState.ACTIVE_KURD_LIVE -> stringResource(UiR.string.connected_relay)
    VpnRuntimeState.STOPPING -> stringResource(UiR.string.disconnecting)
    VpnRuntimeState.DEGRADED -> stringResource(UiR.string.connection_degraded)
    VpnRuntimeState.FALLING_BACK -> stringResource(UiR.string.connection_falling_back)
    VpnRuntimeState.RECONNECTING -> stringResource(UiR.string.connection_reconnecting)
    VpnRuntimeState.RECOVERING -> stringResource(UiR.string.connection_recovering)
    VpnRuntimeState.BLOCKED -> stringResource(UiR.string.connection_blocked)
    VpnRuntimeState.REVOKED -> stringResource(UiR.string.permission_revoked)
    VpnRuntimeState.FAILED -> stringResource(UiR.string.connection_failed)
}

@Composable
private fun connectionExplanation(snapshot: VpnRuntimeSnapshot): String = when (snapshot.state) {
    VpnRuntimeState.ACTIVE_KURD_LOOPBACK -> stringResource(UiR.string.phase11_local_notice)
    VpnRuntimeState.ACTIVE_KURD_LIVE -> stringResource(UiR.string.phase17_live_notice)
    VpnRuntimeState.BLOCKED,
    VpnRuntimeState.REVOKED,
    VpnRuntimeState.FAILED -> stringResource(UiR.string.failure_explanation)
    else -> stringResource(UiR.string.ready_explanation)
}

private fun formatDuration(seconds: Long): String {
    val hours = seconds / 3600
    val minutes = (seconds % 3600) / 60
    val remaining = seconds % 60
    return "%02d:%02d:%02d".format(hours, minutes, remaining)
}
