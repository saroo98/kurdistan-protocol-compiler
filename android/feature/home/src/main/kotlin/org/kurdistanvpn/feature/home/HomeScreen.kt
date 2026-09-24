// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.home

import android.os.SystemClock
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.ui.KurdistanIcons
import org.kurdistanvpn.core.ui.KurdistanBrandMark
import org.kurdistanvpn.core.ui.LocalReducedMotion
import org.kurdistanvpn.core.ui.LocalEssentialBoundaryWidth
import org.kurdistanvpn.core.ui.R as UiR
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.validatedForDisplay

@Composable
fun HomeScreen(
    state: AppState,
    settings: ProductSettings = ProductSettings(),
    vpnRuntime: VpnRuntimeSnapshot,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit,
    onOpenProfiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenDiagnostics: () -> Unit,
    onClearError: () -> Unit,
    onSystemVpnSettings: () -> Unit = onOpenSettings,
    connectionState: org.kurdistanvpn.core.model.ConnectionState? = null,
) {
    val profiles = (state as? AppState.Ready)?.profiles.orEmpty()
    val selectedProfile = profiles.firstOrNull {
        it.localRecordId == settings.profiles.activeLocalRecordId
    }
    val windowWidth = with(LocalDensity.current) { LocalWindowInfo.current.containerSize.width.toDp() }
    val gutter = if (windowWidth < 600.dp) 16.dp else 24.dp
    val twoColumns = windowWidth >= 840.dp && LocalDensity.current.fontScale <= 1f
    var detailsExpanded by rememberSaveable { mutableStateOf(false) }

    Scaffold { padding ->
        Box(
            Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding),
            contentAlignment = Alignment.TopCenter,
        ) {
            Column(
                modifier = Modifier.widthIn(max = 960.dp + gutter * 2).fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = gutter, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Box(Modifier.fillMaxWidth().heightIn(min = 40.dp), contentAlignment = Alignment.Center) {
                    KurdistanBrandMark(Modifier.size(32.dp).testTag("home_brand"))
                }
                val hero: @Composable () -> Unit = {
                    ConnectionHero(vpnRuntime, selectedProfile != null, onStartVpn, onStopVpn, onOpenProfiles, onOpenSettings, onSystemVpnSettings, connectionState)
                }
                val profile: @Composable () -> Unit = {
                    SelectedProfileCard(selectedProfile, onOpenProfiles)
                }
                if (twoColumns) {
                    Row(horizontalArrangement = Arrangement.spacedBy(24.dp), verticalAlignment = Alignment.Top) {
                        Box(Modifier.weight(1f)) { hero() }
                        Box(Modifier.weight(1f)) { profile() }
                    }
                } else {
                    hero()
                    // A blocking storage explanation must remain visible outside Details.
                    RecoveryStatusCard(state, onOpenSettings)
                    profile()
                }
                if (twoColumns) RecoveryStatusCard(state, onOpenSettings)
                if (state is AppState.ImportRejected) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                            contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        ),
                    ) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(stringResource(UiR.string.import_rejected, state.error.name))
                            TextButton(onClick = onClearError, modifier = Modifier.heightIn(min = 48.dp)) {
                                Text(stringResource(UiR.string.dismiss))
                            }
                        }
                    }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                val disclosureState = stringResource(
                    if (detailsExpanded) UiR.string.uiux_expanded else UiR.string.uiux_collapsed,
                )
                TextButton(
                    onClick = { detailsExpanded = !detailsExpanded },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)
                        .testTag("home_details").semantics { stateDescription = disclosureState },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onSurface),
                ) {
                    Text(
                        stringResource(UiR.string.connection_details),
                        style = MaterialTheme.typography.titleLarge,
                        modifier = Modifier.weight(1f),
                    )
                    Icon(
                        if (detailsExpanded) KurdistanIcons.ChevronDown else KurdistanIcons.ChevronForward,
                        contentDescription = null,
                    )
                }
                if (detailsExpanded) {
                    ProfileDetails(selectedProfile, settings, vpnRuntime)
                    RuntimeDetails(vpnRuntime)
                    OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline),
                        onClick = onOpenDiagnostics,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("home_diagnostics"),
                        shape = MaterialTheme.shapes.small,
                    ) { Text(stringResource(UiR.string.diagnostics_about)) }
                    Text(
                        stringResource(UiR.string.phase13_external_boundary),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun RecoveryStatusCard(state: AppState, onOpenRecovery: () -> Unit) {
    val detail = when (state) {
        AppState.LockedStorage -> stringResource(UiR.string.recovery_storage_locked)
        AppState.MigrationRequired -> stringResource(UiR.string.recovery_migration_required)
        AppState.CoreIncompatible -> stringResource(UiR.string.core_incompatible)
        AppState.CoreUnavailable -> stringResource(UiR.string.core_unavailable)
        AppState.KeyInvalidated -> stringResource(UiR.string.recovery_key_invalidated)
        AppState.DegradedStorage -> stringResource(UiR.string.recovery_storage_degraded)
        AppState.Quarantined -> stringResource(UiR.string.recovery_quarantined)
        AppState.FatalRecovery -> stringResource(UiR.string.recovery_fatal)
        else -> null
    } ?: return
    Card(
        modifier = Modifier.fillMaxWidth().testTag("recovery_status"),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer, contentColor = MaterialTheme.colorScheme.onErrorContainer),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(UiR.string.recovery_required), style = MaterialTheme.typography.titleMedium)
            Text(detail, color = MaterialTheme.colorScheme.onErrorContainer)
            if (state != AppState.CoreIncompatible && state != AppState.CoreUnavailable) {
                OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), onClick = onOpenRecovery, modifier = Modifier.heightIn(min = 56.dp), shape = MaterialTheme.shapes.small) { Text(stringResource(UiR.string.open_recovery_settings)) }
            }
        }
    }
}


@Composable
private fun ConnectionHero(
    snapshot: VpnRuntimeSnapshot,
    canStart: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onOpenProfiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onSystemVpnSettings: () -> Unit,
    connectionState: org.kurdistanvpn.core.model.ConnectionState?,
) {
    // Native acknowledgement alone is not proof that device traffic is protected.
    val proxyOnly = snapshot.validatedForDisplay().presentation?.let {
        snapshot.state == VpnRuntimeState.ACTIVE_KURD_LIVE &&
            it.nativeSessionId == it.sessionId && it.proxySessionId == it.sessionId && it.tunSessionId == null
    } == true
    val verifiedDisplay = when {
        snapshot.state == VpnRuntimeState.ACTIVE_KURD_LIVE && connectionState !is org.kurdistanvpn.core.model.ConnectionState.Connected ->
            snapshot.copy(state = VpnRuntimeState.RECOVERING)
        snapshot.state == VpnRuntimeState.DEGRADED && connectionState !is org.kurdistanvpn.core.model.ConnectionState.Degraded ->
            snapshot.copy(state = VpnRuntimeState.RECOVERING)
        else -> snapshot
    }
    val pending = snapshot.state in setOf(
        VpnRuntimeState.PREPARING, VpnRuntimeState.AWAITING_VPN_CONSENT,
        VpnRuntimeState.CONNECTING, VpnRuntimeState.FALLING_BACK,
        VpnRuntimeState.RECONNECTING, VpnRuntimeState.RECOVERING,
    )
    val disconnect = snapshot.state in setOf(
        VpnRuntimeState.ACTIVE_KURD_LIVE, VpnRuntimeState.DEGRADED,
    )
    val warning = snapshot.state in setOf(
        VpnRuntimeState.DEGRADED, VpnRuntimeState.FALLING_BACK, VpnRuntimeState.RECOVERING,
    )
    val error = snapshot.state in setOf(VpnRuntimeState.BLOCKED, VpnRuntimeState.REVOKED, VpnRuntimeState.FAILED)
    val iconColor = when {
        error -> MaterialTheme.colorScheme.error
        warning -> MaterialTheme.colorScheme.tertiary
        pending -> MaterialTheme.colorScheme.primary
        verifiedDisplay.state == VpnRuntimeState.ACTIVE_KURD_LIVE -> MaterialTheme.colorScheme.secondary
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val titleStyle = MaterialTheme.typography.headlineLarge
    val iconTop = with(LocalDensity.current) { (titleStyle.lineHeight.toDp() - 24.dp) / 2 }
    val stopping = snapshot.state == VpnRuntimeState.STOPPING
    val showSun = snapshot.state == VpnRuntimeState.IDLE || snapshot.state == VpnRuntimeState.ACTIVE_KURD_LIVE
    Card(
        modifier = Modifier.fillMaxWidth().testTag("connection_hero"),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        shape = MaterialTheme.shapes.medium,
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.Top) {
                if ((pending || stopping) && !LocalReducedMotion.current) {
                    CircularProgressIndicator(
                        modifier = Modifier.padding(top = iconTop).size(24.dp),
                        color = iconColor,
                        strokeWidth = 2.dp,
                    )
                } else {
                    Icon(
                        if (showSun) KurdistanIcons.Sun else if (warning || error) KurdistanIcons.Warning else KurdistanIcons.Info,
                        contentDescription = null,
                        tint = iconColor,
                        modifier = Modifier.padding(top = iconTop).size(24.dp)
                            .then(if (showSun) Modifier.testTag("home_sun") else Modifier),
                    )
                }
                Text(
                    if (proxyOnly) stringResource(UiR.string.local_proxy_active) else connectionTitle(verifiedDisplay.state),
                    style = titleStyle,
                    modifier = Modifier.weight(1f).semantics { heading(); liveRegion = LiveRegionMode.Polite },
                )
            }
            Text(if (proxyOnly) stringResource(UiR.string.local_proxy_not_device_vpn) else connectionExplanation(verifiedDisplay),
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            val actionModifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)
            when {
                stopping -> Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                    onClick = {},
                    enabled = false,
                    modifier = actionModifier.testTag("home_stopping"),
                    shape = MaterialTheme.shapes.small,
                    colors = ButtonDefaults.buttonColors(
                        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                        disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    ),
                ) { Text(stringResource(UiR.string.disconnecting)) }
                (disconnect && (snapshot.alwaysOn != false || snapshot.lockdown != false)) ||
                    (pending && (snapshot.alwaysOn == true || snapshot.lockdown == true)) -> OutlinedButton(
                    onClick = onSystemVpnSettings, modifier = actionModifier.testTag("home_system_vpn"),
                ) { Text(stringResource(UiR.string.open_system_vpn_settings)) }
                pending || disconnect -> OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline),
                    onClick = onStop,
                    modifier = actionModifier.testTag(if (pending) "home_cancel" else "home_disconnect"),
                    shape = MaterialTheme.shapes.small,
                ) { Text(stringResource(if (pending) UiR.string.cancel else UiR.string.disconnect)) }
                snapshot.state == VpnRuntimeState.BLOCKED -> Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                    onClick = onOpenSettings,
                    modifier = actionModifier.testTag("home_review_restriction"),
                    shape = MaterialTheme.shapes.small,
                ) { Text(stringResource(UiR.string.uiux_review_restriction)) }
                snapshot.state == VpnRuntimeState.REVOKED -> Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                    onClick = onOpenProfiles,
                    modifier = actionModifier.testTag("home_choose_profile"),
                    shape = MaterialTheme.shapes.small,
                ) { Text(stringResource(UiR.string.uiux_choose_profile)) }
                !canStart -> Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                    onClick = onOpenProfiles,
                    modifier = actionModifier.testTag("home_add_profile"),
                    shape = MaterialTheme.shapes.small,
                ) { Text(stringResource(UiR.string.add_profile)) }
                else -> Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                    onClick = onStart,
                    modifier = actionModifier.testTag("connect_button"),
                    shape = MaterialTheme.shapes.small,
                ) {
                    Text(stringResource(if (snapshot.state == VpnRuntimeState.FAILED) UiR.string.uiux_try_again else UiR.string.connect))
                }
            }
            if (!canStart) Text(
                stringResource(UiR.string.profile_required_for_vpn),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun SelectedProfileCard(profile: ProfileSummary?, onOpenProfiles: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp).testTag("home_selected_profile"),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(UiR.string.uiux_selected_profile),
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.weight(1f).semantics { heading() },
            )
            if (profile != null) TextButton(
                onClick = onOpenProfiles,
                modifier = Modifier.weight(1f, fill = false).heightIn(min = 48.dp).testTag("home_profiles"),
            ) { Text(stringResource(UiR.string.uiux_change_profile)) }
        }
        Text(
            profile?.displayAlias ?: stringResource(UiR.string.no_active_profile),
            style = if (profile == null) MaterialTheme.typography.bodyMedium else MaterialTheme.typography.titleMedium,
        )
    }
}

@Composable
private fun ProfileDetails(profile: ProfileSummary?, settings: ProductSettings, snapshot: VpnRuntimeSnapshot) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(UiR.string.uiux_selected_profile), style = MaterialTheme.typography.titleLarge)
        if (profile != null) {
            Text(stringResource(UiR.string.profile_generation_value, profile.generation.toString()))
            Text(stringResource(UiR.string.profile_trust, profile.trust.name))
        }
        Text(stringResource(UiR.string.protocol_kurd))
        Text(settings.connection.selectionMode.name, color = MaterialTheme.colorScheme.onSurfaceVariant)
        val digest = snapshot.planDigest
        if (digest == null) {
            Text(stringResource(UiR.string.session_plan_unavailable))
        } else {
            Text(stringResource(UiR.string.session_plan_digest, digest.take(16)))
            snapshot.strategyFingerprint?.let { Text(stringResource(UiR.string.selected_strategy_fingerprint, it.take(16))) }
            snapshot.relayFingerprint?.let { Text(stringResource(UiR.string.selected_relay_fingerprint, it.take(16))) }
            Text(stringResource(UiR.string.fallback_status_value, snapshot.packetDisposition ?: "NOT_USED"))
        }
    }
}

@Composable
private fun RuntimeDetails(snapshot: VpnRuntimeSnapshot) {
    val durationSeconds = if (snapshot.startedAtElapsedRealtime > 0) {
        ((SystemClock.elapsedRealtime() - snapshot.startedAtElapsedRealtime) / 1000).coerceAtLeast(0)
    } else 0
    Column(modifier = Modifier.fillMaxWidth()) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(UiR.string.connection_details), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(UiR.string.runtime_state, snapshot.state.name))
            Text(stringResource(UiR.string.connected_duration, formatDuration(durationSeconds)))
            Text(stringResource(UiR.string.runtime_packets, snapshot.packetsRead))
            Text(stringResource(UiR.string.runtime_replies, snapshot.packetsWritten))
            Text(stringResource(UiR.string.runtime_dns, snapshot.dnsMode.name))
            Text(stringResource(UiR.string.runtime_ip_mtu, snapshot.ipMode.name, snapshot.mtu))
            Text(stringResource(UiR.string.runtime_protection,
                snapshot.alwaysOn?.toString() ?: stringResource(UiR.string.unknown),
                snapshot.lockdown?.toString() ?: stringResource(UiR.string.unknown)))
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
