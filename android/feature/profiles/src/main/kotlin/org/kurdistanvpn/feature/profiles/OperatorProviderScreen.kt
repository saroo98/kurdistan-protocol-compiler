// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.profiles

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.OperatorClientProjection
import org.kurdistanvpn.core.ui.R as UiR

@Composable
fun OperatorProviderScreen(
    projection: OperatorClientProjection,
    onBack: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().widthIn(max = 840.dp)
            .verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(stringResource(UiR.string.provider_operator_status), style = MaterialTheme.typography.headlineMedium)
        Text(stringResource(UiR.string.operator_authority_boundary))
        StatusCard(stringResource(UiR.string.provider_projection), projection.providerAlias)
        StatusCard(
            stringResource(UiR.string.signed_publication),
            projection.publicationGeneration?.let { stringResource(UiR.string.verified_publication_generation, it) }
                ?: stringResource(UiR.string.provider_publication_unavailable),
        )
        StatusCard(
            stringResource(UiR.string.profile_generation_expiry),
            projection.profileGeneration?.let { generation ->
                stringResource(
                    UiR.string.verified_generation_expiry,
                    generation,
                    projection.profileExpiryEpochSeconds?.toString() ?: stringResource(UiR.string.unavailable),
                )
            } ?: stringResource(UiR.string.active_profile_unavailable),
        )
        StatusCard(
            stringResource(UiR.string.relay_compatibility),
            projection.relayCompatibility.name,
        )
        StatusCard(
            stringResource(UiR.string.signed_updates),
            stringResource(
                UiR.string.signed_update_status,
                projection.updateCapability.name,
                projection.lastVerifiedUpdateCategory ?: stringResource(UiR.string.unavailable),
            ),
        )
        StatusCard(
            stringResource(UiR.string.rotation_revocation_emergency),
            stringResource(
                UiR.string.rotation_emergency_status,
                projection.rotationState.name,
                projection.emergencyDenyState.name,
            ),
        )
        Text(stringResource(UiR.string.operator_private_data_boundary))
        TextButton(onClick = onBack) { Text(stringResource(UiR.string.back)) }
    }
}

@Composable
private fun StatusCard(title: String, detail: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(detail, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
