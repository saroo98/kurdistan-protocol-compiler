// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.ui.R as UiR

@Composable
fun HomeScreen(
    state: AppState,
    onOpenProfiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenDiagnostics: () -> Unit,
    onClearError: () -> Unit,
) {
    Scaffold { padding ->
        Box(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentAlignment = Alignment.TopCenter,
        ) {
        Column(
            modifier = Modifier.widthIn(max = 720.dp).verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(stringResource(UiR.string.product_name), style = MaterialTheme.typography.headlineLarge)
            Text(stringResource(UiR.string.foundation_label), style = MaterialTheme.typography.titleMedium)
            Card {
                Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(UiR.string.runtime_unavailable), style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(UiR.string.phase9_offline_notice))
                    Text(
                        stringResource(
                            UiR.string.application_state,
                            state::class.simpleName ?: stringResource(UiR.string.unknown),
                        ),
                    )
                }
            }
            if (state is AppState.ImportRejected) {
                Text(stringResource(UiR.string.import_rejected, state.error.name))
                androidx.compose.material3.TextButton(onClick = onClearError) {
                    Text(stringResource(UiR.string.dismiss))
                }
            }
            androidx.compose.material3.Button(onClick = onOpenProfiles) {
                Text(stringResource(UiR.string.profiles))
            }
            androidx.compose.material3.OutlinedButton(onClick = onOpenSettings) {
                Text(stringResource(UiR.string.privacy_recovery))
            }
            androidx.compose.material3.OutlinedButton(onClick = onOpenDiagnostics) {
                Text(stringResource(UiR.string.diagnostics_about))
            }
        }
        }
    }
}
