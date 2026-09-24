// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Shared recoverable shell state. It never performs a product operation automatically. */
@Composable
fun ProductStateContent(
    title: String, message: String, actionLabel: String, onAction: () -> Unit,
    secondaryLabel: String? = null, onSecondary: () -> Unit = {},
) {
    Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)
        .imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(title, style = MaterialTheme.typography.headlineSmall)
        Text(message, style = MaterialTheme.typography.bodyLarge)
        Button(onClick = onAction, modifier = Modifier.heightIn(min = 48.dp)) { Text(actionLabel) }
        if (secondaryLabel != null) OutlinedButton(onClick = onSecondary,
            modifier = Modifier.heightIn(min = 48.dp)) { Text(secondaryLabel) }
    }
}
