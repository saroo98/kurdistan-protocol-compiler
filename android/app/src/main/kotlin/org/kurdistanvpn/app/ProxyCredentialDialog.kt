// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.view.View
import android.widget.TextView
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import kotlinx.coroutines.delay

@Composable
internal fun ProxyRecoveryActions(failure: String?, restart: () -> Unit, applyTunOnly: () -> Unit) {
    if (failure != "PROXY_LISTENER_FAILED") return
    Column {
        Text(stringResource(org.kurdistanvpn.core.ui.R.string.proxy_recovery_help))
        TextButton(onClick = restart, modifier = Modifier.testTag("proxy_restart")) {
            Text(stringResource(org.kurdistanvpn.core.ui.R.string.proxy_restart))
        }
        TextButton(onClick = applyTunOnly, modifier = Modifier.testTag("proxy_apply_tun_only")) {
            Text(stringResource(org.kurdistanvpn.core.ui.R.string.proxy_apply_tun_only))
        }
    }
}

@Composable
internal fun ProxyCredentialDialog(controller: ProxyCredentialController, dismiss: () -> Unit) {
    val secret by controller.visible.collectAsState()
    val unavailable by controller.isUnavailable.collectAsState()
    LaunchedEffect(controller) { while (true) { delay(1000); controller.expire() } }
    DisposableEffect(controller) { onDispose { controller.clear() } }
    AlertDialog(
        onDismissRequest = dismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(stringResource(R.string.proxy_credentials_title)) },
        text = {
            Column {
                Text(stringResource(R.string.proxy_credentials_help))
                if (unavailable) Text(stringResource(R.string.proxy_credentials_unavailable))
                if (secret != null) AndroidView(
                    factory = { context -> TextView(context).apply {
                        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                        setTextIsSelectable(false)
                    } },
                    update = { view -> secret?.let { view.setText(it, 0, it.size) } ?: view.setText("") },
                    onRelease = { it.text = "" },
                    modifier = Modifier.testTag("proxy_credential_value"),
                )
                TextButton(onClick = controller::reveal, modifier = Modifier.testTag("proxy_reveal")) {
                    Text(stringResource(R.string.proxy_credentials_reveal))
                }
                TextButton(onClick = controller::copy, enabled = secret != null, modifier = Modifier.testTag("proxy_copy")) {
                    Text(stringResource(R.string.proxy_credentials_copy))
                }
                TextButton(onClick = controller::rotate, modifier = Modifier.testTag("proxy_rotate")) {
                    Text(stringResource(R.string.proxy_credentials_rotate))
                }
            }
        },
        confirmButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.proxy_credentials_clear)) } },
    )
}
