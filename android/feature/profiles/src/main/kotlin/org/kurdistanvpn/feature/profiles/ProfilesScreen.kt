// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.profiles

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import android.text.BidiFormatter
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.ui.R as UiR

@Composable
fun ProfilesScreen(
    profiles: List<ProfileSummary>,
    onImportFile: () -> Unit,
    onImportClipboard: () -> Unit,
    onImportLink: (String) -> Unit,
    onScanQr: () -> Unit,
    onExportProfile: (String, String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onBack: () -> Unit,
) {
    var link by remember { mutableStateOf("") }
    var pendingDelete by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<String?>(null) }
    var exportPassphrase by remember { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxSize().widthIn(max = 720.dp).verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(UiR.string.kurd_profiles), style = MaterialTheme.typography.headlineMedium)
        Text(pluralStringResource(UiR.plurals.verified_profile_count, profiles.size, profiles.size))
        profiles.forEach { profile ->
            Card {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        stringResource(
                            UiR.string.profile_generation,
                            profile.displayAlias,
                            profile.generation.toString(),
                        ),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(stringResource(UiR.string.profile_trust, profile.trust.name))
                    if (pendingExport == profile.localRecordId) {
                        OutlinedTextField(
                            value = exportPassphrase,
                            onValueChange = { if (it.encodeToByteArray().size <= 1024) exportPassphrase = it },
                            label = { Text(stringResource(UiR.string.profile_export_passphrase)) },
                            supportingText = {
                                Text(stringResource(UiR.string.backup_passphrase_help))
                            },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                        )
                        Button(
                            enabled = exportPassphrase.codePointCount(0, exportPassphrase.length) >= 12,
                            onClick = {
                                val passphrase = exportPassphrase
                                exportPassphrase = ""
                                pendingExport = null
                                onExportProfile(profile.localRecordId, passphrase)
                            },
                        ) {
                            Text(stringResource(UiR.string.confirm_profile_export))
                        }
                        TextButton(
                            onClick = {
                                exportPassphrase = ""
                                pendingExport = null
                            },
                        ) {
                            Text(stringResource(UiR.string.cancel))
                        }
                    } else {
                        TextButton(
                            onClick = {
                                pendingDelete = null
                                exportPassphrase = ""
                                pendingExport = profile.localRecordId
                            },
                        ) {
                            Text(stringResource(UiR.string.export_encrypted_profile))
                        }
                    }
                    if (pendingDelete == profile.localRecordId) {
                        Text(stringResource(UiR.string.delete_profile_warning))
                        Button(
                            onClick = {
                                pendingDelete = null
                                onDeleteProfile(profile.localRecordId)
                            },
                        ) {
                            Text(stringResource(UiR.string.confirm_delete_profile))
                        }
                        TextButton(onClick = { pendingDelete = null }) {
                            Text(stringResource(UiR.string.cancel))
                        }
                    } else {
                        TextButton(
                            onClick = {
                                pendingExport = null
                                exportPassphrase = ""
                                pendingDelete = profile.localRecordId
                            },
                        ) {
                            Text(stringResource(UiR.string.delete_profile))
                        }
                    }
                }
            }
        }
        Button(onClick = onImportFile) { Text(stringResource(UiR.string.import_profile_file)) }
        Button(onClick = onImportClipboard) { Text(stringResource(UiR.string.import_clipboard)) }
        Button(onClick = onScanQr) { Text(stringResource(UiR.string.scan_offline_qr)) }
        OutlinedTextField(
            value = link,
            onValueChange = { if (it.length <= 1_500_032) link = it },
            label = { Text(stringResource(UiR.string.profile_link_label)) },
            singleLine = true,
        )
        Button(
            enabled = link.startsWith("kurd://artifact/"),
            onClick = {
                val value = link
                link = ""
                onImportLink(value)
            },
        ) {
            Text(stringResource(UiR.string.preview_link))
        }
        TextButton(onClick = onBack) { Text(stringResource(UiR.string.back)) }
    }
}

@Composable
fun ImportPreviewScreen(
    preview: RedactedProfilePreview,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().widthIn(max = 720.dp).verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(UiR.string.verify_profile), style = MaterialTheme.typography.headlineMedium)
        Text(stringResource(UiR.string.artifact_class, preview.artifactClass))
        Text(stringResource(UiR.string.audience, preview.audienceClass))
        Text(stringResource(UiR.string.generation, preview.generation.toString()))
        Text(
            stringResource(
                UiR.string.fingerprint,
                BidiFormatter.getInstance().unicodeWrap(preview.contentFingerprint.take(16)),
            ),
        )
        Text(
            stringResource(
                if (preview.sealed) UiR.string.encrypted_profile
                else UiR.string.signed_public_profile,
            ),
        )
        Button(onClick = onConfirm) { Text(stringResource(UiR.string.confirm_encrypted_storage)) }
        TextButton(onClick = onCancel) { Text(stringResource(UiR.string.cancel)) }
    }
}
