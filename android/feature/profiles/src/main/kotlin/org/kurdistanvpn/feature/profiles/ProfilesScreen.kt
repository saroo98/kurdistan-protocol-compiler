// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.profiles

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.WindowManager
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import android.text.BidiFormatter
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.model.EnrollmentKeySummary
import org.kurdistanvpn.core.model.EnrollmentUiState
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.QrDisplayMatrix
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.ui.R as UiR

private enum class SortMode { NAME, GENERATION, EXPIRY }

@Composable
fun ProfilesScreen(
    profiles: List<ProfileSummary>,
    settings: Phase9Settings = Phase9Settings(),
    enrollmentState: EnrollmentUiState = EnrollmentUiState.NoEnrollmentKey,
    enrollmentQr: QrDisplayMatrix? = null,
    onCreateEnrollment: () -> Unit = {},
    onExportEnrollment: (String) -> Unit = {},
    onShowEnrollmentQr: (String) -> Unit = {},
    onDismissEnrollmentQr: () -> Unit = {},
    onDeleteEnrollmentKey: (String) -> Unit = {},
    onDismissEnrollmentAction: () -> Unit = {},
    onSelectProfile: (String) -> Unit = {},
    onToggleFavorite: (String) -> Unit = {},
    onOpenOperator: () -> Unit = {},
    onImportFile: () -> Unit,
    onImportClipboard: () -> Unit,
    onImportLink: (String) -> Unit,
    onScanQr: () -> Unit,
    onExportProfile: (String, String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onBack: () -> Unit,
) {
    var link by remember { mutableStateOf("") }
    var search by remember { mutableStateOf("") }
    var favoritesOnly by remember { mutableStateOf(false) }
    var sortMode by remember { mutableStateOf(SortMode.NAME) }
    var expandedProfile by remember { mutableStateOf<String?>(null) }
    var pendingDelete by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<String?>(null) }
    var pendingEnrollmentFile by remember { mutableStateOf<String?>(null) }
    var pendingEnrollmentQr by remember { mutableStateOf<String?>(null) }
    var exportPassphrase by remember { mutableStateOf("") }
    SecureScreenEffect(enabled = pendingExport != null)
    Column(
        modifier = Modifier.fillMaxSize().widthIn(max = 720.dp).verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(UiR.string.kurd_profiles), style = MaterialTheme.typography.headlineMedium)
        Text(pluralStringResource(UiR.plurals.verified_profile_count, profiles.size, profiles.size))
        Text(stringResource(UiR.string.provider_local_authority))
        EnrollmentSection(
            state = enrollmentState,
            qr = enrollmentQr,
            pendingFile = pendingEnrollmentFile,
            pendingQr = pendingEnrollmentQr,
            onCreate = onCreateEnrollment,
            onBeginFile = { pendingEnrollmentFile = it },
            onConfirmFile = {
                pendingEnrollmentFile = null
                onExportEnrollment(it)
            },
            onBeginQr = { pendingEnrollmentQr = it },
            onConfirmQr = {
                pendingEnrollmentQr = null
                onShowEnrollmentQr(it)
            },
            onCancelConfirmation = {
                pendingEnrollmentFile = null
                pendingEnrollmentQr = null
            },
            onDismissQr = onDismissEnrollmentQr,
            onDeleteKey = onDeleteEnrollmentKey,
            onDismissAction = onDismissEnrollmentAction,
        )
        OutlinedTextField(
            value = search,
            onValueChange = { if (it.length <= 128) search = it },
            label = { Text(stringResource(UiR.string.search_profiles)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("profile_search"),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AssistChip(
                onClick = { favoritesOnly = !favoritesOnly },
                label = { Text(if (favoritesOnly) stringResource(UiR.string.favorites_on) else stringResource(UiR.string.favorites_all)) },
            )
            AssistChip(
                onClick = {
                    sortMode = when (sortMode) {
                        SortMode.NAME -> SortMode.GENERATION
                        SortMode.GENERATION -> SortMode.EXPIRY
                        SortMode.EXPIRY -> SortMode.NAME
                    }
                },
                label = { Text(stringResource(UiR.string.sort_value, sortMode.name)) },
            )
        }
        val visibleProfiles = profiles.asSequence()
            .filter { !favoritesOnly || it.localRecordId in settings.profiles.favoriteLocalRecordIds }
            .filter { search.isBlank() || it.displayAlias.contains(search, ignoreCase = true) }
            .sortedWith(
                when (sortMode) {
                    SortMode.NAME -> compareBy<ProfileSummary> { it.displayAlias.lowercase() }
                    SortMode.GENERATION -> compareByDescending { it.generation }
                    SortMode.EXPIRY -> compareBy { it.expiresAtEpochSeconds }
                },
            ).toList()
        if (visibleProfiles.isEmpty()) Text(stringResource(UiR.string.no_matching_profiles))
        visibleProfiles.forEach { profile ->
            val selected = profile.localRecordId == settings.profiles.activeLocalRecordId
            val favorite = profile.localRecordId in settings.profiles.favoriteLocalRecordIds
            Card(modifier = Modifier.fillMaxWidth().testTag("profile_${profile.localRecordId}")) {
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
                    Text(stringResource(UiR.string.profile_expiry_epoch, profile.expiresAtEpochSeconds))
                    Text(stringResource(UiR.string.profile_compatibility_unavailable))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            enabled = !selected,
                            onClick = { onSelectProfile(profile.localRecordId) },
                        ) { Text(if (selected) stringResource(UiR.string.selected) else stringResource(UiR.string.use_profile)) }
                        TextButton(onClick = { onToggleFavorite(profile.localRecordId) }) {
                            Text(if (favorite) stringResource(UiR.string.unfavorite) else stringResource(UiR.string.favorite))
                        }
                    }
                    TextButton(
                        onClick = {
                            expandedProfile = if (expandedProfile == profile.localRecordId) null else profile.localRecordId
                        },
                    ) { Text(stringResource(UiR.string.profile_details)) }
                    if (expandedProfile == profile.localRecordId) {
                        Text(stringResource(UiR.string.protocol_kurd))
                        Text(stringResource(UiR.string.strategy_matrix_unavailable))
                        Text(stringResource(UiR.string.profile_compatibility_unavailable))
                        Text(stringResource(UiR.string.profile_safe_summary, profile.generation.toString(), profile.trust.name))
                    }
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
        Text(stringResource(UiR.string.add_profile), style = MaterialTheme.typography.titleLarge)
        Button(onClick = onOpenOperator, modifier = Modifier.fillMaxWidth().testTag("profiles_operator")) {
            Text(stringResource(UiR.string.provider_operator_status))
        }
        Button(onClick = onImportFile, modifier = Modifier.fillMaxWidth()) { Text(stringResource(UiR.string.import_profile_file)) }
        Button(onClick = onImportClipboard, modifier = Modifier.fillMaxWidth()) { Text(stringResource(UiR.string.import_clipboard)) }
        Button(onClick = onScanQr, modifier = Modifier.fillMaxWidth()) { Text(stringResource(UiR.string.scan_offline_qr)) }
        OutlinedTextField(
            value = link,
            onValueChange = { if (it.length <= 1_500_032) link = it },
            label = { Text(stringResource(UiR.string.profile_link_label)) },
            singleLine = true,
        )
        Button(
            enabled = link.isNotBlank(),
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
private fun EnrollmentSection(
    state: EnrollmentUiState,
    qr: QrDisplayMatrix?,
    pendingFile: String?,
    pendingQr: String?,
    onCreate: () -> Unit,
    onBeginFile: (String) -> Unit,
    onConfirmFile: (String) -> Unit,
    onBeginQr: (String) -> Unit,
    onConfirmQr: (String) -> Unit,
    onCancelConfirmation: () -> Unit,
    onDismissQr: () -> Unit,
    onDeleteKey: (String) -> Unit,
    onDismissAction: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag("device_enrollment")) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                stringResource(UiR.string.device_enrollment_title),
                style = MaterialTheme.typography.titleLarge,
            )
            Text(stringResource(UiR.string.device_enrollment_explanation))
            val keys = state.enrollmentKeys()
            when (state) {
                EnrollmentUiState.NoEnrollmentKey ->
                    Text(stringResource(UiR.string.device_enrollment_none))
                EnrollmentUiState.Working ->
                    Text(stringResource(UiR.string.device_enrollment_working))
                is EnrollmentUiState.RequestReady ->
                    Text(stringResource(UiR.string.device_enrollment_request_ready))
                is EnrollmentUiState.AwaitingProfile ->
                    Text(stringResource(UiR.string.device_enrollment_awaiting_profile))
                is EnrollmentUiState.ProfileVerified ->
                    Text(stringResource(UiR.string.device_enrollment_profile_verified))
                is EnrollmentUiState.MissingKey ->
                    Text(stringResource(UiR.string.device_enrollment_missing_key, state.fingerprint))
                EnrollmentUiState.KeyInvalidated ->
                    Text(stringResource(UiR.string.device_enrollment_key_invalidated))
                EnrollmentUiState.RecoveryRequired ->
                    Text(stringResource(UiR.string.device_enrollment_recovery_required))
                is EnrollmentUiState.OfferKeyDeletion ->
                    Text(stringResource(UiR.string.device_enrollment_delete_offer))
                is EnrollmentUiState.Failed ->
                    Text(stringResource(UiR.string.device_enrollment_failed, state.error.name))
            }
            keys.forEach { key ->
                Text(
                    stringResource(
                        UiR.string.device_enrollment_fingerprint,
                        BidiFormatter.getInstance().unicodeWrap(key.requestFingerprint.take(16)),
                    ),
                )
                Text(stringResource(UiR.string.device_enrollment_expiry, key.expiresAtEpochSeconds))
                Text(stringResource(UiR.string.device_enrollment_bound_profiles, key.boundProfileCount))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { onBeginFile(key.localRecordId) }) {
                        Text(stringResource(UiR.string.device_enrollment_export_file))
                    }
                    TextButton(onClick = { onBeginQr(key.localRecordId) }) {
                        Text(stringResource(UiR.string.device_enrollment_show_qr))
                    }
                }
            }
            val confirmationId = pendingFile ?: pendingQr
            if (confirmationId != null) {
                Text(stringResource(UiR.string.device_enrollment_public_export_warning))
                Button(
                    onClick = {
                        if (pendingFile != null) onConfirmFile(confirmationId)
                        else onConfirmQr(confirmationId)
                    },
                ) {
                    Text(stringResource(UiR.string.confirm))
                }
                TextButton(onClick = onCancelConfirmation) {
                    Text(stringResource(UiR.string.cancel))
                }
            }
            if (qr != null) {
                RecipientQr(qr)
                Text(stringResource(UiR.string.device_enrollment_qr_public_only))
                TextButton(onClick = onDismissQr) { Text(stringResource(UiR.string.close)) }
            }
            if (state is EnrollmentUiState.OfferKeyDeletion) {
                Button(onClick = { onDeleteKey(state.key.localRecordId) }) {
                    Text(stringResource(UiR.string.device_enrollment_delete_key))
                }
                TextButton(onClick = onDismissAction) {
                    Text(stringResource(UiR.string.keep_enrollment_key))
                }
            }
            Button(
                enabled = state !is EnrollmentUiState.Working,
                onClick = onCreate,
                modifier = Modifier.testTag("create_enrollment_request"),
            ) {
                Text(stringResource(UiR.string.create_device_enrollment_request))
            }
        }
    }
}

private fun EnrollmentUiState.enrollmentKeys(): List<EnrollmentKeySummary> = when (this) {
    is EnrollmentUiState.RequestReady -> keys
    is EnrollmentUiState.AwaitingProfile -> keys
    is EnrollmentUiState.ProfileVerified -> keys
    is EnrollmentUiState.OfferKeyDeletion -> listOf(key)
    else -> emptyList()
}

@Composable
private fun RecipientQr(qr: QrDisplayMatrix) {
    Canvas(
        modifier = Modifier.fillMaxWidth().widthIn(max = 320.dp).aspectRatio(1f)
            .testTag("enrollment_qr"),
    ) {
        drawQr(qr)
    }
}

private fun DrawScope.drawQr(qr: QrDisplayMatrix) {
    val side = size.minDimension
    drawRect(Color.White, size = androidx.compose.ui.geometry.Size(side, side))
    val cell = side / qr.width
    qr.modules.forEachIndexed { index, enabled ->
        if (enabled) {
            drawRect(
                color = Color.Black,
                topLeft = androidx.compose.ui.geometry.Offset(
                    (index % qr.width) * cell,
                    (index / qr.width) * cell,
                ),
                size = androidx.compose.ui.geometry.Size(cell, cell),
            )
        }
    }
}

@Composable
private fun SecureScreenEffect(enabled: Boolean) {
    val activity = LocalContext.current.findActivity()
    DisposableEffect(activity, enabled) {
        if (enabled) activity?.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            if (enabled) activity?.window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
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
        if (preview.deploymentFingerprint.isNotEmpty()) {
            Text(
                stringResource(
                    UiR.string.deployment_fingerprint,
                    BidiFormatter.getInstance().unicodeWrap(preview.deploymentFingerprint),
                ),
                modifier = Modifier.testTag("deployment_fingerprint"),
            )
        }
        if (preview.relayEndpointSummary.isNotEmpty()) {
            Text(
                stringResource(
                    UiR.string.relay_endpoint_summary,
                    BidiFormatter.getInstance().unicodeWrap(preview.relayEndpointSummary),
                ),
            )
        }
        if (preview.authorityScope.isNotEmpty()) {
            Text(stringResource(UiR.string.authority_scope, preview.authorityScope))
        }
        Text(
            if (preview.updatesEnabled) {
                stringResource(UiR.string.profile_updates_enabled, preview.updateLocation)
            } else {
                stringResource(UiR.string.profile_updates_disabled)
            },
        )
        if (preview.ownerControlled) {
            Text(
                stringResource(UiR.string.owner_controlled_source_warning),
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.testTag("owner_controlled_source_warning"),
            )
        }
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
