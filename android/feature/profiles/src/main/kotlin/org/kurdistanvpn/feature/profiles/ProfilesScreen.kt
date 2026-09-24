// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.feature.profiles

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.WindowManager
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.AssistChip
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import org.kurdistanvpn.core.ui.KurdistanOutlinedTextField as OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.kurdistanvpn.core.ui.kurdistanBidiFormatter
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.model.EnrollmentKeySummary
import org.kurdistanvpn.core.model.EnrollmentUiState
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.QrDisplayMatrix
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.ui.LocalEssentialBoundaryWidth
import org.kurdistanvpn.core.ui.KurdistanDialogAppearance
import org.kurdistanvpn.core.ui.R as UiR


import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.foundation.layout.RowScope
import androidx.compose.ui.graphics.Shape
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconToggleButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.kurdistanvpn.core.model.ProfileTrust
import org.kurdistanvpn.core.ui.KurdistanIcons

private enum class SortMode { NAME, GENERATION, EXPIRY }

@Composable
fun ProfilesScreen(
    profiles: List<ProfileSummary>,
    settings: ProductSettings = ProductSettings(),
    enrollmentState: EnrollmentUiState = EnrollmentUiState.NoEnrollmentKey,
    enrollmentQr: QrDisplayMatrix? = null,
    onCreateEnrollment: () -> Unit = {},
    onExportEnrollment: (String) -> Unit = {},
    onShowEnrollmentQr: (String) -> Unit = {},
    onDismissEnrollmentQr: () -> Unit = {},
    onDeleteEnrollmentKey: (String) -> Unit = {},
    onDismissEnrollmentAction: () -> Unit = {},
    onSelectProfile: (String) -> Unit = {},
    onReviewProfile: (String) -> Unit = {},
    onToggleFavorite: (String) -> Unit = {},
    onOpenOperator: () -> Unit = {},
    onImportFile: () -> Unit,
    onImportClipboard: () -> Unit,
    onImportLink: (String) -> Unit,
    onScanQr: () -> Unit,
    onExportProfile: (String, String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onBack: () -> Unit,
    showBack: Boolean = true,
    connectionWillStopOnSelection: Boolean = false,
    detailProfileId: String? = null,
    onOpenDetail: ((String) -> Unit)? = null,
) {

    var link by remember { mutableStateOf("") }
    var search by remember { mutableStateOf("") }
    var favoritesOnly by rememberSaveable { mutableStateOf(false) }
    var sortMode by rememberSaveable { mutableStateOf(SortMode.NAME) }
    var expandedProfile by rememberSaveable(detailProfileId) { mutableStateOf(detailProfileId) }
    var adding by remember { mutableStateOf(false) }
    var sorting by remember { mutableStateOf(false) }
    var pendingSelection by remember { mutableStateOf<String?>(null) }
    var selectionReason by remember { mutableStateOf<Int?>(null) }
    var pendingDelete by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<String?>(null) }
    var pendingEnrollmentFile by remember { mutableStateOf<String?>(null) }
    var pendingEnrollmentQr by remember { mutableStateOf<String?>(null) }
    var exportPassphrase by remember { mutableStateOf("") }
    SecureScreenEffect(enabled = pendingExport != null)

    // Preview approval is transient. The current model is checked again before any effect.
    LaunchedEffect(profiles, settings.profiles.activeLocalRecordId, pendingSelection) {
        pendingSelection?.let { id ->
            val reason = profiles.find { it.localRecordId == id }.selectionRestriction()
            if (reason != null || id == settings.profiles.activeLocalRecordId) {
                pendingSelection = null
                selectionReason = reason
            }
        }
    }
    val gutter = if (with(LocalDensity.current) { LocalWindowInfo.current.containerSize.width.toDp() } < 600.dp) 16.dp else 24.dp
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
    Column(
        modifier = Modifier.widthIn(max = 720.dp).fillMaxSize()
            .verticalScroll(rememberScrollState()).padding(horizontal = gutter, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (showBack) ProfileTextButton(onClick = onBack, modifier = Modifier.heightIn(min = 48.dp)) {
            Text(stringResource(UiR.string.back))
        }
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(stringResource(UiR.string.kurd_profiles), style = MaterialTheme.typography.headlineMedium)
            if (profiles.isNotEmpty()) ProfileTextButton(
                onClick = { adding = true },
                modifier = Modifier.heightIn(min = 48.dp).testTag("profiles_add"),
            ) { Text(stringResource(UiR.string.add_profile)) }
        }
        selectionReason?.let {
            Text(stringResource(it), color = MaterialTheme.colorScheme.error,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag("profile_selection_reason"))
        }
        if (profiles.isEmpty()) {
            Text(stringResource(UiR.string.uiux_no_profiles), style = MaterialTheme.typography.titleLarge)
            Text(stringResource(UiR.string.uiux_no_profiles_help), color = MaterialTheme.colorScheme.onSurfaceVariant)
            ProfileButton(onClick = { adding = true }, shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("profiles_add")) {
                Text(stringResource(UiR.string.add_profile))
            }
        } else {
            OutlinedTextField(
                value = search,
                onValueChange = { if (it.length <= 128) search = it },
                label = { Text(stringResource(UiR.string.search_profiles)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("profile_search"),
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = favoritesOnly, border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline),
                    onClick = { favoritesOnly = !favoritesOnly },
                    label = { Text(if (favoritesOnly) stringResource(UiR.string.favorites_on) else stringResource(UiR.string.favorites_all)) },
                    modifier = Modifier.heightIn(min = 48.dp).testTag("profile_favorites"),
                )
                AssistChip(border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), onClick = { sorting = true },
                    label = { Text(stringResource(UiR.string.sort_value, stringResource(sortMode.label()))) },
                    modifier = Modifier.heightIn(min = 48.dp).testTag("profile_sort"))
            }
        }
        val visibleProfiles = profiles.asSequence()
            .filter { !favoritesOnly || it.localRecordId in settings.profiles.favoriteLocalRecordIds }
            .filter { search.isBlank() || it.displayAlias.contains(search, ignoreCase = true) }
            .sortedWith(
                when (sortMode) {
                    SortMode.NAME -> compareBy<ProfileSummary> { it.displayAlias.lowercase() }
                    SortMode.GENERATION -> compareByDescending { it.generation }
                    SortMode.EXPIRY -> compareBy { it.expiresAtEpochSeconds }
                }.thenBy { it.localRecordId },
            ).toList()
        if (profiles.isNotEmpty() && visibleProfiles.isEmpty()) {
            Text(stringResource(UiR.string.no_matching_profiles))
            ProfileTextButton(onClick = { search = ""; favoritesOnly = false }, modifier = Modifier.heightIn(min = 48.dp)) {
                Text(stringResource(UiR.string.uiux_clear_filters))
            }
        }
        visibleProfiles.forEach { profile ->
            val selected = profile.localRecordId == settings.profiles.activeLocalRecordId
            val favorite = profile.localRecordId in settings.profiles.favoriteLocalRecordIds
            val expanded = expandedProfile == profile.localRecordId
            val restriction = profile.selectionRestriction()
            val detailState = stringResource(if (expanded) UiR.string.uiux_expanded else UiR.string.uiux_collapsed)
            Card(
                modifier = Modifier.fillMaxWidth().testTag("profile_${profile.localRecordId}"),
                shape = MaterialTheme.shapes.medium,
                colors = CardDefaults.cardColors(
                    containerColor = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
                    contentColor = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface),
                border = BorderStroke(if (selected) LocalEssentialBoundaryWidth.current else 1.dp, if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant),
                elevation = CardDefaults.cardElevation(0.dp),
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
                        Column(
                            Modifier.weight(1f).heightIn(min = 48.dp)
                                .clickable(role = Role.Button) {
                                    if (detailProfileId == null && onOpenDetail != null) {
                                        onOpenDetail(profile.localRecordId)
                                        return@clickable
                                    }
                                    expandedProfile = if (expanded) null else profile.localRecordId
                                    pendingExport = null
                                    pendingDelete = null
                                    exportPassphrase = ""
                                }
                                .semantics { stateDescription = detailState }
                                .testTag("profile_details_${profile.localRecordId}"),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Text(kurdistanBidiFormatter().unicodeWrap(profile.displayAlias), style = MaterialTheme.typography.titleMedium)
                            Text(if (restriction == null) stringResource(UiR.string.profile_expiry_epoch, profile.expiresAtEpochSeconds) else stringResource(restriction),
                                style = MaterialTheme.typography.bodyMedium)
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(stringResource(UiR.string.profile_details), style = MaterialTheme.typography.labelMedium,
                                    modifier = Modifier.weight(1f))
                                Icon(if (expanded) KurdistanIcons.ChevronDown else KurdistanIcons.ChevronForward, null, Modifier.size(24.dp))
                            }
                        }
                        IconToggleButton(
                            checked = favorite,
                            onCheckedChange = { onToggleFavorite(profile.localRecordId) },
                            modifier = Modifier.size(48.dp).testTag("profile_favorite_${profile.localRecordId}"),
                        ) {
                            Icon(if (favorite) KurdistanIcons.StarFilled else KurdistanIcons.Star,
                                stringResource(if (favorite) UiR.string.uiux_unfavorite_profile else UiR.string.uiux_favorite_profile, profile.displayAlias),
                                Modifier.size(24.dp))
                        }
                    }
                    if (selected) {
                        Text(stringResource(UiR.string.profile_selected), style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.testTag("profile_selected_${profile.localRecordId}"))
                    } else if (restriction == null) {
                        ProfileTextButton(
                            onClick = {
                                val current = profiles.find { it.localRecordId == profile.localRecordId }
                                val reason = current.selectionRestriction()
                                if (reason != null) selectionReason = reason
                                else if (current?.localRecordId != settings.profiles.activeLocalRecordId) {
                                    onReviewProfile(profile.localRecordId)
                                    if (connectionWillStopOnSelection) pendingSelection = profile.localRecordId
                                    else onSelectProfile(profile.localRecordId)
                                }
                            },
                            modifier = Modifier.heightIn(min = 48.dp).testTag("profile_select_${profile.localRecordId}"),
                        ) { Text(stringResource(UiR.string.use_profile)) }
                    }
                    if (expanded) {
                        Text(stringResource(UiR.string.protocol_kurd))
                        Text(stringResource(UiR.string.strategy_matrix_unavailable))
                        Text(stringResource(UiR.string.profile_compatibility_unavailable))
                        Text(stringResource(UiR.string.profile_safe_summary, profile.generation.toString(), profile.trust.name))
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
                            ProfileButton(
                                enabled = exportPassphrase.codePointCount(0, exportPassphrase.length) >= 12,
                                onClick = {
                                    val passphrase = exportPassphrase
                                    exportPassphrase = ""
                                    pendingExport = null
                                    if (passphrase.codePointCount(0, passphrase.length) >= 12) onExportProfile(profile.localRecordId, passphrase)
                                },
                            ) {
                                Text(stringResource(UiR.string.confirm_profile_export))
                            }
                            ProfileTextButton(
                                onClick = {
                                    exportPassphrase = ""
                                    pendingExport = null
                                },
                            ) {
                                Text(stringResource(UiR.string.cancel))
                            }
                        } else {
                            ProfileTextButton(
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
                            ProfileButton(
                                destructive = true,
                                onClick = {
                                    val confirmed = pendingDelete == profile.localRecordId
                                    pendingDelete = null
                                    if (confirmed) onDeleteProfile(profile.localRecordId)
                                },
                            ) {
                                Text(stringResource(UiR.string.confirm_delete_profile))
                            }
                            ProfileTextButton(onClick = { pendingDelete = null }) {
                                Text(stringResource(UiR.string.cancel))
                            }
                        } else {
                            ProfileTextButton(
                                onClick = {
                                    pendingExport = null
                                    exportPassphrase = ""
                                    pendingDelete = profile.localRecordId
                                    onReviewProfile(profile.localRecordId)
                                },
                            ) {
                                Text(stringResource(UiR.string.delete_profile))
                            }
                        }
                    }
                }
            }
        }
        EnrollmentSection(
            state = enrollmentState,
            qr = enrollmentQr,
            pendingFile = pendingEnrollmentFile,
            pendingQr = pendingEnrollmentQr,
            onCreate = onCreateEnrollment,
            onBeginFile = { pendingEnrollmentFile = it },
            onConfirmFile = {
                val confirmed = pendingEnrollmentFile == it
                pendingEnrollmentFile = null
                if (confirmed) onExportEnrollment(it)
            },
            onBeginQr = { pendingEnrollmentQr = it },
            onConfirmQr = {
                val confirmed = pendingEnrollmentQr == it
                pendingEnrollmentQr = null
                if (confirmed) onShowEnrollmentQr(it)
            },
            onCancelConfirmation = {
                pendingEnrollmentFile = null
                pendingEnrollmentQr = null
            },
            onDismissQr = onDismissEnrollmentQr,
            onDeleteKey = onDeleteEnrollmentKey,
            onDismissAction = onDismissEnrollmentAction,
        )
        ProfileTextButton(onClick = onOpenOperator, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("profiles_operator")) {
            Text(stringResource(UiR.string.provider_operator_status))
        }
    }
    }
    if (adding) ProfileDialog(stringResource(UiR.string.add_profile), selection = true, onDismiss = { adding = false; link = "" }) {
        OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), onClick = { if (adding) { adding = false; link = ""; onImportFile() } }, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp), shape = MaterialTheme.shapes.small) { Text(stringResource(UiR.string.import_profile_file)) }
        OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), onClick = { if (adding) { adding = false; link = ""; onImportClipboard() } }, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp), shape = MaterialTheme.shapes.small) { Text(stringResource(UiR.string.import_clipboard)) }
        OutlinedButton(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), border = BorderStroke(LocalEssentialBoundaryWidth.current, MaterialTheme.colorScheme.outline), onClick = { if (adding) { adding = false; link = ""; onScanQr() } }, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp), shape = MaterialTheme.shapes.small) { Text(stringResource(UiR.string.scan_offline_qr)) }
        OutlinedTextField(
            value = link,
            onValueChange = { if (it.length <= 1_500_032) link = it },
            label = { Text(stringResource(UiR.string.profile_link_label)) },
            singleLine = true,
        )
        ProfileButton(
            enabled = link.isNotBlank(),
            onClick = {
                val value = link
                link = ""
                adding = false
                if (value.isNotBlank()) onImportLink(value)
            },
        ) {
            Text(stringResource(UiR.string.preview_link))
        }
        ProfileTextButton(onClick = { adding = false; link = "" }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
            Text(stringResource(UiR.string.cancel))
        }
    }
    if (sorting) ProfileDialog(stringResource(UiR.string.uiux_sort_profiles), selection = true, onDismiss = { sorting = false }) {
        SortMode.entries.forEach { mode ->
            Row(
                Modifier.fillMaxWidth().heightIn(min = 48.dp)
                    .selectable(selected = sortMode == mode, role = Role.RadioButton, onClick = { sortMode = mode; sorting = false })
                    .testTag("profile_sort_${mode.name}"),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = sortMode == mode, onClick = null)
                Text(stringResource(mode.label()), Modifier.padding(start = 12.dp).weight(1f))
            }
        }
        ProfileTextButton(onClick = { sorting = false }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
            Text(stringResource(UiR.string.cancel))
        }
    }
    pendingSelection?.let { id ->
        val current = profiles.find { it.localRecordId == id }
        ProfileDialog(stringResource(UiR.string.uiux_select_confirmation_title), onDismiss = { pendingSelection = null }) {
            Text(stringResource(UiR.string.uiux_select_confirmation_body, current?.displayAlias.orEmpty()))
            ProfileButton(
                onClick = {
                    val applying = pendingSelection
                    pendingSelection = null
                    if (applying != null) {
                        val candidate = profiles.find { it.localRecordId == applying }
                        val reason = candidate.selectionRestriction()
                        if (reason != null) selectionReason = reason
                        else if (candidate?.localRecordId != settings.profiles.activeLocalRecordId) onSelectProfile(applying)
                    }
                },
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("profile_confirm_selection"),
            ) { Text(stringResource(UiR.string.uiux_disconnect_select)) }
            ProfileTextButton(onClick = { pendingSelection = null }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("profile_cancel_selection")) {
                Text(stringResource(UiR.string.cancel))
            }
        }
    }
}

private fun SortMode.label(): Int = when (this) {
    SortMode.NAME -> UiR.string.uiux_sort_name
    SortMode.GENERATION -> UiR.string.uiux_sort_generation
    SortMode.EXPIRY -> UiR.string.uiux_sort_expiry
}

private fun ProfileSummary?.selectionRestriction(): Int? = when {
    this == null -> UiR.string.uiux_profile_unavailable
    trust != ProfileTrust.VERIFIED_NONPRODUCTION && trust != ProfileTrust.VERIFIED_PRODUCTION -> UiR.string.uiux_profile_unavailable
    expiresAtEpochSeconds <= System.currentTimeMillis() / 1000 -> UiR.string.uiux_profile_expired
    else -> null
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProfileDialog(title: String, selection: Boolean = false, onDismiss: () -> Unit, content: @Composable () -> Unit) {
    @Composable fun Body() {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(title, style = MaterialTheme.typography.headlineMedium)
            content()
        }
    }
    if (selection && with(LocalDensity.current) { LocalWindowInfo.current.containerSize.width.toDp() } < 600.dp) {
        ModalBottomSheet(scrimColor = androidx.compose.ui.graphics.Color.Black.copy(alpha = 0.56f),
            onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = MaterialTheme.shapes.large, containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) { Body() }
    } else {
        Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            KurdistanDialogAppearance()
            Surface(
                Modifier.padding(24.dp).widthIn(max = 560.dp).fillMaxWidth(),
                shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainerHigh,
            ) { Body() }
        }
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
                        kurdistanBidiFormatter().unicodeWrap(key.requestFingerprint.take(16)),
                    ),
                )
                Text(stringResource(UiR.string.device_enrollment_expiry, key.expiresAtEpochSeconds))
                Text(stringResource(UiR.string.device_enrollment_bound_profiles, key.boundProfileCount))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    ProfileTextButton(onClick = { onBeginFile(key.localRecordId) }) {
                        Text(stringResource(UiR.string.device_enrollment_export_file))
                    }
                    ProfileTextButton(onClick = { onBeginQr(key.localRecordId) }) {
                        Text(stringResource(UiR.string.device_enrollment_show_qr))
                    }
                }
            }
            val confirmationId = pendingFile ?: pendingQr
            if (confirmationId != null) {
                Text(stringResource(UiR.string.device_enrollment_public_export_warning))
                ProfileButton(
                    onClick = {
                        if (pendingFile != null) onConfirmFile(confirmationId)
                        else onConfirmQr(confirmationId)
                    },
                ) {
                    Text(stringResource(UiR.string.confirm))
                }
                ProfileTextButton(onClick = onCancelConfirmation) {
                    Text(stringResource(UiR.string.cancel))
                }
            }
            if (qr != null) {
                RecipientQr(qr)
                Text(stringResource(UiR.string.device_enrollment_qr_public_only))
                ProfileTextButton(onClick = onDismissQr) { Text(stringResource(UiR.string.close)) }
            }
            if (state is EnrollmentUiState.OfferKeyDeletion) {
                ProfileButton(onClick = { onDeleteKey(state.key.localRecordId) }) {
                    Text(stringResource(UiR.string.device_enrollment_delete_key))
                }
                ProfileTextButton(onClick = onDismissAction) {
                    Text(stringResource(UiR.string.keep_enrollment_key))
                }
            }
            ProfileButton(
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
                kurdistanBidiFormatter().unicodeWrap(preview.contentFingerprint.take(16)),
            ),
        )
        if (preview.deploymentFingerprint.isNotEmpty()) {
            Text(
                stringResource(
                    UiR.string.deployment_fingerprint,
                    kurdistanBidiFormatter().unicodeWrap(preview.deploymentFingerprint),
                ),
                modifier = Modifier.testTag("deployment_fingerprint"),
            )
        }
        if (preview.relayEndpoint == org.kurdistanvpn.core.model.RedactedFieldPresence.PROVIDED_REDACTED) {
            Text(
                stringResource(
                    UiR.string.relay_endpoint_summary,
                    stringResource(UiR.string.preview_detail_redacted),
                ),
            )
        }
        if (preview.authorityScope == org.kurdistanvpn.core.model.PreviewAuthorityScope.DEPLOYMENT_LOCAL) {
            Text(stringResource(UiR.string.authority_scope, stringResource(UiR.string.preview_deployment_local)))
        }
        Text(
            if (preview.updatesEnabled) {
                stringResource(UiR.string.profile_updates_enabled, stringResource(
                    if (preview.updateSource == org.kurdistanvpn.core.model.RedactedFieldPresence.PROVIDED_REDACTED)
                        UiR.string.preview_detail_redacted else UiR.string.unavailable,
                ))
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
        ProfileButton(onClick = onConfirm) { Text(stringResource(UiR.string.confirm_encrypted_storage)) }
        ProfileTextButton(onClick = onCancel) { Text(stringResource(UiR.string.cancel)) }
    }
}

@Composable
private fun ProfileButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    shape: Shape = MaterialTheme.shapes.small,
    destructive: Boolean = false,
    content: @Composable RowScope.() -> Unit,
) {
    val colors = if (destructive) ButtonDefaults.buttonColors(
        containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError,
        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
    ) else ButtonDefaults.buttonColors(
        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant, disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant)
    Button(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), onClick = { if (enabled) onClick() }, enabled = enabled, modifier = modifier.fillMaxWidth().heightIn(min = 56.dp),
        shape = shape, colors = colors, content = content)
}

@Composable
private fun ProfileTextButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable RowScope.() -> Unit,
) {
    TextButton(onClick = onClick, modifier = modifier.heightIn(min = 48.dp), content = content)
}
