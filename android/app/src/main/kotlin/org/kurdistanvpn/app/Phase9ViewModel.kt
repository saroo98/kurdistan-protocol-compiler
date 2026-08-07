// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.BackupWorkflowState
import org.kurdistanvpn.core.model.CompatibilitySummary
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.EnrollmentKeySummary
import org.kurdistanvpn.core.model.EnrollmentUiState
import org.kurdistanvpn.core.model.ImportSource
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.model.ConnectionPreferences
import org.kurdistanvpn.core.model.DiagnosticPreferences
import org.kurdistanvpn.core.model.ExpertPreferences
import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProbeExecutionState
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticRetention
import org.kurdistanvpn.core.model.RoutingPreferences
import org.kurdistanvpn.core.model.TunnelPreferences
import org.kurdistanvpn.core.model.UpdatePreferences
import org.kurdistanvpn.core.model.SelectionMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.ProbeMethod
import org.kurdistanvpn.core.model.ResetScope
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.BackupPreviewHandle
import org.kurdistanvpn.core.nativeapi.DiagnosticPreviewHandle
import org.kurdistanvpn.data.secure.AdmissionResult
import org.kurdistanvpn.data.secure.BackupPayloadCodec
import org.kurdistanvpn.data.secure.ClientKeyRestoreResult
import org.kurdistanvpn.data.secure.ClientKeyResult
import org.kurdistanvpn.data.secure.ClientKeyStatus
import org.kurdistanvpn.data.secure.RestoreResult
import org.kurdistanvpn.data.secure.RuntimeAuthorityResult
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.platform.importing.ImportCandidate
import org.kurdistanvpn.platform.importing.ArtifactClass
import org.kurdistanvpn.platform.importing.VerifyRequestEncoder
import org.kurdistanvpn.runtime.api.RuntimeStartWire
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig

class ProductRootViewModel(
    private val root: Phase9CompositionRoot,
) : ViewModel() {
    private val coordinators = Phase13Coordinators.create(root)
    private val mutableState = MutableStateFlow<AppState>(AppState.Booting)
    val state: StateFlow<AppState> = mutableState.asStateFlow()
    private val mutableBackupState =
        MutableStateFlow<BackupWorkflowState>(BackupWorkflowState.Idle)
    val backupState: StateFlow<BackupWorkflowState> = mutableBackupState.asStateFlow()
    private val mutableDiagnosticState =
        MutableStateFlow<DiagnosticWorkflowState>(DiagnosticWorkflowState.Idle)
    val diagnosticState: StateFlow<DiagnosticWorkflowState> =
        mutableDiagnosticState.asStateFlow()
    private val mutableSettings = MutableStateFlow(Phase9Settings())
    val settings: StateFlow<Phase9Settings> = mutableSettings.asStateFlow()
    private val mutableCompatibility = MutableStateFlow<CompatibilitySummary?>(null)
    val compatibility: StateFlow<CompatibilitySummary?> = mutableCompatibility.asStateFlow()
    private val mutableProbeState = MutableStateFlow<ProbeExecutionState>(ProbeExecutionState.Idle)
    val probeState: StateFlow<ProbeExecutionState> = mutableProbeState.asStateFlow()
    private val mutableEnrollmentState =
        MutableStateFlow<EnrollmentUiState>(EnrollmentUiState.NoEnrollmentKey)
    val enrollmentState: StateFlow<EnrollmentUiState> = mutableEnrollmentState.asStateFlow()
    private val mutableDiagnosticEvents = MutableStateFlow<List<DiagnosticEvent>>(emptyList())
    val diagnosticEvents: StateFlow<List<DiagnosticEvent>> = mutableDiagnosticEvents.asStateFlow()
    private var diagnosticSequence = 0L
    private var pending: PendingImport? = null
    private var pendingBackup: BackupPreviewHandle? = null
    private var pendingDiagnostic: DiagnosticPreviewHandle? = null

    init {
        viewModelScope.launch {
            coordinators.settings.settings.collect { persisted ->
                val localSafe = persisted.forLocalPhase13Runtime()
                if (localSafe.connection != persisted.connection) {
                    coordinators.settings.setConnection(localSafe.connection)
                }
                if (localSafe.tunnel != persisted.tunnel) {
                    coordinators.settings.setTunnel(localSafe.tunnel)
                }
                if (localSafe.updates != persisted.updates) {
                    coordinators.settings.setUpdates(localSafe.updates)
                }
                if (localSafe.probes != persisted.probes) {
                    coordinators.settings.setProbes(localSafe.probes)
                }
                val securePackages = runCatching {
                    withContext(Dispatchers.IO) { coordinators.settings.routing.load() }
                }.getOrElse {
                    mutableState.value = AppState.DegradedStorage
                    return@collect
                }
                val migratedPackages = when {
                    securePackages.isNotEmpty() -> securePackages
                    localSafe.routing.packages.isNotEmpty() && coordinators.settings.routing.available() -> {
                        runCatching {
                            withContext(Dispatchers.IO) {
                                coordinators.settings.routing.save(localSafe.routing.packages)
                                coordinators.settings.clearLegacyRoutingPackages()
                            }
                        }.getOrElse {
                            mutableState.value = AppState.DegradedStorage
                            return@collect
                        }
                        localSafe.routing.packages
                    }
                    else -> emptySet()
                }
                mutableSettings.value = localSafe.copy(
                    routing = localSafe.routing.copy(packages = migratedPackages),
                )
            }
        }
        viewModelScope.launch { initialize() }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { coordinators.diagnostics.load() }
                .onSuccess { events ->
                    val retained = retainDiagnosticEvents(events, mutableSettings.value.diagnostics.retention)
                    mutableDiagnosticEvents.value = retained
                    diagnosticSequence = retained.maxOfOrNull { it.sequence } ?: 0
                }
                .onFailure { mutableState.value = AppState.DegradedStorage }
        }
    }

    fun preview(candidate: ImportCandidate, source: ImportSource) {
        clearPendingImport()
        mutableState.value = AppState.Importing(source)
        viewModelScope.launch {
            try {
                var finalError = OperationError.TRUST_REJECTED
                for (artifactClass in ArtifactClass.entries) {
                    val request = runCatching {
                        VerifyRequestEncoder.encode(candidate.copy(artifactClass = artifactClass))
                    }.getOrElse {
                        mutableState.value = AppState.ImportRejected(OperationError.INVALID_INPUT)
                        return@launch
                    }
                    when (val result = coordinators.profiles.resolvePreview(request)) {
                        is NativeResult.Failure -> {
                            finalError = result.error
                            request.fill(0)
                        }
                        is NativeResult.Success -> {
                            val preview = result.value.verified.preview
                            coordinators.profiles.nativeCore.releaseVerified(result.value.verified)
                            pending = PendingImport(
                                request = request,
                                preview = preview,
                                source = source,
                                recipientKeyLocalId = result.value.recipientKeyLocalId,
                            )
                            mutableState.value = AppState.ImportPreview(preview)
                            return@launch
                        }
                    }
                }
                clearPendingImport()
                mutableState.value = AppState.ImportRejected(finalError)
                if (finalError == OperationError.TRUST_REJECTED &&
                    coordinators.profiles.enrollmentKeys().isEmpty()
                ) {
                    mutableEnrollmentState.value = EnrollmentUiState.MissingKey("unavailable")
                }
                recordDiagnostic(DiagnosticLogLevel.WARNING, DiagnosticComponent.PROFILE, "IMPORT_REJECTED")
            } finally {
                candidate.parts.forEach { it.fill(0) }
            }
        }
    }

    fun confirmImport() {
        val value = pending ?: return
        pending = null
        mutableState.value = AppState.Importing(value.source)
        viewModelScope.launch {
            try {
                val journal = coordinators.profiles.journalOrNull()
                if (journal == null) {
                    mutableState.value = AppState.KeyInvalidated
                    return@launch
                }
                when (
                    val result = journal.admit(
                        value.request,
                        value.preview,
                        value.recipientKeyLocalId,
                    )
                ) {
                    is AdmissionResult.Failure ->
                        mutableState.value = AppState.ImportRejected(result.error).also {
                            recordDiagnostic(DiagnosticLogLevel.ERROR, DiagnosticComponent.PROFILE, "ACTIVATION_REJECTED")
                        }
                    is AdmissionResult.Success -> {
                        recordDiagnostic(DiagnosticLogLevel.INFO, DiagnosticComponent.PROFILE, "PROFILE_ACTIVATED")
                        refreshEnrollmentState()
                        refreshProfiles()
                    }
                }
            } finally {
                value.request.fill(0)
            }
        }
    }

    fun cancelImport() {
        clearPendingImport()
        viewModelScope.launch { refreshProfiles() }
    }

    fun clearError() {
        viewModelScope.launch { refreshProfiles() }
    }

    fun rejectImport(error: OperationError = OperationError.INVALID_INPUT) {
        clearPendingImport()
        mutableState.value = AppState.ImportRejected(error)
    }

    fun deleteProfile(localRecordId: String) {
        viewModelScope.launch {
            if (coordinators.profiles.journalOrNull()?.delete(localRecordId) == true) {
                val offered = runCatching { coordinators.profiles.unbindProfile(localRecordId) }
                    .getOrNull()
                if (offered != null) {
                    mutableEnrollmentState.value = EnrollmentUiState.OfferKeyDeletion(
                        offered.toUiSummary(),
                    )
                } else {
                    refreshEnrollmentState()
                }
                refreshProfiles()
            } else {
                mutableState.value = AppState.DegradedStorage
            }
        }
    }

    fun createEnrollmentRequest(validitySeconds: Int = 24 * 60 * 60) {
        mutableEnrollmentState.value = EnrollmentUiState.Working
        viewModelScope.launch(Dispatchers.IO) {
            when (
                val result = coordinators.profiles.createEnrollment(
                    validitySeconds,
                    System.currentTimeMillis() / 1000,
                )
            ) {
                is ClientKeyResult.Failure -> mutableEnrollmentState.value =
                    if (result.error == OperationError.KEY_INVALIDATED) {
                        EnrollmentUiState.KeyInvalidated
                    } else {
                        EnrollmentUiState.Failed(result.error)
                    }
                is ClientKeyResult.Success -> refreshEnrollmentState()
            }
        }
    }

    fun exportEnrollmentRequest(localRecordId: String, onReady: (ByteArray) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val request = runCatching {
                coordinators.profiles.enrollmentRequest(localRecordId)
            }.getOrNull()
            if (request == null) {
                mutableEnrollmentState.value = EnrollmentUiState.RecoveryRequired
            } else {
                try {
                    withContext(Dispatchers.Main.immediate) { onReady(request) }
                } catch (_: Throwable) {
                    request.fill(0)
                    mutableEnrollmentState.value = EnrollmentUiState.RecoveryRequired
                }
            }
        }
    }

    fun deleteEnrollmentKey(localRecordId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val deleted = runCatching {
                coordinators.profiles.deleteEnrollmentKey(localRecordId)
            }.getOrDefault(false)
            if (deleted) refreshEnrollmentState()
            else mutableEnrollmentState.value = EnrollmentUiState.RecoveryRequired
        }
    }

    fun markEnrollmentRequestExported(localRecordId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { coordinators.profiles.markEnrollmentRequestExported(localRecordId) }
                .onSuccess { refreshEnrollmentState() }
                .onFailure { mutableEnrollmentState.value = EnrollmentUiState.RecoveryRequired }
        }
    }

    fun dismissEnrollmentAction() {
        viewModelScope.launch(Dispatchers.IO) { refreshEnrollmentState() }
    }

    fun createBackup(passphrase: String, onReady: (ByteArray) -> Unit) {
        createBackup(localRecordId = null, passphrase = passphrase, onReady = onReady)
    }

    fun createProfileBackup(
        localRecordId: String,
        passphrase: String,
        onReady: (ByteArray) -> Unit,
    ) {
        createBackup(localRecordId = localRecordId, passphrase = passphrase, onReady = onReady)
    }

    private fun createBackup(
        localRecordId: String?,
        passphrase: String,
        onReady: (ByteArray) -> Unit,
    ) {
        mutableBackupState.value = BackupWorkflowState.Working
        viewModelScope.launch {
            val passphraseBytes = passphrase.encodeToByteArray()
            val result = try {
                withContext(Dispatchers.Default) {
                    val payload = runCatching {
                        coordinators.profiles.journalOrNull()?.backupPayload(localRecordId)
                    }.getOrNull()
                        ?: return@withContext NativeResult.Failure(OperationError.KEY_INVALIDATED)
                    try {
                        coordinators.profiles.nativeCore.createBackup(payload, passphraseBytes)
                    } finally {
                        payload.fill(0)
                    }
                }
            } finally {
                passphraseBytes.fill(0)
            }
            when (result) {
                is NativeResult.Failure ->
                    mutableBackupState.value = BackupWorkflowState.Failed(result.error)
                is NativeResult.Success -> {
                    mutableBackupState.value = BackupWorkflowState.Idle
                    onReady(result.value)
                }
            }
        }
    }

    fun failBackup(error: OperationError) {
        pendingBackup?.let(coordinators.profiles.nativeCore::releaseBackup)
        pendingBackup = null
        mutableBackupState.value = BackupWorkflowState.Failed(error)
    }

    fun openBackup(backup: ByteArray, passphrase: String) {
        mutableBackupState.value = BackupWorkflowState.Working
        viewModelScope.launch {
            pendingBackup?.let(coordinators.profiles.nativeCore::releaseBackup)
            pendingBackup = null
            val passphraseBytes = passphrase.encodeToByteArray()
            val result = try {
                withContext(Dispatchers.Default) {
                    coordinators.profiles.nativeCore.openBackup(backup, passphraseBytes)
                }
            } finally {
                passphraseBytes.fill(0)
                backup.fill(0)
            }
            when (result) {
                is NativeResult.Failure ->
                    mutableBackupState.value = BackupWorkflowState.Failed(result.error)
                is NativeResult.Success -> {
                    val decoded = runCatching {
                        Phase9ExportWire.backupPreview(result.value.previewBytes)
                    }.getOrElse {
                        coordinators.profiles.nativeCore.releaseBackup(result.value)
                        mutableBackupState.value =
                            BackupWorkflowState.Failed(OperationError.INVALID_INPUT)
                        return@launch
                    }
                    pendingBackup = result.value
                    mutableBackupState.value = BackupWorkflowState.RestorePreview(
                        recordCount = decoded.first,
                        nativeProfileCount = decoded.second,
                    )
                }
            }
        }
    }

    fun confirmRestore() {
        val opened = pendingBackup ?: return
        pendingBackup = null
        mutableBackupState.value = BackupWorkflowState.Working
        viewModelScope.launch {
            val result = withContext(Dispatchers.Default) {
                coordinators.profiles.nativeCore.restoreBackup(opened)
            }
            coordinators.profiles.nativeCore.releaseBackup(opened)
            if (result is NativeResult.Failure) {
                mutableBackupState.value = BackupWorkflowState.Failed(result.error)
                return@launch
            }
            val restoredBytes = (result as NativeResult.Success).value
            val records = try {
                runCatching {
                    BackupPayloadCodec.decodePayload(restoredBytes)
                }.getOrElse {
                    mutableBackupState.value =
                        BackupWorkflowState.Failed(OperationError.INVALID_INPUT)
                    return@launch
                }
            } finally {
                restoredBytes.fill(0)
            }
            val journal = coordinators.profiles.journalOrNull()
            val keyStore = coordinators.profiles.clientKeysOrNull()
            if (journal == null || keyStore == null) {
                records.clientKeys.forEach { it.destroy() }
                records.profiles.forEach { it.verifyRequest.fill(0) }
                mutableBackupState.value = BackupWorkflowState.Failed(OperationError.KEY_INVALIDATED)
                return@launch
            }
            val restoredKeyIds = when (val keyRestore = keyStore.restore(records.clientKeys)) {
                is ClientKeyRestoreResult.Failure -> {
                    records.clientKeys.forEach { it.destroy() }
                    records.profiles.forEach { it.verifyRequest.fill(0) }
                    mutableBackupState.value = BackupWorkflowState.Failed(keyRestore.error)
                    return@launch
                }
                is ClientKeyRestoreResult.Success -> keyRestore.localRecordIds
            }
            val restore = try {
                journal.restore(records.profiles)
            } finally {
                records.clientKeys.forEach { it.destroy() }
                records.profiles.forEach { it.verifyRequest.fill(0) }
            }
            when (restore) {
                is RestoreResult.Failure -> {
                    keyStore.rollbackRestored(restoredKeyIds)
                    mutableBackupState.value = BackupWorkflowState.Failed(restore.error)
                    return@launch
                }
                is RestoreResult.Success -> {
                    mutableBackupState.value =
                        BackupWorkflowState.Completed(restore.restoredProfiles)
                }
            }
            refreshEnrollmentState()
            refreshProfiles()
        }
    }

    fun cancelRestore() {
        pendingBackup?.let(coordinators.profiles.nativeCore::releaseBackup)
        pendingBackup = null
        mutableBackupState.value = BackupWorkflowState.Idle
    }

    fun prepareDiagnostic() {
        mutableDiagnosticState.value = DiagnosticWorkflowState.Working
        viewModelScope.launch {
            pendingDiagnostic?.let(coordinators.profiles.nativeCore::releaseDiagnostic)
            pendingDiagnostic = null
            val count = (mutableState.value as? AppState.Ready)?.profiles?.size ?: 0
            when (
                val result = coordinators.profiles.nativeCore.prepareDiagnostic(
                    Phase9ExportWire.diagnosticRequest(count, mutableDiagnosticEvents.value),
                )
            ) {
                is NativeResult.Failure ->
                    mutableDiagnosticState.value =
                        DiagnosticWorkflowState.Failed(result.error)
                is NativeResult.Success -> {
                    val decoded = runCatching {
                        Phase9ExportWire.diagnosticPreview(result.value.previewBytes)
                    }.getOrElse {
                        coordinators.profiles.nativeCore.releaseDiagnostic(result.value)
                        mutableDiagnosticState.value =
                            DiagnosticWorkflowState.Failed(OperationError.INVALID_INPUT)
                        return@launch
                    }
                    pendingDiagnostic = result.value
                    mutableDiagnosticState.value = DiagnosticWorkflowState.Preview(
                        categoryCount = decoded.first,
                        entryCount = decoded.second,
                        encodedSize = decoded.third,
                    )
                }
            }
        }
    }

    fun confirmDiagnostic(onReady: (ByteArray) -> Unit) {
        val preview = pendingDiagnostic ?: return
        pendingDiagnostic = null
        mutableDiagnosticState.value = DiagnosticWorkflowState.Working
        viewModelScope.launch {
            val result = coordinators.profiles.nativeCore.confirmAndBuildDiagnostic(preview)
            coordinators.profiles.nativeCore.releaseDiagnostic(preview)
            when (result) {
                is NativeResult.Failure ->
                    mutableDiagnosticState.value =
                        DiagnosticWorkflowState.Failed(result.error)
                is NativeResult.Success -> {
                    onReady(result.value)
                }
            }
        }
    }

    fun diagnosticExportCompleted() {
        mutableDiagnosticState.value = DiagnosticWorkflowState.Completed
    }

    fun diagnosticExportCancelled() {
        mutableDiagnosticState.value = DiagnosticWorkflowState.Idle
    }

    fun diagnosticExportFailed(error: OperationError) {
        mutableDiagnosticState.value = DiagnosticWorkflowState.Failed(error)
    }

    fun cancelDiagnostic() {
        pendingDiagnostic?.let(coordinators.profiles.nativeCore::releaseDiagnostic)
        pendingDiagnostic = null
        mutableDiagnosticState.value = DiagnosticWorkflowState.Idle
    }

    fun resetAll() = reset(ResetScope.EVERYTHING)

    fun reset(scope: ResetScope) {
        viewModelScope.launch {
            val succeeded = runCatching {
                when (scope) {
                    ResetScope.SETTINGS -> {
                        coordinators.settings.resetSettings()
                        val current = mutableSettings.value
                        val defaults = Phase9Settings()
                        mutableSettings.value = defaults.copy(
                            routing = current.routing,
                            diagnostics = current.diagnostics,
                            profiles = current.profiles,
                        )
                        true
                    }
                    ResetScope.PROFILES_PROVIDERS -> {
                        if (!coordinators.recovery.resetProfiles()) return@runCatching false
                        coordinators.settings.resetProfiles()
                        mutableSettings.value = mutableSettings.value.copy(
                            profiles = Phase9Settings().profiles,
                        )
                        clearPendingImport()
                        mutableBackupState.value = BackupWorkflowState.Idle
                        refreshProfiles()
                        true
                    }
                    ResetScope.ROUTING -> {
                        if (!coordinators.recovery.resetRouting()) return@runCatching false
                        coordinators.settings.resetRouting()
                        mutableSettings.value = mutableSettings.value.copy(
                            routing = Phase9Settings().routing,
                        )
                        true
                    }
                    ResetScope.DIAGNOSTICS -> {
                        if (!coordinators.recovery.resetDiagnostics()) return@runCatching false
                        coordinators.settings.resetDiagnostics()
                        mutableSettings.value = mutableSettings.value.copy(
                            diagnostics = Phase9Settings().diagnostics,
                        )
                        mutableDiagnosticState.value = DiagnosticWorkflowState.Idle
                        mutableDiagnosticEvents.value = emptyList()
                        diagnosticSequence = 0
                        true
                    }
                    ResetScope.EVERYTHING -> {
                        if (!coordinators.recovery.resetProtectedState()) return@runCatching false
                        coordinators.settings.resetAll()
                        clearPendingImport()
                        mutableBackupState.value = BackupWorkflowState.Idle
                        mutableDiagnosticState.value = DiagnosticWorkflowState.Idle
                        mutableDiagnosticEvents.value = emptyList()
                        diagnosticSequence = 0
                        mutableSettings.value = Phase9Settings()
                        refreshProfiles()
                        true
                    }
                }
            }.getOrDefault(false)
            if (!succeeded) {
                mutableState.value = AppState.DegradedStorage
            }
        }
    }

    fun setTheme(theme: ThemePreference) {
        persistSetting(
            write = { coordinators.settings.setTheme(theme) },
            publish = { mutableSettings.value = mutableSettings.value.copy(theme = theme) },
        )
    }

    fun setHighContrast(enabled: Boolean) {
        persistSetting(
            write = { coordinators.settings.setHighContrast(enabled) },
            publish = { mutableSettings.value = mutableSettings.value.copy(highContrast = enabled) },
        )
    }

    fun setReducedMotion(enabled: Boolean) {
        persistSetting(
            write = { coordinators.settings.setReducedMotion(enabled) },
            publish = { mutableSettings.value = mutableSettings.value.copy(reducedMotion = enabled) },
        )
    }

    fun setConnection(value: ConnectionPreferences) {
        persistSetting(
            write = { coordinators.settings.setConnection(value) },
            publish = { mutableSettings.value = mutableSettings.value.copy(connection = value) },
        )
    }

    fun setTunnel(value: TunnelPreferences) {
        val valid = runCatching { value.validated() }.getOrElse {
            rejectSetting("TUNNEL_SETTING_REJECTED")
            return
        }
        persistSetting(
            write = { coordinators.settings.setTunnel(valid) },
            publish = { mutableSettings.value = mutableSettings.value.copy(tunnel = valid) },
        )
    }

    fun setRouting(value: RoutingPreferences) {
        val valid = runCatching { value.validated() }.getOrElse {
            rejectSetting("ROUTING_SETTING_REJECTED")
            return
        }
        persistSetting(
            write = {
                withContext(Dispatchers.IO) { coordinators.settings.routing.save(valid.packages) }
                coordinators.settings.setRouting(valid)
            },
            publish = { mutableSettings.value = mutableSettings.value.copy(routing = valid) },
        )
    }

    fun setUpdates(value: UpdatePreferences) {
        val valid = runCatching { value.validated() }.getOrElse {
            rejectSetting("UPDATE_SETTING_REJECTED")
            return
        }
        persistSetting(
            write = { coordinators.settings.setUpdates(valid) },
            publish = { mutableSettings.value = mutableSettings.value.copy(updates = valid) },
        )
    }

    fun setProbes(value: ProbePreferences) {
        val valid = runCatching { value.validated() }.getOrElse {
            rejectSetting("PROBE_SETTING_REJECTED")
            return
        }
        persistSetting(
            write = { coordinators.settings.setProbes(valid) },
            publish = { mutableSettings.value = mutableSettings.value.copy(probes = valid) },
        )
    }

    fun setDiagnostics(value: DiagnosticPreferences) {
        persistSetting(
            write = { coordinators.settings.setDiagnostics(value) },
            publish = { mutableSettings.value = mutableSettings.value.copy(diagnostics = value) },
        )
    }

    fun setExpert(value: ExpertPreferences) {
        val valid = runCatching { value.validated() }.getOrElse {
            rejectSetting("EXPERT_SETTING_REJECTED")
            return
        }
        persistSetting(
            write = { coordinators.settings.setExpert(valid) },
            publish = { mutableSettings.value = mutableSettings.value.copy(expert = valid) },
        )
    }

    private fun persistSetting(write: suspend () -> Unit, publish: () -> Unit) {
        viewModelScope.launch {
            runCatching { write() }
                .onSuccess { publish() }
                .onFailure {
                    recordDiagnostic(
                        DiagnosticLogLevel.ERROR,
                        DiagnosticComponent.STORAGE,
                        "SETTINGS_PERSIST_FAILED",
                    )
                    mutableState.value = AppState.DegradedStorage
                }
        }
    }

    private fun rejectSetting(category: String) {
        recordDiagnostic(DiagnosticLogLevel.WARNING, DiagnosticComponent.APP, category)
    }

    fun runLocalProbe() {
        if (mutableProbeState.value == ProbeExecutionState.Running) return
        mutableProbeState.value = ProbeExecutionState.Running
        viewModelScope.launch(Dispatchers.Default) {
            val payload = "phase13-kurd-session-probe".encodeToByteArray()
            val started = android.os.SystemClock.elapsedRealtimeNanos()
            val result = try {
                coordinators.runtime.probe(payload)
            } finally {
                payload.fill(0)
            }
            mutableProbeState.value = when (result) {
                is NativeResult.Success -> {
                    val valid = result.value.contentEquals("phase13-kurd-session-probe".encodeToByteArray())
                    result.value.fill(0)
                    if (valid) {
                        recordDiagnostic(DiagnosticLogLevel.INFO, DiagnosticComponent.PROBE, "KURD_PROBE_SUCCEEDED")
                        ProbeExecutionState.Succeeded(
                            ((android.os.SystemClock.elapsedRealtimeNanos() - started) / 1_000_000)
                                .coerceAtLeast(0),
                        )
                    } else {
                        recordDiagnostic(DiagnosticLogLevel.ERROR, DiagnosticComponent.PROBE, "KURD_PROBE_INVALID")
                        ProbeExecutionState.Failed(OperationError.INTERNAL_FAILURE)
                    }
                }
                is NativeResult.Failure -> {
                    recordDiagnostic(DiagnosticLogLevel.WARNING, DiagnosticComponent.PROBE, "KURD_PROBE_FAILED")
                    ProbeExecutionState.Failed(result.error)
                }
            }
        }
    }

    fun prepareRuntimeStart(
        config: VpnRuntimeConfig,
        onReady: (ByteArray) -> Unit,
        onFailure: (OperationError) -> Unit,
    ) {
        val localRecordId = mutableSettings.value.profiles.activeLocalRecordId
        if (localRecordId == null) {
            onFailure(OperationError.POLICY_REJECTED)
            return
        }
        viewModelScope.launch {
            when (val authority = coordinators.runtime.openLiveAuthority(localRecordId)) {
                is RuntimeAuthorityResult.Success -> authority.material.use { material ->
                    val encoded = runCatching {
                        withContext(Dispatchers.Default) {
                            RuntimeStartWire.encode(
                                verifyRequest = material.verifyRequest,
                                activationRecord = material.activationRecord,
                                recipientRequest = material.recipientRequest,
                                recipientPrivate = material.recipientPrivate,
                                config = config,
                            )
                        }
                    }.getOrElse {
                        recordDiagnostic(
                            DiagnosticLogLevel.WARNING,
                            DiagnosticComponent.RUNTIME,
                            "RUNTIME_AUTHORITY_REJECTED",
                        )
                        onFailure(OperationError.POLICY_REJECTED)
                        return@launch
                    }
                    recordDiagnostic(
                        DiagnosticLogLevel.INFO,
                        DiagnosticComponent.RUNTIME,
                        "RUNTIME_AUTHORITY_PREPARED",
                    )
                    onReady(encoded)
                }
                is RuntimeAuthorityResult.Failure -> {
                    recordDiagnostic(
                        DiagnosticLogLevel.WARNING,
                        DiagnosticComponent.RUNTIME,
                        "RUNTIME_AUTHORITY_UNAVAILABLE",
                    )
                    onFailure(authority.error)
                }
                null -> onFailure(OperationError.STORAGE_FAILURE)
            }
        }
    }

    fun clearDiagnosticEvents() {
        mutableDiagnosticEvents.value = emptyList()
        diagnosticSequence = 0
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { coordinators.diagnostics.clear() }
                .onFailure { mutableState.value = AppState.DegradedStorage }
        }
    }

    @Synchronized
    private fun recordDiagnostic(
        level: DiagnosticLogLevel,
        component: DiagnosticComponent,
        category: String,
    ) {
        if (!shouldRecord(level, mutableSettings.value.diagnostics.level)) return
        diagnosticSequence += 1
        val event = DiagnosticEvent(
            sequence = diagnosticSequence,
            level = level,
            component = component,
            category = category,
            coarseEpochMinutes = System.currentTimeMillis() / 60_000,
        )
        val retained = retainDiagnosticEvents(
            mutableDiagnosticEvents.value + event,
            mutableSettings.value.diagnostics.retention,
        ).takeLast(200)
        mutableDiagnosticEvents.value = retained
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { coordinators.diagnostics.save(retained) }
                .onFailure { mutableState.value = AppState.DegradedStorage }
        }
    }

    fun selectProfile(localRecordId: String) {
        val known = (mutableState.value as? AppState.Ready)?.profiles
            ?.any { it.localRecordId == localRecordId } == true
        if (!known) return
        viewModelScope.launch {
            val value = mutableSettings.value.profiles.copy(activeLocalRecordId = localRecordId)
            coordinators.settings.setProfiles(value)
            mutableSettings.value = mutableSettings.value.copy(profiles = value)
        }
    }

    fun toggleFavorite(localRecordId: String) {
        val known = (mutableState.value as? AppState.Ready)?.profiles
            ?.any { it.localRecordId == localRecordId } == true
        if (!known) return
        viewModelScope.launch {
            val current = mutableSettings.value.profiles
            val favorites = current.favoriteLocalRecordIds.toMutableSet().apply {
                if (!add(localRecordId)) remove(localRecordId)
            }
            val value = current.copy(favoriteLocalRecordIds = favorites)
            coordinators.settings.setProfiles(value)
            mutableSettings.value = mutableSettings.value.copy(profiles = value)
        }
    }

    override fun onCleared() {
        clearPendingImport()
        pendingBackup?.let(coordinators.profiles.nativeCore::releaseBackup)
        pendingDiagnostic?.let(coordinators.profiles.nativeCore::releaseDiagnostic)
        super.onCleared()
    }

    private suspend fun initialize() {
        mutableState.value = AppState.CompatibilityCheck
        when (val compatibility = coordinators.profiles.nativeCore.compatibility()) {
            is NativeResult.Failure -> {
                mutableState.value = AppState.MigrationRequired
                return
            }
            is NativeResult.Success -> {
                val value = compatibility.value
                if (
                    value.bridgeVersion != "kurd-android-bridge-v1" ||
                    value.goCoreVersion != "kurd-go-core-phase9-v1"
                ) {
                    mutableState.value = AppState.MigrationRequired
                    return
                }
                mutableCompatibility.value = CompatibilitySummary(
                    goCoreVersion = value.goCoreVersion,
                    profileSchema = value.profileSchema,
                    strategyRegistry = value.strategyRegistry,
                    relaySchema = value.relaySchema,
                    diagnosticSchema = value.diagnosticSchema,
                    cryptoSuite = value.cryptoSuite,
                )
            }
        }
        when (coordinators.recovery.storageFailure()) {
            Phase9CompositionRoot.StorageFailure.KEY_INVALIDATED -> {
                mutableState.value = AppState.KeyInvalidated
                return
            }
            Phase9CompositionRoot.StorageFailure.DEGRADED -> {
                mutableState.value = AppState.DegradedStorage
                return
            }
            null -> Unit
        }
        val recovery = coordinators.profiles.journalOrNull()?.recoverIncomplete().orEmpty()
        if (recovery.any {
                it is AdmissionResult.Failure && it.error == OperationError.KEY_INVALIDATED
            }
        ) {
            mutableState.value = AppState.KeyInvalidated
            return
        }
        when (val restore = coordinators.profiles.journalOrNull()?.recoverPendingRestore()) {
            is RestoreResult.Failure -> {
                if (restore.error == OperationError.KEY_INVALIDATED) {
                    mutableState.value = AppState.KeyInvalidated
                    return
                }
            }
            is RestoreResult.Success, null -> Unit
        }
        refreshEnrollmentState()
        refreshProfiles()
    }

    private fun refreshEnrollmentState() {
        val keys = runCatching { coordinators.profiles.enrollmentKeys() }.getOrElse {
            mutableEnrollmentState.value = EnrollmentUiState.RecoveryRequired
            return
        }
        if (keys.isEmpty()) {
            mutableEnrollmentState.value = EnrollmentUiState.NoEnrollmentKey
            return
        }
        val summaries = keys.map { it.toUiSummary() }
        mutableEnrollmentState.value = when {
            keys.any { it.status == ClientKeyStatus.PROFILE_VERIFIED } ->
                EnrollmentUiState.ProfileVerified(summaries)
            keys.any { it.status == ClientKeyStatus.AWAITING_PROFILE } ->
                EnrollmentUiState.AwaitingProfile(summaries)
            else -> EnrollmentUiState.RequestReady(summaries)
        }
    }

    private suspend fun refreshProfiles() {
        val journal = coordinators.profiles.journalOrNull()
        val profiles = journal?.listProfiles().orEmpty()
        when (journal?.storageHealth()) {
            CatalogHealth.KEY_INVALIDATED -> {
                mutableState.value = AppState.KeyInvalidated
                return
            }
            CatalogHealth.QUARANTINED -> {
                mutableState.value = AppState.Quarantined
                return
            }
            CatalogHealth.DEGRADED -> {
                mutableState.value = AppState.DegradedStorage
                return
            }
            else -> Unit
        }
        if (profiles.isEmpty()) {
            if (mutableSettings.value.profiles.activeLocalRecordId != null ||
                mutableSettings.value.profiles.favoriteLocalRecordIds.isNotEmpty()
            ) {
                coordinators.settings.setProfiles(org.kurdistanvpn.core.model.ProfilePreferences())
                mutableSettings.value = mutableSettings.value.copy(
                    profiles = org.kurdistanvpn.core.model.ProfilePreferences(),
                )
            }
            mutableState.value = AppState.NoProfiles
        } else {
            val knownIds = profiles.mapTo(mutableSetOf()) { it.localRecordId }
            val current = mutableSettings.value.profiles
            val sanitized = current.copy(
                activeLocalRecordId = current.activeLocalRecordId?.takeIf(knownIds::contains)
                    ?: profiles.first().localRecordId,
                favoriteLocalRecordIds = current.favoriteLocalRecordIds.filterTo(mutableSetOf(), knownIds::contains),
            )
            if (sanitized != current) {
                coordinators.settings.setProfiles(sanitized)
                mutableSettings.value = mutableSettings.value.copy(profiles = sanitized)
            }
            mutableState.value = AppState.Ready(profiles)
        }
    }

    private data class PendingImport(
        val request: ByteArray,
        val preview: RedactedProfilePreview,
        val source: ImportSource,
        val recipientKeyLocalId: String?,
    )

    private fun clearPendingImport() {
        pending?.request?.fill(0)
        pending = null
    }

    class Factory(
        private val root: Phase9CompositionRoot,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(ProductRootViewModel::class.java))
            return ProductRootViewModel(root) as T
        }
    }
}

private fun org.kurdistanvpn.data.secure.ClientKeySummary.toUiSummary(): EnrollmentKeySummary =
    EnrollmentKeySummary(
        localRecordId = localRecordId,
        requestFingerprint = requestFingerprint,
        createdAtEpochSeconds = createdAtEpochSeconds,
        expiresAtEpochSeconds = expiresAtEpochSeconds,
        boundProfileCount = boundProfileCount,
    )

private fun Phase9Settings.forLocalPhase13Runtime(): Phase9Settings = copy(
    connection = connection.copy(
        selectionMode = when (connection.selectionMode) {
            SelectionMode.AUTOMATIC,
            SelectionMode.KURD_ONLY,
            -> connection.selectionMode
            SelectionMode.MANUAL_STRATEGY -> SelectionMode.AUTOMATIC
        },
        autoConnectOnBoot = false,
        autoConnectOnLaunch = false,
        reconnectOnFailure = false,
        killSwitchRequested = false,
        allowLan = false,
        connectOnlyOnUntrustedNetworks = false,
    ),
    tunnel = tunnel.copy(
        ipMode = when (tunnel.ipMode) {
            IpMode.AUTO,
            IpMode.IPV4_ONLY,
            -> tunnel.ipMode
            IpMode.IPV6_ONLY,
            IpMode.DUAL_STACK,
            -> IpMode.AUTO
        },
        dnsMode = DnsMode.INTERNAL_TUN,
        customDns = "",
        showSpeedInNotification = false,
    ),
    updates = UpdatePreferences(),
    probes = probes.copy(
        method = ProbeMethod.KURD_SESSION,
        testUrl = ProbePreferences().testUrl,
    ),
)

private fun shouldRecord(event: DiagnosticLogLevel, configured: DiagnosticLogLevel): Boolean = when (configured) {
    DiagnosticLogLevel.NONE -> false
    DiagnosticLogLevel.ERROR -> event == DiagnosticLogLevel.ERROR
    DiagnosticLogLevel.WARNING -> event == DiagnosticLogLevel.ERROR || event == DiagnosticLogLevel.WARNING
    DiagnosticLogLevel.INFO -> event != DiagnosticLogLevel.DEBUG && event != DiagnosticLogLevel.NONE
    DiagnosticLogLevel.DEBUG -> event != DiagnosticLogLevel.NONE
}

private fun retainDiagnosticEvents(
    events: List<DiagnosticEvent>,
    retention: DiagnosticRetention,
    nowMinutes: Long = System.currentTimeMillis() / 60_000,
): List<DiagnosticEvent> {
    val durationMinutes = when (retention) {
        DiagnosticRetention.ONE_HOUR -> 60
        DiagnosticRetention.SIX_HOURS -> 6 * 60
        DiagnosticRetention.ONE_DAY -> 24 * 60
        DiagnosticRetention.SEVEN_DAYS -> 7 * 24 * 60
    }
    val earliest = (nowMinutes - durationMinutes).coerceAtLeast(0)
    return events.filter { it.coarseEpochMinutes >= earliest }.takeLast(200)
}
