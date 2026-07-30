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
import org.kurdistanvpn.core.model.ImportSource
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.BackupPreviewHandle
import org.kurdistanvpn.core.nativeapi.DiagnosticPreviewHandle
import org.kurdistanvpn.data.secure.AdmissionResult
import org.kurdistanvpn.data.secure.BackupPayloadCodec
import org.kurdistanvpn.data.secure.RestoreResult
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.platform.importing.ImportCandidate
import org.kurdistanvpn.platform.importing.ArtifactClass
import org.kurdistanvpn.platform.importing.VerifyRequestEncoder

class Phase9ViewModel(
    private val root: Phase9CompositionRoot,
) : ViewModel() {
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
    private var pending: PendingImport? = null
    private var pendingBackup: BackupPreviewHandle? = null
    private var pendingDiagnostic: DiagnosticPreviewHandle? = null

    init {
        viewModelScope.launch {
            root.settingsStore.settings.collect { mutableSettings.value = it }
        }
        viewModelScope.launch { initialize() }
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
                    when (val result = root.nativeCore.verifyPreview(request)) {
                        is NativeResult.Failure -> {
                            finalError = result.error
                            request.fill(0)
                        }
                        is NativeResult.Success -> {
                            val preview = result.value.preview
                            root.nativeCore.releaseVerified(result.value)
                            pending = PendingImport(request, preview, source)
                            mutableState.value = AppState.ImportPreview(preview)
                            return@launch
                        }
                    }
                }
                clearPendingImport()
                mutableState.value = AppState.ImportRejected(finalError)
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
                val journal = root.admissionJournal
                if (journal == null) {
                    mutableState.value = AppState.KeyInvalidated
                    return@launch
                }
                when (val result = journal.admit(value.request, value.preview)) {
                    is AdmissionResult.Failure ->
                        mutableState.value = AppState.ImportRejected(result.error)
                    is AdmissionResult.Success -> refreshProfiles()
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
            if (root.admissionJournal?.delete(localRecordId) == true) {
                refreshProfiles()
            } else {
                mutableState.value = AppState.DegradedStorage
            }
        }
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
                        root.admissionJournal?.backupPayload(localRecordId)
                    }.getOrNull()
                        ?: return@withContext NativeResult.Failure(OperationError.KEY_INVALIDATED)
                    try {
                        root.nativeCore.createBackup(payload, passphraseBytes)
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
        pendingBackup?.let(root.nativeCore::releaseBackup)
        pendingBackup = null
        mutableBackupState.value = BackupWorkflowState.Failed(error)
    }

    fun openBackup(backup: ByteArray, passphrase: String) {
        mutableBackupState.value = BackupWorkflowState.Working
        viewModelScope.launch {
            pendingBackup?.let(root.nativeCore::releaseBackup)
            pendingBackup = null
            val passphraseBytes = passphrase.encodeToByteArray()
            val result = try {
                withContext(Dispatchers.Default) {
                    root.nativeCore.openBackup(backup, passphraseBytes)
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
                        root.nativeCore.releaseBackup(result.value)
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
                root.nativeCore.restoreBackup(opened)
            }
            root.nativeCore.releaseBackup(opened)
            if (result is NativeResult.Failure) {
                mutableBackupState.value = BackupWorkflowState.Failed(result.error)
                return@launch
            }
            val restoredBytes = (result as NativeResult.Success).value
            val records = try {
                runCatching {
                    BackupPayloadCodec.decode(restoredBytes)
                }.getOrElse {
                    mutableBackupState.value =
                        BackupWorkflowState.Failed(OperationError.INVALID_INPUT)
                    return@launch
                }
            } finally {
                restoredBytes.fill(0)
            }
            val journal = root.admissionJournal
            if (journal == null) {
                mutableBackupState.value = BackupWorkflowState.Failed(OperationError.KEY_INVALIDATED)
                return@launch
            }
            val restore = try {
                journal.restore(records)
            } finally {
                records.forEach { it.verifyRequest.fill(0) }
            }
            when (restore) {
                is RestoreResult.Failure -> {
                    mutableBackupState.value = BackupWorkflowState.Failed(restore.error)
                    return@launch
                }
                is RestoreResult.Success -> {
                    mutableBackupState.value =
                        BackupWorkflowState.Completed(restore.restoredProfiles)
                }
            }
            refreshProfiles()
        }
    }

    fun cancelRestore() {
        pendingBackup?.let(root.nativeCore::releaseBackup)
        pendingBackup = null
        mutableBackupState.value = BackupWorkflowState.Idle
    }

    fun prepareDiagnostic() {
        mutableDiagnosticState.value = DiagnosticWorkflowState.Working
        viewModelScope.launch {
            pendingDiagnostic?.let(root.nativeCore::releaseDiagnostic)
            pendingDiagnostic = null
            val count = (mutableState.value as? AppState.Ready)?.profiles?.size ?: 0
            when (
                val result = root.nativeCore.prepareDiagnostic(
                    Phase9ExportWire.diagnosticRequest(count),
                )
            ) {
                is NativeResult.Failure ->
                    mutableDiagnosticState.value =
                        DiagnosticWorkflowState.Failed(result.error)
                is NativeResult.Success -> {
                    val decoded = runCatching {
                        Phase9ExportWire.diagnosticPreview(result.value.previewBytes)
                    }.getOrElse {
                        root.nativeCore.releaseDiagnostic(result.value)
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
            val result = root.nativeCore.confirmAndBuildDiagnostic(preview)
            root.nativeCore.releaseDiagnostic(preview)
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
        pendingDiagnostic?.let(root.nativeCore::releaseDiagnostic)
        pendingDiagnostic = null
        mutableDiagnosticState.value = DiagnosticWorkflowState.Idle
    }

    fun resetAll() {
        viewModelScope.launch {
            if (!root.resetProtectedState()) {
                mutableState.value = AppState.DegradedStorage
                return@launch
            }
            clearPendingImport()
            mutableBackupState.value = BackupWorkflowState.Idle
            mutableDiagnosticState.value = DiagnosticWorkflowState.Idle
            refreshProfiles()
        }
    }

    fun setTheme(theme: ThemePreference) {
        viewModelScope.launch {
            root.settingsStore.setTheme(theme)
            mutableSettings.value = mutableSettings.value.copy(theme = theme)
        }
    }

    fun setHighContrast(enabled: Boolean) {
        viewModelScope.launch {
            root.settingsStore.setHighContrast(enabled)
            mutableSettings.value = mutableSettings.value.copy(highContrast = enabled)
        }
    }

    fun setReducedMotion(enabled: Boolean) {
        viewModelScope.launch {
            root.settingsStore.setReducedMotion(enabled)
            mutableSettings.value = mutableSettings.value.copy(reducedMotion = enabled)
        }
    }

    override fun onCleared() {
        clearPendingImport()
        pendingBackup?.let(root.nativeCore::releaseBackup)
        pendingDiagnostic?.let(root.nativeCore::releaseDiagnostic)
        super.onCleared()
    }

    private suspend fun initialize() {
        mutableState.value = AppState.CompatibilityCheck
        when (val compatibility = root.nativeCore.compatibility()) {
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
        when (root.storageFailure) {
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
        val recovery = root.admissionJournal?.recoverIncomplete().orEmpty()
        if (recovery.any {
                it is AdmissionResult.Failure && it.error == OperationError.KEY_INVALIDATED
            }
        ) {
            mutableState.value = AppState.KeyInvalidated
            return
        }
        when (val restore = root.admissionJournal?.recoverPendingRestore()) {
            is RestoreResult.Failure -> {
                if (restore.error == OperationError.KEY_INVALIDATED) {
                    mutableState.value = AppState.KeyInvalidated
                    return
                }
            }
            is RestoreResult.Success, null -> Unit
        }
        refreshProfiles()
    }

    private suspend fun refreshProfiles() {
        val journal = root.admissionJournal
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
        mutableState.value = if (profiles.isEmpty()) AppState.NoProfiles else AppState.Ready(profiles)
    }

    private data class PendingImport(
        val request: ByteArray,
        val preview: RedactedProfilePreview,
        val source: ImportSource,
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
            require(modelClass.isAssignableFrom(Phase9ViewModel::class.java))
            return Phase9ViewModel(root) as T
        }
    }
}
