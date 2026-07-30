// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.content.Intent
import android.os.Bundle
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.fragment.app.FragmentActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.core.content.IntentCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation3.runtime.NavEntry
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.ui.NavDisplay
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.BackupWorkflowState
import org.kurdistanvpn.core.model.CompatibilitySummary
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.ImportSource
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.ui.KurdistanTheme
import org.kurdistanvpn.core.ui.R as UiR
import org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsAboutScreen
import org.kurdistanvpn.feature.home.HomeScreen
import org.kurdistanvpn.feature.profiles.ImportPreviewScreen
import org.kurdistanvpn.feature.profiles.ProfilesScreen
import org.kurdistanvpn.feature.settingsrecovery.SettingsRecoveryScreen
import org.kurdistanvpn.platform.importing.AndroidImportSources
import org.kurdistanvpn.platform.importing.ArtifactClass
import org.kurdistanvpn.platform.importing.BoundedInputReader
import org.kurdistanvpn.platform.importing.ImportCandidate
import org.kurdistanvpn.platform.importing.MultipartQrAccumulator
import org.kurdistanvpn.platform.importing.OfflineQrScanner
import org.kurdistanvpn.data.secure.SensitiveAction
import org.kurdistanvpn.data.secure.SensitiveActionAuthorizer

class MainActivity : FragmentActivity() {
    private val viewModel: Phase9ViewModel by viewModels {
        Phase9ViewModel.Factory((application as KurdistanApplication).compositionRoot)
    }
    private val vpnController by lazy { VpnRuntimeController(applicationContext) }

    internal fun appStateSnapshotForTesting(): AppState = viewModel.state.value
    internal fun diagnosticStateSnapshotForTesting(): DiagnosticWorkflowState =
        viewModel.diagnosticState.value

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val state = viewModel.state.collectAsStateWithLifecycle().value
            val backupState = viewModel.backupState.collectAsStateWithLifecycle().value
            val diagnosticState = viewModel.diagnosticState.collectAsStateWithLifecycle().value
            val settings = viewModel.settings.collectAsStateWithLifecycle().value
            val compatibility = viewModel.compatibility.collectAsStateWithLifecycle().value
            val vpnRuntime = vpnController.snapshot.collectAsStateWithLifecycle().value
            val vpnPermission = rememberLauncherForActivityResult(
                ActivityResultContracts.StartActivityForResult(),
            ) { result ->
                if (result.resultCode == RESULT_OK) {
                    vpnController.start()
                } else {
                    vpnController.permissionRejected()
                }
            }
            val notificationPermission = rememberLauncherForActivityResult(
                ActivityResultContracts.RequestPermission(),
            ) { granted ->
                if (granted) {
                    val permission = vpnController.prepareIntent()
                    if (permission == null) {
                        vpnController.start()
                    } else {
                        vpnPermission.launch(permission)
                    }
                } else {
                    vpnController.notificationPermissionRejected()
                }
            }
            var pendingBackupBytes by remember { mutableStateOf<ByteArray?>(null) }
            var pendingDiagnosticBytes by remember { mutableStateOf<ByteArray?>(null) }
            var restorePassphrase by remember { mutableStateOf("") }
            val authorizer = remember { SensitiveActionAuthorizer(this@MainActivity) }
            val backupWriter = rememberLauncherForActivityResult(
                ActivityResultContracts.CreateDocument("application/vnd.kurdistan.backup"),
            ) { uri ->
                pendingBackupBytes?.let { bytes ->
                    if (uri == null) {
                        bytes.fill(0)
                    } else if (runCatching { writeAndWipe(uri, bytes) }.isFailure) {
                        viewModel.failBackup(OperationError.STORAGE_FAILURE)
                    }
                }
                pendingBackupBytes = null
            }
            val diagnosticWriter = rememberLauncherForActivityResult(
                ActivityResultContracts.CreateDocument("application/vnd.kurdistan.diagnostic"),
            ) { uri ->
                pendingDiagnosticBytes?.let { bytes ->
                    when {
                        uri == null -> {
                            bytes.fill(0)
                            viewModel.diagnosticExportCancelled()
                        }
                        runCatching { writeAndWipe(uri, bytes) }.isFailure ->
                            viewModel.diagnosticExportFailed(OperationError.STORAGE_FAILURE)
                        else -> viewModel.diagnosticExportCompleted()
                    }
                }
                pendingDiagnosticBytes = null
            }
            val backupReader = rememberLauncherForActivityResult(
                ActivityResultContracts.OpenDocument(),
            ) { uri ->
                val passphrase = restorePassphrase
                restorePassphrase = ""
                if (uri == null) return@rememberLauncherForActivityResult
                val bytes = runCatching { readBounded(uri, MAX_BACKUP_BYTES) }.getOrNull()
                    ?: run {
                        viewModel.failBackup(OperationError.INVALID_INPUT)
                        return@rememberLauncherForActivityResult
                    }
                viewModel.openBackup(bytes, passphrase)
            }
            val darkTheme = when (settings.theme) {
                ThemePreference.SYSTEM -> isSystemInDarkTheme()
                ThemePreference.LIGHT -> false
                ThemePreference.DARK -> true
            }
            KurdistanTheme(
                darkTheme = darkTheme,
                highContrast = settings.highContrast,
                reducedMotion = settings.reducedMotion,
            ) {
                KurdistanApp(
                    state = state,
                    backupState = backupState,
                    diagnosticState = diagnosticState,
                    settings = settings,
                    compatibility = compatibility,
                    vpnRuntime = vpnRuntime,
                    onPreviewFile = ::previewFile,
                    onPreviewClipboard = ::previewClipboard,
                    onPreviewQr = viewModel::preview,
                    onConfirmImport = viewModel::confirmImport,
                    onCancelImport = viewModel::cancelImport,
                    onClearError = viewModel::clearError,
                    onDeleteProfile = viewModel::deleteProfile,
                    onExportProfile = { localRecordId, passphrase ->
                        authorizer.authorize(
                            SensitiveAction.EXPORT_PROFILE,
                            getString(UiR.string.authorize_profile_export_title),
                            getString(UiR.string.authorize_profile_export_subtitle),
                        ) { approved ->
                            if (approved) {
                                viewModel.createProfileBackup(localRecordId, passphrase) { bytes ->
                                    pendingBackupBytes = bytes
                                    backupWriter.launch("kurd-profile-encrypted.kbackup")
                                }
                            }
                        }
                    },
                    onCreateBackup = { passphrase ->
                        authorizer.authorize(
                            SensitiveAction.CREATE_BACKUP,
                            getString(UiR.string.authorize_backup_title),
                            getString(UiR.string.authorize_backup_subtitle),
                        ) { approved ->
                            if (approved) {
                                viewModel.createBackup(passphrase) { bytes ->
                                    pendingBackupBytes = bytes
                                    backupWriter.launch("kurdistan-vpn-backup.kbackup")
                                }
                            }
                        }
                    },
                    onOpenBackup = { passphrase ->
                        restorePassphrase = passphrase
                        backupReader.launch(
                            arrayOf(
                                "application/vnd.kurdistan.backup",
                                "application/octet-stream",
                            ),
                        )
                    },
                    onConfirmRestore = viewModel::confirmRestore,
                    onCancelRestore = viewModel::cancelRestore,
                    onResetAll = viewModel::resetAll,
                    onTheme = viewModel::setTheme,
                    onHighContrast = viewModel::setHighContrast,
                    onReducedMotion = viewModel::setReducedMotion,
                    onPrepareDiagnostic = viewModel::prepareDiagnostic,
                    onConfirmDiagnostic = {
                        viewModel.confirmDiagnostic { bytes ->
                            pendingDiagnosticBytes = bytes
                            diagnosticWriter.launch("kurdistan-vpn-diagnostics.kdiag")
                        }
                    },
                    onCancelDiagnostic = viewModel::cancelDiagnostic,
                    onStartVpn = {
                        if (
                            Build.VERSION.SDK_INT >= 33 &&
                            ContextCompat.checkSelfPermission(
                                this@MainActivity,
                                Manifest.permission.POST_NOTIFICATIONS,
                            ) != PackageManager.PERMISSION_GRANTED
                        ) {
                            notificationPermission.launch(
                                Manifest.permission.POST_NOTIFICATIONS,
                            )
                        } else {
                            val permission = vpnController.prepareIntent()
                            if (permission == null) {
                                vpnController.start()
                            } else {
                                vpnPermission.launch(permission)
                            }
                        }
                    },
                    onStopVpn = vpnController::stop,
                )
            }
        }
        if (savedInstanceState == null) {
            handleExternalIntent(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleExternalIntent(intent)
    }

    override fun onDestroy() {
        vpnController.close()
        super.onDestroy()
    }

    private fun previewFile(
        uri: Uri,
        source: ImportSource = ImportSource.FILE,
    ) {
        val candidate = runCatching {
            if (source == ImportSource.SHARE_INTENT) {
                AndroidImportSources.sharedDocument(
                    contentResolver,
                    uri,
                    ArtifactClass.SIGNED_PUBLIC,
                )
            } else {
                AndroidImportSources.document(
                    contentResolver,
                    uri,
                    ArtifactClass.SIGNED_PUBLIC,
                )
            }
        }.getOrNull() ?: run {
            viewModel.rejectImport()
            return
        }
        viewModel.preview(candidate, source)
    }

    private fun previewClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip ?: run {
            viewModel.rejectImport()
            return
        }
        val candidate = runCatching {
            AndroidImportSources.clipboard(clip, ArtifactClass.SIGNED_PUBLIC)
        }.getOrNull() ?: run {
            viewModel.rejectImport()
            return
        }
        viewModel.preview(candidate, ImportSource.CLIPBOARD)
    }

    private fun handleExternalIntent(value: Intent) {
        when (value.action) {
            Intent.ACTION_VIEW -> {
                val link = value.dataString ?: run {
                    viewModel.rejectImport()
                    return
                }
                val candidate = runCatching {
                    AndroidImportSources.uri(link, ArtifactClass.SIGNED_PUBLIC)
                }.getOrNull() ?: run {
                    viewModel.rejectImport()
                    return
                }
                viewModel.preview(candidate, ImportSource.KURD_URI)
            }
            Intent.ACTION_SEND -> {
                val uri = IntentCompat.getParcelableExtra(
                    value,
                    Intent.EXTRA_STREAM,
                    Uri::class.java,
                ) ?: run {
                    viewModel.rejectImport()
                    return
                }
                previewFile(uri, ImportSource.SHARE_INTENT)
            }
        }
    }

    private fun readBounded(uri: Uri, maximum: Int): ByteArray {
        val stream = checkNotNull(contentResolver.openInputStream(uri))
        return stream.use { input ->
            BoundedInputReader.read(input, maximum)
        }
    }

    private fun writeAndWipe(uri: Uri, bytes: ByteArray) {
        try {
            checkNotNull(contentResolver.openOutputStream(uri, "w")).use { output ->
                output.write(bytes)
                output.flush()
            }
        } finally {
            bytes.fill(0)
        }
    }

    private companion object {
        const val MAX_BACKUP_BYTES = 8 * 1024 * 1024 + 128
    }
}

private enum class AppDestination : NavKey {
    HOME,
    PROFILES,
    SETTINGS_RECOVERY,
    DIAGNOSTICS_ABOUT,
}

@Composable
private fun KurdistanApp(
    state: AppState,
    backupState: BackupWorkflowState,
    diagnosticState: DiagnosticWorkflowState,
    settings: Phase9Settings,
    compatibility: CompatibilitySummary?,
    vpnRuntime: org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot,
    onPreviewFile: (Uri) -> Unit,
    onPreviewClipboard: () -> Unit,
    onPreviewQr: (ImportCandidate, ImportSource) -> Unit,
    onConfirmImport: () -> Unit,
    onCancelImport: () -> Unit,
    onClearError: () -> Unit,
    onDeleteProfile: (String) -> Unit,
    onExportProfile: (String, String) -> Unit,
    onCreateBackup: (String) -> Unit,
    onOpenBackup: (String) -> Unit,
    onConfirmRestore: () -> Unit,
    onCancelRestore: () -> Unit,
    onResetAll: () -> Unit,
    onTheme: (ThemePreference) -> Unit,
    onHighContrast: (Boolean) -> Unit,
    onReducedMotion: (Boolean) -> Unit,
    onPrepareDiagnostic: () -> Unit,
    onConfirmDiagnostic: () -> Unit,
    onCancelDiagnostic: () -> Unit,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit,
) {
    val backStack = remember { mutableStateListOf<NavKey>(AppDestination.HOME) }
    val currentState by rememberUpdatedState(state)
    val currentBackupState by rememberUpdatedState(backupState)
    val currentDiagnosticState by rememberUpdatedState(diagnosticState)
    val currentSettings by rememberUpdatedState(settings)
    val currentCompatibility by rememberUpdatedState(compatibility)
    val currentVpnRuntime by rememberUpdatedState(vpnRuntime)
    val documentPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) onPreviewFile(uri)
    }
    val context = androidx.compose.ui.platform.LocalContext.current
    val qrAccumulator = remember { MultipartQrAccumulator() }
    var scanningQr by remember { mutableStateOf(false) }
    val cameraPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        scanningQr = granted
        if (!granted) qrAccumulator.cancel()
    }
    if (scanningQr) {
        OfflineQrScanner(
            onDecoded = { value ->
                val multipart = value.startsWith("KURD1/")
                val candidate = runCatching {
                    if (multipart) {
                        qrAccumulator.add(value, ArtifactClass.SIGNED_PUBLIC)
                    } else {
                        AndroidImportSources.uri(value, ArtifactClass.SIGNED_PUBLIC)
                    }
                }.getOrNull()
                if (candidate != null) {
                    scanningQr = false
                    onPreviewQr(
                        candidate,
                        if (multipart) ImportSource.MULTIPART_QR else ImportSource.SINGLE_QR,
                    )
                    true
                } else {
                    false
                }
            },
            onBackgrounded = {
                qrAccumulator.onBackgrounded()
                scanningQr = false
            },
            onCancel = {
                qrAccumulator.cancel()
                scanningQr = false
            },
        )
        return
    }
    if (state is AppState.ImportPreview) {
        ImportPreviewScreen(
            preview = state.preview,
            onConfirm = onConfirmImport,
            onCancel = onCancelImport,
        )
        return
    }
    NavDisplay(
        backStack = backStack,
        onBack = { if (backStack.size > 1) backStack.removeAt(backStack.lastIndex) },
        entryProvider = { key ->
            when (key) {
                AppDestination.HOME -> NavEntry(key) {
                    HomeScreen(
                        state = currentState,
                        vpnRuntime = currentVpnRuntime,
                        onStartVpn = onStartVpn,
                        onStopVpn = onStopVpn,
                        onOpenProfiles = { backStack.add(AppDestination.PROFILES) },
                        onOpenSettings = { backStack.add(AppDestination.SETTINGS_RECOVERY) },
                        onOpenDiagnostics = { backStack.add(AppDestination.DIAGNOSTICS_ABOUT) },
                        onClearError = onClearError,
                    )
                }
                AppDestination.PROFILES -> NavEntry(key) {
                    ProfilesScreen(
                        profiles = (currentState as? AppState.Ready)?.profiles.orEmpty(),
                        onImportFile = {
                            documentPicker.launch(
                                arrayOf(
                                    "application/octet-stream",
                                    "application/vnd.kurdistan.profile+cose",
                                ),
                            )
                        },
                        onImportClipboard = onPreviewClipboard,
                        onImportLink = { value ->
                            val candidate = runCatching {
                                AndroidImportSources.uri(value, ArtifactClass.SIGNED_PUBLIC)
                            }.getOrNull()
                            if (candidate != null) onPreviewQr(candidate, ImportSource.KURD_URI)
                        },
                        onScanQr = {
                            if (
                                ContextCompat.checkSelfPermission(
                                    context,
                                    Manifest.permission.CAMERA,
                                ) == PackageManager.PERMISSION_GRANTED
                            ) {
                                scanningQr = true
                            } else {
                                cameraPermission.launch(Manifest.permission.CAMERA)
                            }
                        },
                        onExportProfile = onExportProfile,
                        onDeleteProfile = onDeleteProfile,
                        onBack = { backStack.removeAt(backStack.lastIndex) },
                    )
                }
                AppDestination.SETTINGS_RECOVERY -> NavEntry(key) {
                    SettingsRecoveryScreen(
                        backupState = currentBackupState,
                        settings = currentSettings,
                        onTheme = onTheme,
                        onHighContrast = onHighContrast,
                        onReducedMotion = onReducedMotion,
                        onCreateBackup = onCreateBackup,
                        onOpenBackup = onOpenBackup,
                        onConfirmRestore = onConfirmRestore,
                        onCancelRestore = onCancelRestore,
                        onResetAll = onResetAll,
                        onBack = { backStack.removeAt(backStack.lastIndex) },
                    )
                }
                AppDestination.DIAGNOSTICS_ABOUT -> NavEntry(key) {
                    DiagnosticsAboutScreen(
                        state = currentDiagnosticState,
                        appVersion = BuildConfig.VERSION_NAME,
                        compatibility = currentCompatibility,
                        onPrepare = onPrepareDiagnostic,
                        onConfirm = onConfirmDiagnostic,
                        onCancel = onCancelDiagnostic,
                        onBack = { backStack.removeAt(backStack.lastIndex) },
                    )
                }
                else -> error("Unknown navigation key")
            }
        },
    )
}
