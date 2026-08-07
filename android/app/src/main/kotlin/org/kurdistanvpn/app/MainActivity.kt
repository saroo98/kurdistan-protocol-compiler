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
import androidx.compose.runtime.produceState
import androidx.compose.runtime.setValue
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
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
import org.kurdistanvpn.core.model.EnrollmentUiState
import org.kurdistanvpn.core.model.ImportSource
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.OperatorClientProjection
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProductCapabilities
import org.kurdistanvpn.core.model.ProductCapability
import org.kurdistanvpn.core.model.InstalledApplication
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.ProbeExecutionState
import org.kurdistanvpn.core.model.ResetScope
import org.kurdistanvpn.core.model.ProjectionStatus
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.model.QrDisplayMatrix
import org.kurdistanvpn.core.ui.KurdistanTheme
import org.kurdistanvpn.core.ui.KurdistanIcons
import org.kurdistanvpn.core.ui.R as UiR
import org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsAboutScreen
import org.kurdistanvpn.feature.home.HomeScreen
import org.kurdistanvpn.feature.profiles.ImportPreviewScreen
import org.kurdistanvpn.feature.profiles.ProfilesScreen
import org.kurdistanvpn.feature.profiles.OperatorProviderScreen
import org.kurdistanvpn.feature.settingsrecovery.SettingsRecoveryScreen
import org.kurdistanvpn.feature.settingsrecovery.SettingsIndexScreen
import org.kurdistanvpn.feature.settingsrecovery.ConnectionSettingsScreen
import org.kurdistanvpn.feature.settingsrecovery.TunnelDnsSettingsScreen
import org.kurdistanvpn.feature.settingsrecovery.RoutingSettingsScreen
import org.kurdistanvpn.feature.settingsrecovery.UpdatesProbeSettingsScreen
import org.kurdistanvpn.feature.settingsrecovery.ExpertSettingsScreen
import org.kurdistanvpn.platform.importing.AndroidImportSources
import org.kurdistanvpn.platform.importing.ArtifactClass
import org.kurdistanvpn.platform.importing.BoundedInputReader
import org.kurdistanvpn.platform.importing.ImportCandidate
import org.kurdistanvpn.platform.importing.MultipartQrAccumulator
import org.kurdistanvpn.platform.importing.OfflineQrScanner
import org.kurdistanvpn.platform.importing.OfflineQrEncoder
import org.kurdistanvpn.data.secure.SensitiveAction
import org.kurdistanvpn.data.secure.SensitiveActionAuthorizer
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() {
    private val viewModel: ProductRootViewModel by viewModels {
        ProductRootViewModel.Factory((application as KurdistanApplication).compositionRoot)
    }
    private val vpnController by lazy { VpnRuntimeController(applicationContext) }

    internal fun appStateSnapshotForTesting(): AppState = viewModel.state.value
    internal fun diagnosticStateSnapshotForTesting(): DiagnosticWorkflowState =
        viewModel.diagnosticState.value

    internal fun prepareRuntimeAuthorityForTesting(
        config: VpnRuntimeConfig,
        onReady: (ByteArray) -> Unit,
        onFailure: (OperationError) -> Unit,
    ) {
        viewModel.prepareRuntimeStart(config, onReady, onFailure)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val state = viewModel.state.collectAsStateWithLifecycle().value
            val backupState = viewModel.backupState.collectAsStateWithLifecycle().value
            val diagnosticState = viewModel.diagnosticState.collectAsStateWithLifecycle().value
            val diagnosticEvents = viewModel.diagnosticEvents.collectAsStateWithLifecycle().value
            val settings = viewModel.settings.collectAsStateWithLifecycle().value
            val compatibility = viewModel.compatibility.collectAsStateWithLifecycle().value
            val probeState = viewModel.probeState.collectAsStateWithLifecycle().value
            val enrollmentState = viewModel.enrollmentState.collectAsStateWithLifecycle().value
            val vpnRuntime = vpnController.snapshot.collectAsStateWithLifecycle().value
            val installedApplications by produceState(initialValue = emptyList<InstalledApplication>()) {
                value = withContext(Dispatchers.IO) { discoverLaunchableApplications() }
            }
            val capabilities = remember { phase13Capabilities() }
            val vpnPermission = rememberLauncherForActivityResult(
                ActivityResultContracts.StartActivityForResult(),
            ) { result ->
                if (result.resultCode == RESULT_OK) {
                    vpnController.startStaged()
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
                        vpnController.startStaged()
                    } else {
                        vpnPermission.launch(permission)
                    }
                } else {
                    vpnController.notificationPermissionRejected()
                }
            }
            var pendingBackupBytes by remember { mutableStateOf<ByteArray?>(null) }
            var pendingDiagnosticBytes by remember { mutableStateOf<ByteArray?>(null) }
            var pendingEnrollmentBytes by remember { mutableStateOf<ByteArray?>(null) }
            var pendingEnrollmentLocalId by remember { mutableStateOf<String?>(null) }
            var enrollmentQr by remember { mutableStateOf<QrDisplayMatrix?>(null) }
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
            val enrollmentWriter = rememberLauncherForActivityResult(
                ActivityResultContracts.CreateDocument("application/vnd.kurdistan.recipient"),
            ) { uri ->
                pendingEnrollmentBytes?.let { bytes ->
                    if (uri == null) bytes.fill(0)
                    else runCatching { writeAndWipe(uri, bytes) }
                        .onSuccess {
                            pendingEnrollmentLocalId?.let(viewModel::markEnrollmentRequestExported)
                        }
                        .onFailure { viewModel.dismissEnrollmentAction() }
                }
                pendingEnrollmentBytes = null
                pendingEnrollmentLocalId = null
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
                    diagnosticEvents = diagnosticEvents,
                    settings = settings,
                    compatibility = compatibility,
                    probeState = probeState,
                    enrollmentState = enrollmentState,
                    enrollmentQr = enrollmentQr,
                    installedApplications = installedApplications,
                    capabilities = capabilities,
                    vpnRuntime = vpnRuntime,
                    onPreviewFile = ::previewFile,
                    onPreviewClipboard = ::previewClipboard,
                    onPreviewQr = viewModel::preview,
                    onConfirmImport = viewModel::confirmImport,
                    onCancelImport = viewModel::cancelImport,
                    onRejectImport = viewModel::rejectImport,
                    onClearError = viewModel::clearError,
                    onDeleteProfile = { localRecordId ->
                        if (localRecordId == settings.profiles.activeLocalRecordId && vpnRuntime.state.hasRuntimeSession()) {
                            vpnController.stop()
                        }
                        viewModel.deleteProfile(localRecordId)
                    },
                    onCreateEnrollment = viewModel::createEnrollmentRequest,
                    onExportEnrollment = { localRecordId ->
                        viewModel.exportEnrollmentRequest(localRecordId) { bytes ->
                            pendingEnrollmentLocalId = localRecordId
                            pendingEnrollmentBytes = bytes
                            enrollmentWriter.launch("kurd-device-request.kurd-recipient")
                        }
                    },
                    onShowEnrollmentQr = { localRecordId ->
                        viewModel.exportEnrollmentRequest(localRecordId) { bytes ->
                            enrollmentQr = try {
                                OfflineQrEncoder.recipientRequest(bytes)
                            } finally {
                                bytes.fill(0)
                            }
                            viewModel.markEnrollmentRequestExported(localRecordId)
                        }
                    },
                    onDismissEnrollmentQr = { enrollmentQr = null },
                    onDeleteEnrollmentKey = viewModel::deleteEnrollmentKey,
                    onDismissEnrollmentAction = viewModel::dismissEnrollmentAction,
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
                    onResetAll = {
                        vpnController.stop()
                        viewModel.resetAll()
                    },
                    onResetScope = { scope ->
                        vpnController.stop()
                        viewModel.reset(scope)
                    },
                    onTheme = viewModel::setTheme,
                    onHighContrast = viewModel::setHighContrast,
                    onReducedMotion = viewModel::setReducedMotion,
                    onConnection = { value ->
                        if (vpnRuntime.state.hasRuntimeSession()) vpnController.stop()
                        viewModel.setConnection(value)
                    },
                    onTunnel = { value ->
                        if (vpnRuntime.state.hasRuntimeSession()) vpnController.stop()
                        viewModel.setTunnel(value)
                    },
                    onRouting = { value ->
                        if (vpnRuntime.state.hasRuntimeSession()) vpnController.stop()
                        viewModel.setRouting(value)
                    },
                    onUpdates = viewModel::setUpdates,
                    onProbes = viewModel::setProbes,
                    onDiagnosticsSettings = viewModel::setDiagnostics,
                    onExpert = viewModel::setExpert,
                    onSelectProfile = { localRecordId ->
                        if (localRecordId != settings.profiles.activeLocalRecordId && vpnRuntime.state.hasRuntimeSession()) {
                            vpnController.stop()
                        }
                        viewModel.selectProfile(localRecordId)
                    },
                    onToggleFavorite = viewModel::toggleFavorite,
                    onRunLocalProbe = viewModel::runLocalProbe,
                    onPrepareDiagnostic = viewModel::prepareDiagnostic,
                    onConfirmDiagnostic = {
                        viewModel.confirmDiagnostic { bytes ->
                            pendingDiagnosticBytes = bytes
                            diagnosticWriter.launch("kurdistan-vpn-diagnostics.kdiag")
                        }
                    },
                    onCancelDiagnostic = viewModel::cancelDiagnostic,
                    onClearDiagnosticEvents = viewModel::clearDiagnosticEvents,
                    onStartVpn = {
                        viewModel.prepareRuntimeStart(
                            config = runtimeConfig(settings),
                            onReady = { authority ->
                                vpnController.stageAuthority(authority)
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
                                        vpnController.startStaged()
                                    } else {
                                        vpnPermission.launch(permission)
                                    }
                                }
                            },
                            onFailure = { error ->
                                vpnController.authorityRejected(error.name)
                            },
                        )
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

    private fun discoverLaunchableApplications(): List<InstalledApplication> {
        val query = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.queryIntentActivities(
                query,
                android.content.pm.PackageManager.ResolveInfoFlags.of(0),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.queryIntentActivities(query, 0)
        }
        return resolved.mapNotNull { info ->
            val applicationInfo = info.activityInfo?.applicationInfo ?: return@mapNotNull null
            val packageName = applicationInfo.packageName ?: return@mapNotNull null
            InstalledApplication(
                packageName = packageName,
                label = info.loadLabel(packageManager).toString().take(128),
                systemApp = applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0,
            )
        }.distinctBy { it.packageName }
            .sortedBy { it.label.lowercase() }
            .take(512)
    }

    private companion object {
        const val MAX_BACKUP_BYTES = 8 * 1024 * 1024 + 128
    }
}

private fun org.kurdistanvpn.runtime.api.VpnRuntimeState.hasRuntimeSession(): Boolean = when (this) {
    org.kurdistanvpn.runtime.api.VpnRuntimeState.IDLE,
    org.kurdistanvpn.runtime.api.VpnRuntimeState.FAILED,
    org.kurdistanvpn.runtime.api.VpnRuntimeState.REVOKED,
    org.kurdistanvpn.runtime.api.VpnRuntimeState.BLOCKED,
    -> false
    else -> true
}

private fun runtimeConfig(settings: Phase9Settings): VpnRuntimeConfig {
    val mode = when (settings.routing.mode) {
        PerAppSelectionMode.ALL_APPS -> PerAppRoutingMode.ALL_APPS
        PerAppSelectionMode.INCLUDE_ONLY -> PerAppRoutingMode.INCLUDE_ONLY
        PerAppSelectionMode.EXCLUDE_SELECTED -> PerAppRoutingMode.EXCLUDE_SELECTED
    }
    return VpnRuntimeConfig(
        routingPolicy = VpnRoutingPolicy(mode, settings.routing.packages),
        selectionMode = settings.connection.selectionMode,
        ipMode = settings.tunnel.ipMode,
        dnsMode = settings.tunnel.dnsMode,
        customDns = settings.tunnel.customDns,
        mtu = settings.tunnel.mtu,
        metered = settings.tunnel.metered,
        allowLan = settings.connection.allowLan,
    )
}

private fun operatorProjection(
    state: AppState,
    settings: Phase9Settings,
): OperatorClientProjection {
    val profiles = (state as? AppState.Ready)?.profiles.orEmpty()
    val active = profiles.firstOrNull { it.localRecordId == settings.profiles.activeLocalRecordId }
        ?: profiles.firstOrNull()
    val expired = active?.expiresAtEpochSeconds?.let { it <= System.currentTimeMillis() / 1000 } == true
    return OperatorClientProjection(
        providerAlias = "Local signed import",
        publicationGeneration = null,
        profileGeneration = active?.generation,
        profileExpiryEpochSeconds = active?.expiresAtEpochSeconds,
        relayCompatibility = ProjectionStatus.UNAVAILABLE,
        rotationState = if (expired) ProjectionStatus.EXPIRED else ProjectionStatus.UNAVAILABLE,
        updateCapability = ProjectionStatus.UNAVAILABLE,
        lastVerifiedUpdateCategory = null,
        emergencyDenyState = ProjectionStatus.UNAVAILABLE,
    )
}

private fun phase13Capabilities(): ProductCapabilities = ProductCapabilities(
    vpnRuntime = ProductCapability(
        id = "Android VpnService and Kurd loopback transport",
        available = true,
        explanation = "Real TUN lifecycle and authenticated Kurd transport over the owned loopback relay.",
    ),
    publicRelay = ProductCapability(
        id = "Owned non-loopback relay",
        available = false,
        explanation = "Requires explicitly authorized Phase 14 deployment and field evidence.",
    ),
    providerNetworkUpdates = ProductCapability(
        id = "Automatic provider network updates",
        available = false,
        explanation = "No production provider endpoint or authority is configured. Signed local imports remain available.",
    ),
    localProxy = ProductCapability(
        id = "Authenticated local proxy",
        available = false,
        explanation = "Closed until the proxy can use the Kurd relay path without direct-egress bypass.",
    ),
    hotspotProxy = ProductCapability(
        id = "Authenticated hotspot proxy",
        available = false,
        explanation = "Closed pending relay-backed operation, abuse controls, and Phase 14 validation.",
    ),
)

private enum class AppDestination : NavKey {
    HOME,
    PROFILES,
    OPERATOR_PROVIDER,
    SETTINGS,
    CONNECTION,
    TUNNEL_DNS,
    ROUTING,
    UPDATES_PROBES,
    EXPERT,
    PRIVACY_RECOVERY,
    DIAGNOSTICS_ABOUT,
}

@Composable
private fun KurdistanApp(
    state: AppState,
    backupState: BackupWorkflowState,
    diagnosticState: DiagnosticWorkflowState,
    diagnosticEvents: List<org.kurdistanvpn.core.model.DiagnosticEvent>,
    settings: Phase9Settings,
    compatibility: CompatibilitySummary?,
    probeState: ProbeExecutionState,
    enrollmentState: EnrollmentUiState,
    enrollmentQr: QrDisplayMatrix?,
    installedApplications: List<InstalledApplication>,
    capabilities: ProductCapabilities,
    vpnRuntime: org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot,
    onPreviewFile: (Uri) -> Unit,
    onPreviewClipboard: () -> Unit,
    onPreviewQr: (ImportCandidate, ImportSource) -> Unit,
    onConfirmImport: () -> Unit,
    onCancelImport: () -> Unit,
    onRejectImport: () -> Unit,
    onClearError: () -> Unit,
    onDeleteProfile: (String) -> Unit,
    onCreateEnrollment: () -> Unit,
    onExportEnrollment: (String) -> Unit,
    onShowEnrollmentQr: (String) -> Unit,
    onDismissEnrollmentQr: () -> Unit,
    onDeleteEnrollmentKey: (String) -> Unit,
    onDismissEnrollmentAction: () -> Unit,
    onExportProfile: (String, String) -> Unit,
    onCreateBackup: (String) -> Unit,
    onOpenBackup: (String) -> Unit,
    onConfirmRestore: () -> Unit,
    onCancelRestore: () -> Unit,
    onResetAll: () -> Unit,
    onResetScope: (ResetScope) -> Unit,
    onTheme: (ThemePreference) -> Unit,
    onHighContrast: (Boolean) -> Unit,
    onReducedMotion: (Boolean) -> Unit,
    onConnection: (org.kurdistanvpn.core.model.ConnectionPreferences) -> Unit,
    onTunnel: (org.kurdistanvpn.core.model.TunnelPreferences) -> Unit,
    onRouting: (org.kurdistanvpn.core.model.RoutingPreferences) -> Unit,
    onUpdates: (org.kurdistanvpn.core.model.UpdatePreferences) -> Unit,
    onProbes: (org.kurdistanvpn.core.model.ProbePreferences) -> Unit,
    onDiagnosticsSettings: (org.kurdistanvpn.core.model.DiagnosticPreferences) -> Unit,
    onExpert: (org.kurdistanvpn.core.model.ExpertPreferences) -> Unit,
    onSelectProfile: (String) -> Unit,
    onToggleFavorite: (String) -> Unit,
    onRunLocalProbe: () -> Unit,
    onPrepareDiagnostic: () -> Unit,
    onConfirmDiagnostic: () -> Unit,
    onCancelDiagnostic: () -> Unit,
    onClearDiagnosticEvents: () -> Unit,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit,
) {
    val backStack = remember { mutableStateListOf<NavKey>(AppDestination.HOME) }
    val currentState by rememberUpdatedState(state)
    val currentBackupState by rememberUpdatedState(backupState)
    val currentDiagnosticState by rememberUpdatedState(diagnosticState)
    val currentDiagnosticEvents by rememberUpdatedState(diagnosticEvents)
    val currentSettings by rememberUpdatedState(settings)
    val currentCompatibility by rememberUpdatedState(compatibility)
    val currentProbeState by rememberUpdatedState(probeState)
    val currentEnrollmentState by rememberUpdatedState(enrollmentState)
    val currentEnrollmentQr by rememberUpdatedState(enrollmentQr)
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
    val navigatePrimary: (AppDestination) -> Unit = { destination ->
        if (backStack.isEmpty()) {
            backStack.add(destination)
        } else {
            backStack[0] = destination
            while (backStack.size > 1) {
                backStack.removeAt(backStack.lastIndex)
            }
        }
    }
    val navigateBack: () -> Unit = {
        when {
            backStack.size > 1 -> backStack.removeAt(backStack.lastIndex)
            backStack.firstOrNull() != AppDestination.HOME -> backStack[0] = AppDestination.HOME
        }
    }
    ProductNavigationChrome(
        current = backStack.lastOrNull() as? AppDestination ?: AppDestination.HOME,
        onNavigate = navigatePrimary,
    ) {
    NavDisplay(
        backStack = backStack,
        onBack = navigateBack,
        entryProvider = { key ->
            when (key) {
                AppDestination.HOME -> NavEntry(key) {
                    HomeScreen(
                        state = currentState,
                        settings = currentSettings,
                        vpnRuntime = currentVpnRuntime,
                        onStartVpn = onStartVpn,
                        onStopVpn = onStopVpn,
                        onOpenProfiles = { backStack.add(AppDestination.PROFILES) },
                        onOpenSettings = { backStack.add(AppDestination.SETTINGS) },
                        onOpenDiagnostics = { backStack.add(AppDestination.DIAGNOSTICS_ABOUT) },
                        onClearError = onClearError,
                    )
                }
                AppDestination.PROFILES -> NavEntry(key) {
                    ProfilesScreen(
                        profiles = (currentState as? AppState.Ready)?.profiles.orEmpty(),
                        settings = currentSettings,
                        enrollmentState = currentEnrollmentState,
                        enrollmentQr = currentEnrollmentQr,
                        onCreateEnrollment = onCreateEnrollment,
                        onExportEnrollment = onExportEnrollment,
                        onShowEnrollmentQr = onShowEnrollmentQr,
                        onDismissEnrollmentQr = onDismissEnrollmentQr,
                        onDeleteEnrollmentKey = onDeleteEnrollmentKey,
                        onDismissEnrollmentAction = onDismissEnrollmentAction,
                        onSelectProfile = onSelectProfile,
                        onToggleFavorite = onToggleFavorite,
                        onOpenOperator = { backStack.add(AppDestination.OPERATOR_PROVIDER) },
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
                            if (candidate != null) {
                                onPreviewQr(candidate, ImportSource.KURD_URI)
                            } else {
                                onRejectImport()
                            }
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
                        onBack = navigateBack,
                    )
                }
                AppDestination.OPERATOR_PROVIDER -> NavEntry(key) {
                    OperatorProviderScreen(
                        projection = operatorProjection(currentState, currentSettings),
                        onBack = navigateBack,
                    )
                }
                AppDestination.SETTINGS -> NavEntry(key) {
                    SettingsIndexScreen(
                        settings = currentSettings,
                        capabilities = capabilities,
                        onConnection = { backStack.add(AppDestination.CONNECTION) },
                        onTunnelDns = { backStack.add(AppDestination.TUNNEL_DNS) },
                        onRouting = { backStack.add(AppDestination.ROUTING) },
                        onUpdatesProbes = { backStack.add(AppDestination.UPDATES_PROBES) },
                        onExpert = { backStack.add(AppDestination.EXPERT) },
                        onPrivacyRecovery = { backStack.add(AppDestination.PRIVACY_RECOVERY) },
                        onDiagnostics = { backStack.add(AppDestination.DIAGNOSTICS_ABOUT) },
                        onBack = navigateBack,
                    )
                }
                AppDestination.CONNECTION -> NavEntry(key) {
                    ConnectionSettingsScreen(
                        value = currentSettings.connection,
                        onChange = onConnection,
                        onRecoverInternet = onStopVpn,
                        onBack = navigateBack,
                    )
                }
                AppDestination.TUNNEL_DNS -> NavEntry(key) {
                    TunnelDnsSettingsScreen(
                        value = currentSettings.tunnel,
                        onChange = onTunnel,
                        onBack = navigateBack,
                    )
                }
                AppDestination.ROUTING -> NavEntry(key) {
                    RoutingSettingsScreen(
                        value = currentSettings.routing,
                        applications = installedApplications,
                        onChange = onRouting,
                        onBack = navigateBack,
                    )
                }
                AppDestination.UPDATES_PROBES -> NavEntry(key) {
                    UpdatesProbeSettingsScreen(
                        updates = currentSettings.updates,
                        probes = currentSettings.probes,
                        probeState = currentProbeState,
                        onUpdates = onUpdates,
                        onProbes = onProbes,
                        onRunLocalProbe = onRunLocalProbe,
                        onBack = navigateBack,
                    )
                }
                AppDestination.EXPERT -> NavEntry(key) {
                    ExpertSettingsScreen(
                        expert = currentSettings.expert,
                        diagnostics = currentSettings.diagnostics,
                        onExpert = onExpert,
                        onDiagnostics = onDiagnosticsSettings,
                        onBack = navigateBack,
                    )
                }
                AppDestination.PRIVACY_RECOVERY -> NavEntry(key) {
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
                        onBack = navigateBack,
                        onResetScope = onResetScope,
                    )
                }
                AppDestination.DIAGNOSTICS_ABOUT -> NavEntry(key) {
                    DiagnosticsAboutScreen(
                        state = currentDiagnosticState,
                        appVersion = BuildConfig.VERSION_NAME,
                        compatibility = currentCompatibility,
                        events = currentDiagnosticEvents,
                        onPrepare = onPrepareDiagnostic,
                        onConfirm = onConfirmDiagnostic,
                        onCancel = onCancelDiagnostic,
                        onClearEvents = onClearDiagnosticEvents,
                        onBack = navigateBack,
                    )
                }
                else -> error("Unknown navigation key")
            }
        },
    )
    }
}

@Composable
private fun ProductNavigationChrome(
    current: AppDestination,
    onNavigate: (AppDestination) -> Unit,
    content: @Composable () -> Unit,
) {
    val primary = listOf(AppDestination.HOME, AppDestination.PROFILES, AppDestination.SETTINGS)
    val compact = LocalConfiguration.current.screenWidthDp < 600
    if (compact) {
        Column(Modifier.fillMaxSize()) {
            Box(Modifier.weight(1f)) { content() }
            NavigationBar {
                primary.forEach { destination ->
                    NavigationBarItem(
                        selected = current == destination,
                        onClick = { onNavigate(destination) },
                        icon = {
                            Icon(
                                imageVector = primaryIcon(destination),
                                contentDescription = null,
                            )
                        },
                        label = { Text(primaryLabel(destination)) },
                        modifier = Modifier.testTag("primary_${destination.name.lowercase()}"),
                    )
                }
            }
        }
    } else {
        Row(Modifier.fillMaxSize()) {
            NavigationRail {
                primary.forEach { destination ->
                    NavigationRailItem(
                        selected = current == destination,
                        onClick = { onNavigate(destination) },
                        icon = {
                            Icon(
                                imageVector = primaryIcon(destination),
                                contentDescription = null,
                            )
                        },
                        label = { Text(primaryLabel(destination)) },
                        modifier = Modifier.testTag("primary_${destination.name.lowercase()}"),
                    )
                }
            }
            Box(Modifier.weight(1f)) { content() }
        }
    }
}

@Composable
private fun primaryLabel(destination: AppDestination): String = when (destination) {
    AppDestination.HOME -> stringResource(UiR.string.home)
    AppDestination.PROFILES -> stringResource(UiR.string.profiles)
    AppDestination.SETTINGS -> stringResource(UiR.string.settings)
    else -> error("not a primary destination")
}

private fun primaryIcon(destination: AppDestination) = when (destination) {
    AppDestination.HOME -> KurdistanIcons.Home
    AppDestination.PROFILES -> KurdistanIcons.Profiles
    AppDestination.SETTINGS -> KurdistanIcons.Settings
    else -> error("not a primary destination")
}
