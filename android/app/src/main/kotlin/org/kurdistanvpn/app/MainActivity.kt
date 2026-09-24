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
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.foundation.layout.absoluteOffset
import androidx.compose.foundation.layout.size
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInWindow
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.geometry.Offset
import androidx.lifecycle.repeatOnLifecycle
import androidx.window.layout.WindowInfoTracker
import androidx.window.layout.FoldingFeature
import org.kurdistanvpn.core.ui.ProductFold
import org.kurdistanvpn.core.ui.ProductRect
import org.kurdistanvpn.core.ui.ProductLayoutMode
import org.kurdistanvpn.core.ui.adaptiveProductLayout
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.produceState
import androidx.compose.runtime.setValue
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
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
import org.kurdistanvpn.core.model.DeploymentProjection
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.ProductCapabilities
import org.kurdistanvpn.core.model.ProductCapability
import org.kurdistanvpn.core.model.InstalledApplication
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.ProbeExecutionState
import org.kurdistanvpn.core.model.ResetScope
import org.kurdistanvpn.core.model.ProjectionStatus
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.model.QrDisplayMatrix
import org.kurdistanvpn.core.model.ProtectedRecoveryPresentation
import org.kurdistanvpn.core.model.ProtectedRecoveryReason
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
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.first
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.withResumed
import org.kurdistanvpn.domain.*
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.ProductFailure
import org.kurdistanvpn.core.model.ProductFailureCode
import kotlin.coroutines.resume

class MainActivity : AppCompatActivity(), org.kurdistanvpn.platform.system.ForegroundSystemActions, ProductConnectionForeground, ProductDiagnosticForeground, ProductBackupForeground, ProductEnrollmentForeground, ProductPrivacyForeground {
    private var startupCoreFailure: AppState? = null
    private var enrollmentQr by mutableStateOf<QrDisplayMatrix?>(null)
    private val exportRequests = mutableMapOf<ExportDocumentKind, ActivityEffectRequest>()
    private val exportLaunchers = mutableMapOf<ExportDocumentKind, androidx.activity.result.ActivityResultLauncher<String>>()
    private val permissionRequests = mutableMapOf<ActivityEffectKind, ActivityEffectRequest>()
    private lateinit var vpnPermission: androidx.activity.result.ActivityResultLauncher<Intent>
    private lateinit var notificationPermission: androidx.activity.result.ActivityResultLauncher<String>
    private lateinit var profilePicker: androidx.activity.result.ActivityResultLauncher<Array<String>>
    private lateinit var backupPicker: androidx.activity.result.ActivityResultLauncher<Array<String>>
    private lateinit var systemSettings: androidx.activity.result.ActivityResultLauncher<Intent>
    private var backupPassword: ByteArray? = null
    private lateinit var cameraPermission: androidx.activity.result.ActivityResultLauncher<String>
    private var cameraResult: ((Boolean) -> Unit)? = null
    private var platformPermissionResult: Pair<ActivityEffectKind, kotlinx.coroutines.CancellableContinuation<DomainResult<Unit>>>? = null
    private var manualOperation: org.kurdistanvpn.core.model.CatalogId? = null
    private var manualTarget: Pair<CatalogId, Long>? = null
    private val viewModel: ProductRootViewModel by viewModels {
        ProductRootViewModel.Factory((application as KurdistanApplication).compositionRoot)
    }
    private val connectionViewModel: org.kurdistanvpn.feature.home.ConnectionViewModel by viewModels {
        ProductViewModelFactory((application as KurdistanApplication).compositionRoot)
    }
    private val settingsViewModel: org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel by viewModels {
        ProductViewModelFactory((application as KurdistanApplication).compositionRoot)
    }
    private val diagnosticsViewModel: org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsViewModel by viewModels {
        ProductViewModelFactory((application as KurdistanApplication).compositionRoot)
    }
    private val profilesViewModel: org.kurdistanvpn.feature.profiles.ProfilesViewModel by viewModels {
        ProductViewModelFactory((application as KurdistanApplication).compositionRoot)
    }
    private val onboardingViewModel: org.kurdistanvpn.feature.onboarding.OnboardingViewModel by viewModels {
        ProductViewModelFactory((application as KurdistanApplication).compositionRoot)
    }
    private val privacyViewModel: org.kurdistanvpn.feature.settingsrecovery.PrivacyRecoveryViewModel by viewModels {
        ProductViewModelFactory((application as KurdistanApplication).compositionRoot)
    }
    private val vpnController by lazy {
        (application as KurdistanApplication).runtimeController.also { it.attachScreen() }
    }
    private val manualConsentAdmission = ManualStartAdmission()
    private val sensitiveAuthorizer = SensitiveActionAuthorizer(this) { (application as KurdistanApplication).activityEffects }
    private var foregroundLaunchJob: kotlinx.coroutines.Job? = null
    private val proxyClipboard by lazy { ProxyClipboard(this) }
    private val proxyCredentials by lazy {
        ProxyCredentialController(android.os.SystemClock::elapsedRealtime, { complete ->
            sensitiveAuthorizer.authorize(SensitiveAction.REVEAL,
                getString(R.string.proxy_credentials_title), getString(R.string.proxy_credentials_help), onResult = complete)
        }, vpnController::readProxyCredentials, vpnController::rotateProxyCredentials,
            proxyClipboard::copy, proxyClipboard::clear)
    }

    internal fun appStateSnapshotForTesting(): AppState = startupCoreFailure ?: profilesViewModel.importState.value ?: viewModel.state.value
    internal fun diagnosticStateSnapshotForTesting(): DiagnosticWorkflowState =
        diagnosticsViewModel.state.value
    internal fun backupStateSnapshotForTesting(): org.kurdistanvpn.core.model.BackupWorkflowState = privacyViewModel.backupState.value

    private val productFold = kotlinx.coroutines.flow.MutableStateFlow<ProductFold?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                WindowInfoTracker.getOrCreate(this@MainActivity).windowLayoutInfo(this@MainActivity).collect { info ->
                    val fold = info.displayFeatures.filterIsInstance<FoldingFeature>().firstOrNull { it.isSeparating }
                    val density = resources.displayMetrics.density
                    productFold.value = fold?.let {
                        ProductFold(ProductRect(it.bounds.left / density, it.bounds.top / density,
                            it.bounds.right / density, it.bounds.bottom / density),
                            it.orientation == FoldingFeature.Orientation.VERTICAL, it.isSeparating)
                    }
                }
            }
        }
        registerExportDestinations(savedInstanceState)
        registerConnectionPermissions(savedInstanceState)
        // Native class initialization may fail before the protected graph can be constructed.
        // Show a binary failure without inventing storage or offering destructive recovery.
        startupCoreFailure = coreStartupFailure(readCoreCompatibility {
            org.kurdistanvpn.core.nativejni.NativeBridge().compatibility()
        })
        if (startupCoreFailure != null) {
            setContent {
                KurdistanTheme {
                    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)
                        .windowInsetsPadding(WindowInsets.safeDrawing).padding(24.dp)) {
                        androidx.compose.material3.Text(stringResource(if (startupCoreFailure == AppState.CoreIncompatible)
                            org.kurdistanvpn.core.ui.R.string.core_incompatible else org.kurdistanvpn.core.ui.R.string.core_unavailable),
                            color = MaterialTheme.colorScheme.onBackground)
                        androidx.compose.material3.Button(onClick = { vpnController.stop() }) {
                            androidx.compose.material3.Text(stringResource(org.kurdistanvpn.core.ui.R.string.disconnect))
                        }
                        androidx.compose.material3.Button(onClick = { vpnController.recoverInternet() }) {
                            androidx.compose.material3.Text(stringResource(org.kurdistanvpn.core.ui.R.string.recover_internet_stop_vpn))
                        }
                    }
                }
            }
            return
        }
        // Configuration restoration preserves location, never an earlier profile approval.
        profilesViewModel.cancelReview()
        setContent {
            val startupState = viewModel.state.collectAsStateWithLifecycle().value
            val importState = profilesViewModel.importState.collectAsStateWithLifecycle().value
            val state = importState ?: startupState
            val backupState = privacyViewModel.backupState.collectAsStateWithLifecycle().value
            val privacyOperation = privacyViewModel.state.collectAsStateWithLifecycle().value
            val diagnosticState = diagnosticsViewModel.state.collectAsStateWithLifecycle().value
            val diagnosticEvents = diagnosticsViewModel.events.collectAsStateWithLifecycle().value
            val protectedRecovery = viewModel.protectedRecovery.collectAsStateWithLifecycle().value
            val startupSettings = viewModel.settings.collectAsStateWithLifecycle().value
            val settings = settingsViewModel.appliedSettings.collectAsStateWithLifecycle().value ?: startupSettings
            val compatibility = viewModel.compatibility.collectAsStateWithLifecycle().value
            val probeState = if ((application as KurdistanApplication).compositionRoot.protectedStateFacade() != null)
                settingsViewModel.probeState.collectAsStateWithLifecycle().value else ProbeExecutionState.Idle
            val enrollmentState = onboardingViewModel.state.collectAsStateWithLifecycle().value
            androidx.compose.runtime.LaunchedEffect(startupState) { onboardingViewModel.refresh() }
            val vpnRuntime = vpnController.snapshot.collectAsStateWithLifecycle().value
            val connectionState = connectionViewModel.state.collectAsStateWithLifecycle().value
            val settingsEditor = if ((application as KurdistanApplication).compositionRoot.protectedStateFacade() != null)
                settingsViewModel.state.collectAsStateWithLifecycle().value else null
            val settingsFailure = settingsViewModel.changeFailure.collectAsStateWithLifecycle().value
            val connectionFailure = connectionViewModel.failure.collectAsStateWithLifecycle().value
            val dismissSettingsFailure = {
                settingsViewModel.clearChangeFailure()
            }
            val profileFailure = profilesViewModel.failure.collectAsStateWithLifecycle().value
            var proxyDialog by remember { mutableStateOf(false) }
            androidx.compose.runtime.LaunchedEffect(vpnRuntime.runtimeRequestId, vpnRuntime.state) {
                proxyCredentials.clear()
                if (vpnRuntime.state != org.kurdistanvpn.runtime.api.VpnRuntimeState.ACTIVE_KURD_LIVE) proxyDialog = false
            }
            val installedApplications by produceState(initialValue = emptyList<InstalledApplication>()) {
                val result = (application as KurdistanApplication).compositionRoot.systemPolicy.installedApplications()
                if (result is DomainResult.Success) value = result.value
            }
            val capabilities = remember { phase13Capabilities() }
            val authorizer = sensitiveAuthorizer
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
                if (connectionFailure != null) androidx.compose.material3.AlertDialog(
                    onDismissRequest = connectionViewModel::dismissFailure,
                    text = { Text(stringResource(UiR.string.protected_action_unconfirmed)) },
                    confirmButton = { androidx.compose.material3.TextButton(onClick = connectionViewModel::dismissFailure) {
                        Text(stringResource(android.R.string.ok))
                    } },
                )
                if (privacyOperation is org.kurdistanvpn.core.model.OperationState.Failed ||
                    privacyOperation is org.kurdistanvpn.core.model.OperationState.PartiallyApplied) androidx.compose.material3.AlertDialog(
                    onDismissRequest = privacyViewModel::dismissFailure,
                    text = { Text(stringResource(UiR.string.protected_action_unconfirmed)) },
                    confirmButton = { androidx.compose.material3.TextButton(onClick = privacyViewModel::dismissFailure) {
                        Text(stringResource(android.R.string.ok))
                    } },
                )
                if (profileFailure != null && importState == null) androidx.compose.material3.AlertDialog(
                    onDismissRequest = profilesViewModel::dismissFailure,
                    text = { Text(stringResource(UiR.string.profile_change_unconfirmed)) },
                    confirmButton = { androidx.compose.material3.TextButton(onClick = profilesViewModel::dismissFailure) {
                        Text(stringResource(android.R.string.ok))
                    } },
                )
                if (settingsFailure != null) androidx.compose.material3.AlertDialog(
                    onDismissRequest = dismissSettingsFailure,
                    title = { androidx.compose.material3.Text(stringResource(R.string.settings_apply_failed_title)) },
                    text = { androidx.compose.material3.Text(stringResource(R.string.settings_apply_failed_help)) },
                    confirmButton = { androidx.compose.material3.TextButton(onClick = dismissSettingsFailure) {
                        androidx.compose.material3.Text(stringResource(android.R.string.ok))
                    } },
                )
                KurdistanApp(
                    fold = productFold.collectAsStateWithLifecycle().value,
                    state = state,
                    backupState = backupState,
                    diagnosticState = diagnosticState,
                    diagnosticEvents = diagnosticEvents,
                    protectedRecovery = protectedRecovery,
                    settings = settings,
                    compatibility = compatibility,
                    probeState = probeState,
                    enrollmentState = enrollmentState,
                    enrollmentQr = enrollmentQr,
                    installedApplications = installedApplications,
                    capabilities = capabilities,
                    vpnRuntime = vpnRuntime,
                    connectionState = connectionState,
                    settingsEditor = settingsEditor,
                    onOpenSettingsDraft = { settingsViewModel.open() },
                    onEditSettings = { requested -> lifecycleScope.launch {
                        if (settingsViewModel.state.value.phase in setOf(
                                org.kurdistanvpn.feature.settingsrecovery.SettingsEditorPhase.APPLIED,
                                org.kurdistanvpn.feature.settingsrecovery.SettingsEditorPhase.IDLE)) settingsViewModel.open().join()
                        settingsViewModel.saveDraft(requested)
                    } },
                    onApplySettingsDraft = { lifecycleScope.launch {
                        settingsViewModel.apply().join()
                        settingsViewModel.refreshApplied().join()
                    } },
                    onCancelSettingsDraft = { lifecycleScope.launch {
                        settingsViewModel.cancel().join()
                        if (settingsViewModel.state.value.failure == null) settingsViewModel.open()
                    } },
                    onPickFile = ::launchProfilePicker,
                    onRequestCamera = ::requestCamera,
                    onPreviewClipboard = ::previewClipboard,
                    onPreviewQr = ::previewCandidate,
                    onConfirmImport = { lifecycleScope.launch { profilesViewModel.confirmImport().join(); viewModel.clearError() } },
                    onCancelImport = { profilesViewModel.cancelImport() },
                    onRejectImport = { profilesViewModel.rejectImport() },
                    onClearError = { profilesViewModel.cancelImport(); viewModel.clearError() },
                    onDeleteProfile = { localRecordId ->
                        if (localRecordId == settings.profiles.activeLocalRecordId && vpnRuntime.state.hasRuntimeSession()) {
                            vpnController.stop()
                        }
                        lifecycleScope.launch {
                            profilesViewModel.deleteReviewed(CatalogId(localRecordId)).join()
                            viewModel.clearError()
                        }
                    },
                    onCreateEnrollment = { lifecycleScope.launch { onboardingViewModel.createEnrollment().join(); viewModel.clearError() } },
                    onExportEnrollment = { onboardingViewModel.export(CatalogId(it), EnrollmentExport.FILE) },
                    onShowEnrollmentQr = { onboardingViewModel.export(CatalogId(it), EnrollmentExport.QR) },
                    onDismissEnrollmentQr = { enrollmentQr = null },
                    onDeleteEnrollmentKey = { onboardingViewModel.delete(CatalogId(it)) },
                    onDismissEnrollmentAction = { onboardingViewModel.refresh() },
                    onExportProfile = ::createBackupExport,
                    onCreateBackup = { passphrase -> createBackupExport(null, passphrase) },
                    onOpenBackup = ::launchBackupPicker,
                    onConfirmRestore = { lifecycleScope.launch { privacyViewModel.confirmRestore().join(); viewModel.clearError() } },
                    onCancelRestore = { privacyViewModel.cancel() },
                    onConfirmMigration = { lifecycleScope.launch { privacyViewModel.migrateLegacy().join(); viewModel.refresh() } },
                    onConfirmPresentationRecovery = { lifecycleScope.launch { privacyViewModel.recover().join(); viewModel.refresh() } },
                    onReviewReset = { privacyViewModel.previewReset(it) },
                    onCancelReset = { privacyViewModel.cancelReset() },
                    onResetAll = {
                        vpnController.stop()
                        lifecycleScope.launch { privacyViewModel.confirmReset(ResetScope.EVERYTHING).join(); viewModel.refresh() }
                    },
                    onResetScope = { scope ->
                        dispatchSupportedReset(scope, vpnController::stop) {
                            lifecycleScope.launch { privacyViewModel.confirmReset(it).join(); viewModel.refresh() }
                        }
                    },
                    onTheme = { value -> settingsViewModel.change { it.copy(theme = value) } },
                    onHighContrast = { value -> settingsViewModel.change { it.copy(highContrast = value) } },
                    onReducedMotion = { value -> settingsViewModel.change { it.copy(reducedMotion = value) } },
                    onConnection = { value ->
                        settingsViewModel.change { it.copy(connection = value) }
                    },
                    onTunnel = { value ->
                        settingsViewModel.change { it.copy(tunnel = value) }
                    },
                    onRouting = { value ->
                        settingsViewModel.change { it.copy(routing = value) }
                    },
                    onUpdates = { value -> settingsViewModel.change { it.copy(updates = value) } },
                    onProbes = { value -> settingsViewModel.change { it.copy(probes = value) } },
                    onDiagnosticsSettings = { value -> lifecycleScope.launch {
                        diagnosticsViewModel.setPreferences(value).join()
                        settingsViewModel.refreshApplied()
                    } },
                    onExpert = { value -> settingsViewModel.change { it.copy(expert = value) } },
                    onSelectProfile = { localRecordId ->
                        cancelManualRequest()
                        if (localRecordId != settings.profiles.activeLocalRecordId && vpnRuntime.state.hasRuntimeSession()) {
                            vpnController.stop()
                        }
                        lifecycleScope.launch {
                            profilesViewModel.activateReviewed(CatalogId(localRecordId)).join()
                            settingsViewModel.refreshApplied()
                        }
                    },
                    onReviewProfile = { profilesViewModel.review(CatalogId(it)) },
                    onCancelProfileReview = { profilesViewModel.cancelReview() },
                    onToggleFavorite = { id -> lifecycleScope.launch {
                        profilesViewModel.setFavorite(CatalogId(id), id !in settings.profiles.favoriteLocalRecordIds).join()
                        settingsViewModel.refreshApplied()
                    } },
                    onRunLocalProbe = { if ((application as KurdistanApplication).compositionRoot.protectedStateFacade() != null) settingsViewModel.runProbe() },
                    onPrepareDiagnostic = { diagnosticsViewModel.prepare() },
                    onConfirmDiagnostic = { diagnosticsViewModel.confirm() },
                    onCancelDiagnostic = { diagnosticsViewModel.cancel() },
                    onClearDiagnosticEvents = { diagnosticsViewModel.clear() },
                    onStartVpn = ::requestManualConnection,
                    onStopVpn = { cancelManualRequest(); connectionViewModel.disconnect() },
                    onRecoverInternet = { cancelManualRequest(); connectionViewModel.recoverInternet() },
                    onPauseVpn = { duration ->
                        cancelManualRequest()
                        lifecycleScope.launch {
                            val current = try { vpnController.querySettingsStatus() } catch (_: Exception) { null }
                            if (duration != null && (current?.alwaysOn != false || current.lockdown != false)) {
                                openSystemVpnSettings()
                            } else {
                                if (duration == null) connectionViewModel.resume().join()
                                else connectionViewModel.pause(duration).join()
                                settingsViewModel.refreshApplied()
                            }
                        }
                    },
                    onSystemVpnSettings = ::openSystemVpnSettings,
                    onProxyCredentials = { proxyDialog = true },
                    onRestartProxy = { proxyCredentials.clear(); vpnController.restartProxy() },
                    onApplyTunOnly = {
                        proxyCredentials.clear()
                        settingsViewModel.change {
                            it.copy(tunnelMode = org.kurdistanvpn.core.model.TunnelMode.TUN_ONLY)
                        }
                    },
                )
                if (proxyDialog) ProxyCredentialDialog(proxyCredentials) { proxyDialog = false }
            }
        }
        if (savedInstanceState == null) {
            handleExternalIntent(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (startupCoreFailure != null) return
        handleExternalIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        proxyClipboard.clear()
        proxyCredentials.foreground()
    }

    override fun onStop() {
        proxyCredentials.background(sensitiveAuthorizer.isDeviceCredentialPending)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        if (startupCoreFailure != null) return
        (application as KurdistanApplication).compositionRoot.attachSystemActions(this)
        val boot = try { android.provider.Settings.Global.getInt(contentResolver, android.provider.Settings.Global.BOOT_COUNT) }
            catch (_: Exception) { -1 }
        foregroundLaunchJob?.cancel()
        foregroundLaunchJob = lifecycleScope.launch {
            viewModel.state.first { it != AppState.Booting && it != AppState.CompatibilityCheck }
            try {
                (application as KurdistanApplication).compositionRoot.expireForegroundPause(
                    System.currentTimeMillis(), android.os.SystemClock.elapsedRealtime(), boot)
            } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
            catch (_: Exception) { return@launch } // Unproved storage must not permit foreground auto-connect.
            settingsViewModel.refreshApplied().join()
            val settings = settingsViewModel.appliedSettings.value ?: return@launch
            if (!viewModel.foregroundLaunch.consume(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED),
                    viewModel.state.value is AppState.Ready && settings.connection.autoConnectOnLaunch,
                    !settings.pausePolicy.permitsAutoConnect)) return@launch
            kotlinx.coroutines.withTimeoutOrNull(5_000) {
                vpnController.controlReady.first { it }
                vpnController.startOnForegroundLaunch { lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) }
            }
        }
    }

    override fun onPause() {
        if (startupCoreFailure == null) (application as KurdistanApplication).compositionRoot.detachSystemActions(this)
        proxyClipboard.clear()
        foregroundLaunchJob?.cancel()
        foregroundLaunchJob = null
        super.onPause()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) proxyClipboard.clear()
    }

    override fun onDestroy() {
        platformPermissionResult?.second?.let { if (it.isActive) it.resume(interruptedPlatformAction()) }
        platformPermissionResult = null
        cameraResult = null
        backupPassword?.fill(0)
        backupPassword = null
        if (isFinishing) {
            exportRequests.values.forEach { (application as KurdistanApplication).exportDestination.cancel(it.id) }
            exportRequests.clear()
            permissionRequests.values.forEach { (application as KurdistanApplication).activityEffects.cancel(it.id) }
            permissionRequests.clear()
        }
        proxyCredentials.close()
        manualConsentAdmission.close()
        vpnController.detachScreen()
        super.onDestroy()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        exportRequests.forEach { (kind, request) ->
            outState.putString("export-${kind.name}-request", request.id.value)
            outState.putString("export-${kind.name}-operation", request.operationId.value)
        }
        permissionRequests.forEach { (kind, request) ->
            outState.putString("permission-${kind.name}-request", request.id.value)
            outState.putString("permission-${kind.name}-operation", request.operationId.value)
        }
        super.onSaveInstanceState(outState)
    }

    private fun registerConnectionPermissions(saved: Bundle?) {
        listOf(ActivityEffectKind.VPN_CONSENT, ActivityEffectKind.NOTIFICATION_PERMISSION,
            ActivityEffectKind.FILE_IMPORT, ActivityEffectKind.BACKUP_IMPORT, ActivityEffectKind.CAMERA_PERMISSION,
            ActivityEffectKind.SYSTEM_SETTINGS).forEach { kind ->
            val id = saved?.getString("permission-${kind.name}-request")
            val operation = saved?.getString("permission-${kind.name}-operation")
            if (id != null && operation != null) runCatching {
                ActivityEffectRequest(org.kurdistanvpn.core.model.CatalogId(id), org.kurdistanvpn.core.model.CatalogId(operation), kind)
            }.getOrNull()?.let { permissionRequests[kind] = it }
        }
        vpnPermission = activityResultRegistry.register("product-vpn-consent", this,
            ActivityResultContracts.StartActivityForResult()) { result ->
            finishConnectionPermission(ActivityEffectKind.VPN_CONSENT, result.resultCode == RESULT_OK)
        }
        notificationPermission = activityResultRegistry.register("product-notification-permission", this,
            ActivityResultContracts.RequestPermission()) { granted ->
            finishConnectionPermission(ActivityEffectKind.NOTIFICATION_PERMISSION, granted)
        }
        systemSettings = activityResultRegistry.register("product-system-settings", this,
            ActivityResultContracts.StartActivityForResult()) {
            val request = permissionRequests.remove(ActivityEffectKind.SYSTEM_SETTINGS) ?: return@register
            (application as KurdistanApplication).activityEffects.complete(request.id, request.operationId, true)
        }
        profilePicker = activityResultRegistry.register("product-profile-import", this,
            ActivityResultContracts.OpenDocument()) { uri ->
            val request = permissionRequests.remove(ActivityEffectKind.FILE_IMPORT) ?: return@register
            val accepted = (application as KurdistanApplication).activityEffects.complete(request.id, request.operationId,
                startupCoreFailure == null) == EffectCompletion.COMPLETED
            if (startupCoreFailure == null) {
                if (accepted && uri != null) previewFile(uri) else if (!accepted) profilesViewModel.rejectImport(OperationError.CANCELLED)
            }
        }
        backupPicker = activityResultRegistry.register("product-backup-import", this,
            ActivityResultContracts.OpenDocument()) { uri ->
            val password = backupPassword
            backupPassword = null
            val request = permissionRequests.remove(ActivityEffectKind.BACKUP_IMPORT)
            val accepted = request != null && (application as KurdistanApplication).activityEffects.complete(
                request.id, request.operationId, password != null && startupCoreFailure == null) == EffectCompletion.COMPLETED
            if (!accepted || uri == null || password == null) {
                password?.fill(0)
                if (startupCoreFailure == null) privacyViewModel.backupInputFailed(OperationError.CANCELLED)
            } else openBackupDocument(uri, password)
        }
        cameraPermission = activityResultRegistry.register("product-camera-permission", this,
            ActivityResultContracts.RequestPermission()) { granted ->
            val request = permissionRequests.remove(ActivityEffectKind.CAMERA_PERMISSION) ?: return@register
            if (completePlatformPermission(request)) return@register
            val callback = cameraResult
            cameraResult = null
            val accepted = (application as KurdistanApplication).activityEffects.complete(request.id, request.operationId,
                callback != null && startupCoreFailure == null) == EffectCompletion.COMPLETED
            lifecycleScope.launch { lifecycle.withResumed {
                callback?.invoke(accepted && granted && ContextCompat.checkSelfPermission(this@MainActivity,
                    Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
            } }
        }
    }

    private fun beginPickerRequest(kind: ActivityEffectKind): ActivityEffectRequest? {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) || permissionRequests.isNotEmpty()) return null
        val request = ActivityEffectRequest(org.kurdistanvpn.core.model.CatalogId(java.util.UUID.randomUUID().toString()),
            org.kurdistanvpn.core.model.CatalogId(java.util.UUID.randomUUID().toString()), kind)
        val effects = (application as KurdistanApplication).activityEffects
        if (!effects.offer(request)) return null
        if (!effects.claim(request.id, true)) { effects.cancel(request.id); return null }
        permissionRequests[kind] = request
        return request
    }

    private fun launchProfilePicker() {
        val request = beginPickerRequest(ActivityEffectKind.FILE_IMPORT) ?: return
        try { profilePicker.launch(arrayOf("application/octet-stream", "application/vnd.kurdistan.profile+cose")) }
        catch (_: Exception) {
            (application as KurdistanApplication).activityEffects.cancel(request.id)
            permissionRequests.remove(request.kind)
            profilesViewModel.rejectImport(OperationError.CANCELLED)
        }
    }

    private fun launchBackupPicker(passphrase: String) {
        val request = beginPickerRequest(ActivityEffectKind.BACKUP_IMPORT) ?: return
        backupPassword = passphrase.encodeToByteArray()
        try { backupPicker.launch(arrayOf("application/vnd.kurdistan.backup", "application/octet-stream")) }
        catch (_: Exception) {
            backupPassword?.fill(0)
            backupPassword = null
            (application as KurdistanApplication).activityEffects.cancel(request.id)
            permissionRequests.remove(request.kind)
            privacyViewModel.backupInputFailed(OperationError.CANCELLED)
        }
    }

    private fun createBackupExport(localId: String?, passphrase: String) {
        val password = passphrase.encodeToByteArray()
        sensitiveAuthorizer.authorize(
            if (localId == null) SensitiveAction.CREATE_BACKUP else SensitiveAction.EXPORT_PROFILE,
            getString(if (localId == null) UiR.string.authorize_backup_title else UiR.string.authorize_profile_export_title),
            getString(if (localId == null) UiR.string.authorize_backup_subtitle else UiR.string.authorize_profile_export_subtitle),
        ) { approved ->
            if (!approved) { password.fill(0); return@authorize }
            lifecycleScope.launch {
                try {
                    privacyViewModel.beginBackupInput().join()
                    val ids = localId?.let { setOf(CatalogId(it)) } ?: emptySet()
                    (application as KurdistanApplication).compositionRoot.backupOperations.stageExportPassword(ids, password)
                    privacyViewModel.previewBackup(ids).join()
                    privacyViewModel.confirmBackup().join()
                } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
                catch (_: Exception) { privacyViewModel.backupInputFailed(OperationError.RECOVERY_REQUIRED) }
                finally { password.fill(0) }
            }
        }
    }

    private fun openBackupDocument(uri: Uri, password: ByteArray) {
        val operations = (application as KurdistanApplication).compositionRoot.backupOperations
        lifecycleScope.launch {
            var opened: BackupOperationPreview? = null
            var handedOff = false
            try {
                privacyViewModel.beginBackupInput().join()
                val result = withContext(Dispatchers.IO) {
                    val bytes = readBounded(uri, MAX_BACKUP_BYTES)
                    operations.open(bytes, password).also {
                        if (it is org.kurdistanvpn.core.nativeapi.NativeResult.Success) opened = it.value
                    }
                }
                when (result) {
                    is org.kurdistanvpn.core.nativeapi.NativeResult.Success -> {
                        privacyViewModel.previewRestore(result.value.id).join()
                        handedOff = privacyViewModel.state.value is org.kurdistanvpn.core.model.OperationState.AwaitingConfirmation
                    }
                    is org.kurdistanvpn.core.nativeapi.NativeResult.Failure -> privacyViewModel.backupInputFailed(result.error)
                }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                privacyViewModel.backupInputFailed(OperationError.INVALID_INPUT)
            } finally {
                password.fill(0)
                if (!handedOff) operations.cancel(opened?.id)
            }
        }
    }

    private fun requestCamera(result: (Boolean) -> Unit) {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            result(true); return
        }
        val request = beginPickerRequest(ActivityEffectKind.CAMERA_PERMISSION) ?: return
        cameraResult = result
        try { cameraPermission.launch(Manifest.permission.CAMERA) }
        catch (_: Exception) {
            cameraResult = null
            (application as KurdistanApplication).activityEffects.cancel(request.id)
            permissionRequests.remove(request.kind)
            result(false)
        }
    }

    private fun requestManualConnection() {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) || permissionRequests.isNotEmpty()) return
        manualConsentAdmission.stage()
        val operation = CatalogId(java.util.UUID.randomUUID().toString())
        manualOperation = operation
        lifecycleScope.launch {
            val target = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                (application as KurdistanApplication).compositionRoot.protectedStateFacade()?.readProjection()?.runtimeProfile
            }
            if (manualOperation != operation || !lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return@launch
            if (target == null) {
                cancelManualRequest(); vpnController.authorityRejected("AUTHORITY_UNAVAILABLE"); return@launch
            }
            val result = (application as KurdistanApplication).compositionRoot.connectionRepository
                .connect(CatalogId(target.profileId), target.settingsRevision)
            if (result is DomainResult.Rejected && manualOperation == operation) {
                cancelManualRequest(); vpnController.authorityRejected(result.failure.code.name)
            }
        }
    }

    override fun beginConnection(profileId: CatalogId, settingsRevision: Long): Boolean {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) || permissionRequests.isNotEmpty()) return false
        manualConsentAdmission.stage()
        manualOperation = CatalogId(java.util.UUID.randomUUID().toString())
        manualTarget = profileId to settingsRevision
        requestConnectionPermissions()
        return true
    }

    private fun requestConnectionPermissions() {
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) {
            launchConnectionPermission(ActivityEffectKind.NOTIFICATION_PERMISSION) {
                notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        } else prepareVpnConsent()
    }

    private fun cancelManualRequest() {
        manualConsentAdmission.cancel()
        manualOperation = null
        manualTarget = null
    }

    private fun prepareVpnConsent() {
        val permission = vpnController.prepareIntent()
        if (permission == null) startAfterConsent()
        else launchConnectionPermission(ActivityEffectKind.VPN_CONSENT) { vpnPermission.launch(permission) }
    }

    private fun launchConnectionPermission(kind: ActivityEffectKind, launch: () -> Unit) {
        val operation = manualOperation ?: return
        val effects = (application as KurdistanApplication).activityEffects
        val request = ActivityEffectRequest(org.kurdistanvpn.core.model.CatalogId(java.util.UUID.randomUUID().toString()), operation, kind)
        if (!effects.offer(request)) { manualConsentAdmission.cancel(); manualOperation = null; return }
        if (!effects.claim(request.id, lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))) {
            effects.cancel(request.id); manualConsentAdmission.cancel(); manualOperation = null; return
        }
        permissionRequests[kind] = request
        try { launch() } catch (_: Exception) {
            effects.cancel(request.id); permissionRequests.remove(kind)
            manualConsentAdmission.cancel(); manualOperation = null
            vpnController.permissionRejected()
        }
    }

    private fun finishConnectionPermission(kind: ActivityEffectKind, granted: Boolean) {
        val request = permissionRequests.remove(kind) ?: return
        if (completePlatformPermission(request)) return
        val completion = (application as KurdistanApplication).activityEffects.complete(request.id, request.operationId,
            manualOperation == request.operationId && startupCoreFailure == null)
        if (completion != EffectCompletion.COMPLETED || !granted) {
            manualConsentAdmission.cancel(); manualOperation = null
            if (kind == ActivityEffectKind.NOTIFICATION_PERMISSION) vpnController.notificationPermissionRejected()
            else vpnController.permissionRejected()
            return
        }
        lifecycleScope.launch {
            lifecycle.withResumed {
                if (manualOperation != request.operationId) return@withResumed
                if (kind == ActivityEffectKind.NOTIFICATION_PERMISSION) {
                    if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this@MainActivity,
                        Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                        manualConsentAdmission.cancel(); manualOperation = null; vpnController.notificationPermissionRejected()
                    } else prepareVpnConsent()
                } else if (vpnController.prepareIntent() == null) startAfterConsent()
                else { manualConsentAdmission.cancel(); manualOperation = null; vpnController.permissionRejected() }
            }
        }
    }

    private fun startAfterConsent() {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        val target = manualTarget ?: return
        manualTarget = null
        val ticket = manualConsentAdmission.consume() ?: return
        manualOperation = null
        lifecycleScope.launch {
            val failure = (application as KurdistanApplication).compositionRoot
                .validateProductionManualStart(target.first, target.second)
            if (!manualConsentAdmission.isCurrent(ticket) || !lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return@launch
            if (failure == null) { vpnController.stageManualStart(); vpnController.startStaged() }
            else vpnController.authorityRejected(failure.name)
        }
    }

    private fun registerExportDestinations(saved: Bundle?) {
        ExportDocumentKind.entries.forEach { kind ->
            val requestId = saved?.getString("export-${kind.name}-request")
            val operationId = saved?.getString("export-${kind.name}-operation")
            if (requestId != null && operationId != null) {
                runCatching {
                    ActivityEffectRequest(org.kurdistanvpn.core.model.CatalogId(requestId),
                        org.kurdistanvpn.core.model.CatalogId(operationId), ActivityEffectKind.EXPORT_DESTINATION)
                }.getOrNull()?.let { exportRequests[kind] = it }
            }
            val mime = when (kind) {
                ExportDocumentKind.BACKUP -> "application/vnd.kurdistan.backup"
                ExportDocumentKind.DIAGNOSTIC -> "application/vnd.kurdistan.diagnostic"
                ExportDocumentKind.ENROLLMENT -> "application/vnd.kurdistan.recipient"
            }
            exportLaunchers[kind] = activityResultRegistry.register("product-export-${kind.name}", this,
                ActivityResultContracts.CreateDocument(mime)) { uri -> finishExport(kind, uri) }
        }
    }

    override fun requestDiagnosticDestination(operationId: CatalogId, bytes: ByteArray): Boolean =
        launchExport(ExportDocumentKind.DIAGNOSTIC, bytes, "kurdistan-vpn-diagnostics.kdiag", operationId = operationId)

    override fun requestBackupDestination(bytes: ByteArray, operationId: CatalogId?): Boolean =
        launchExport(ExportDocumentKind.BACKUP, bytes, "kurdistan-vpn-backup.kbackup", operationId = operationId)

    override suspend fun authenticatePrivacy(action: org.kurdistanvpn.core.model.SensitiveAction,
        allowed: Set<org.kurdistanvpn.core.model.AllowedAuthenticator>): Boolean =
        kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
            sensitiveAuthorizer.authorize(SensitiveAction.REVEAL, getString(UiR.string.privacy_authentication_title),
                getString(UiR.string.privacy_authentication_help), allowed) { accepted ->
                if (continuation.isActive) continuation.resumeWith(Result.success(accepted))
            }
        }

    override fun requestEnrollmentDestination(id: CatalogId, destination: EnrollmentExport, bytes: ByteArray): Boolean {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return false
        return when (destination) {
            EnrollmentExport.FILE -> launchExport(ExportDocumentKind.ENROLLMENT, bytes, "kurd-device-request.kurd-recipient", id.value)
            EnrollmentExport.QR -> try { enrollmentQr = OfflineQrEncoder.recipientRequest(bytes); true }
                finally { bytes.fill(0) }
        }
    }

    private fun previewCandidate(candidate: ImportCandidate, source: ImportSource) {
        when (val staged = (application as KurdistanApplication).compositionRoot.importOperations.stage(candidate, source)) {
            is org.kurdistanvpn.core.nativeapi.NativeResult.Success -> profilesViewModel.preview(source, staged.value)
            is org.kurdistanvpn.core.nativeapi.NativeResult.Failure -> profilesViewModel.rejectImport(staged.error)
        }
    }

    private fun launchExport(kind: ExportDocumentKind, bytes: ByteArray, name: String, localId: String? = null,
        operationId: CatalogId? = null): Boolean {
        if (exportRequests.isNotEmpty()) { bytes.fill(0); return false }
        val owner = (application as KurdistanApplication).exportDestination
        val request = owner.stage(kind, bytes, localId, lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED), operationId)
            ?: return false
        exportRequests[kind] = request
        try {
            checkNotNull(exportLaunchers[kind]).launch(name)
            return true
        } catch (_: Exception) {
            owner.cancel(request.id)
            exportRequests.remove(kind)
            exportFailed(kind, OperationError.STORAGE_FAILURE, request.operationId)
            return false
        }
    }

    private fun finishExport(kind: ExportDocumentKind, uri: Uri?) {
        val request = exportRequests.remove(kind) ?: return
        val document = (application as KurdistanApplication).exportDestination.take(request.id, request.operationId)
        if (startupCoreFailure != null) { document?.close(); return }
        if (document == null) { exportFailed(kind, OperationError.CANCELLED, request.operationId); return }
        document.use {
            if (uri == null) { exportFailed(kind, OperationError.CANCELLED, request.operationId); return }
            if (runCatching { writeAndWipe(uri, it.bytes) }.isFailure) {
                exportFailed(kind, OperationError.STORAGE_FAILURE, request.operationId)
            } else when (kind) {
                ExportDocumentKind.BACKUP -> (application as KurdistanApplication).compositionRoot.privacyRepository.backupDestinationFinished(request.operationId, null)
                ExportDocumentKind.DIAGNOSTIC -> (application as KurdistanApplication).compositionRoot.diagnosticsRepository.destinationFinished(request.operationId, null)
                ExportDocumentKind.ENROLLMENT -> it.enrollmentLocalId?.let { id -> onboardingViewModel.markExported(CatalogId(id)) }
            }
        }
    }

    private fun exportFailed(kind: ExportDocumentKind, error: OperationError, operationId: CatalogId? = null) {
        when (kind) {
            ExportDocumentKind.BACKUP -> if (operationId != null)
                (application as KurdistanApplication).compositionRoot.privacyRepository.backupDestinationFinished(operationId, error)
                else privacyViewModel.backupInputFailed(error)
            ExportDocumentKind.DIAGNOSTIC -> if (operationId != null)
                (application as KurdistanApplication).compositionRoot.diagnosticsRepository.destinationFinished(operationId, error)
            ExportDocumentKind.ENROLLMENT -> onboardingViewModel.refresh()
        }
    }

    private fun openSystemVpnSettings() {
        lifecycleScope.launch { if (openSettings(PlatformSetting.VPN) is DomainResult.Rejected)
            vpnController.authorityRejected("SYSTEM_SETTINGS_UNAVAILABLE") }
    }

    private fun interruptedPlatformAction() = DomainResult.Rejected(ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))

    private fun completePlatformPermission(request: ActivityEffectRequest): Boolean {
        val callback = platformPermissionResult?.takeIf { it.first == request.kind }?.second ?: return false
        platformPermissionResult = null
        val completed = (application as KurdistanApplication).activityEffects.complete(request.id, request.operationId,
            callback.isActive && startupCoreFailure == null) == EffectCompletion.COMPLETED
        if (callback.isActive) callback.resume(if (completed) DomainResult.Success(Unit) else interruptedPlatformAction())
        return true
    }

    override suspend fun requestPermission(permission: ProductPermission): DomainResult<Unit> {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return interruptedPlatformAction()
        val kind = when (permission) {
            ProductPermission.VPN_CONSENT -> ActivityEffectKind.VPN_CONSENT
            ProductPermission.NOTIFICATIONS -> ActivityEffectKind.NOTIFICATION_PERMISSION
            ProductPermission.CAMERA -> ActivityEffectKind.CAMERA_PERMISSION
            ProductPermission.NETWORK_IDENTITY -> return DomainResult.Rejected(ProductFailure(ProductFailureCode.NETWORK_IDENTITY_UNAVAILABLE))
        }
        val vpnIntent = if (permission == ProductPermission.VPN_CONSENT) android.net.VpnService.prepare(this) else null
        if (permission == ProductPermission.VPN_CONSENT && vpnIntent == null) return DomainResult.Success(Unit)
        if (permission == ProductPermission.NOTIFICATIONS && Build.VERSION.SDK_INT < 33) return DomainResult.Success(Unit)
        val request = beginPickerRequest(kind) ?: return DomainResult.Rejected(ProductFailure(ProductFailureCode.OPERATION_ALREADY_ACTIVE))
        return kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
            platformPermissionResult = kind to continuation
            continuation.invokeOnCancellation {
                runOnUiThread {
                    if (platformPermissionResult?.second === continuation) {
                        platformPermissionResult = null
                        permissionRequests.remove(kind)
                        (application as KurdistanApplication).activityEffects.cancel(request.id)
                    }
                }
            }
            try {
                when (permission) {
                    ProductPermission.VPN_CONSENT -> vpnPermission.launch(checkNotNull(vpnIntent))
                    ProductPermission.NOTIFICATIONS -> notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                    ProductPermission.CAMERA -> cameraPermission.launch(Manifest.permission.CAMERA)
                    ProductPermission.NETWORK_IDENTITY -> error("UNREACHABLE_PERMISSION")
                }
            } catch (_: RuntimeException) {
                platformPermissionResult = null
                permissionRequests.remove(kind)
                (application as KurdistanApplication).activityEffects.cancel(request.id)
                if (continuation.isActive) continuation.resume(interruptedPlatformAction())
            }
        }
    }

    override suspend fun openSettings(setting: PlatformSetting): DomainResult<Unit> {
        val request = beginPickerRequest(ActivityEffectKind.SYSTEM_SETTINGS) ?: return interruptedPlatformAction()
        val intent = when (setting) {
            PlatformSetting.VPN -> Intent(android.provider.Settings.ACTION_VPN_SETTINGS)
            PlatformSetting.NOTIFICATIONS -> Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, packageName)
            PlatformSetting.BATTERY -> Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            PlatformSetting.APP_DETAILS -> Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))
            PlatformSetting.LANGUAGE -> if (Build.VERSION.SDK_INT >= 33)
                Intent(android.provider.Settings.ACTION_APP_LOCALE_SETTINGS, Uri.parse("package:$packageName"))
                else Intent(android.provider.Settings.ACTION_LOCALE_SETTINGS)
        }
        return try { systemSettings.launch(intent); DomainResult.Success(Unit) }
        catch (_: RuntimeException) {
            permissionRequests.remove(request.kind)
            (application as KurdistanApplication).activityEffects.cancel(request.id)
            interruptedPlatformAction()
        }
    }

    override fun screenshotPolicy(): ScreenshotPolicy = if (window.attributes.flags and
        android.view.WindowManager.LayoutParams.FLAG_SECURE != 0) ScreenshotPolicy.PROTECTED else ScreenshotPolicy.ALLOWED

    override fun setScreenshotPolicy(policy: ScreenshotPolicy): DomainResult<Unit> {
        val request = beginPickerRequest(ActivityEffectKind.SCREENSHOT_POLICY) ?: return interruptedPlatformAction()
        return try {
            if (policy == ScreenshotPolicy.PROTECTED) window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            else window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            DomainResult.Success(Unit)
        } finally {
            permissionRequests.remove(request.kind)
            (application as KurdistanApplication).activityEffects.complete(request.id, request.operationId, true)
        }
    }

    override fun clipboardState(): ClipboardState = if (proxyClipboard.ownsValue) ClipboardState.OWNED_SENSITIVE_VALUE
        else ClipboardState.OTHER_OR_UNAVAILABLE

    override fun clearOwnedClipboard(): DomainResult<Unit> {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return interruptedPlatformAction()
        proxyClipboard.clear()
        return if (proxyClipboard.ownsValue) interruptedPlatformAction() else DomainResult.Success(Unit)
    }

    override suspend fun previewClipboardImport(): DomainResult<ProfileImportPreview> {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return interruptedPlatformAction()
        val candidate = try {
            val clip = getSystemService(ClipboardManager::class.java).primaryClip ?: return DomainResult.Rejected(ProductFailure(ProductFailureCode.INVALID_INPUT))
            AndroidImportSources.clipboard(clip, ArtifactClass.SIGNED_PUBLIC)
        } catch (_: RuntimeException) { return DomainResult.Rejected(ProductFailure(ProductFailureCode.INVALID_INPUT)) }
        val owner = (application as KurdistanApplication).compositionRoot.importOperations
        var preview: ImportOperationPreview? = null
        return try {
            when (val result = withContext(Dispatchers.IO) { owner.prepare(candidate, ImportSource.CLIPBOARD).also {
                if (it is org.kurdistanvpn.core.nativeapi.NativeResult.Success) preview = it.value
            } }) {
                is org.kurdistanvpn.core.nativeapi.NativeResult.Success -> DomainResult.Success(ProfileImportPreview(result.value.id, result.value.display))
                is org.kurdistanvpn.core.nativeapi.NativeResult.Failure -> DomainResult.Rejected(ProductFailure(
                    if (owner.cleanupUnproven) ProductFailureCode.STORAGE_DEGRADED else ProductFailureCode.PROFILE_UNTRUSTED))
            }
        } catch (cancelled: kotlinx.coroutines.CancellationException) { owner.cancel(preview?.id); throw cancelled }
        finally { candidate.parts.forEach { it.fill(0) } }
    }

    override suspend fun copyRedactedSummary(profileId: CatalogId): DomainResult<Unit> {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return interruptedPlatformAction()
        val projection = withContext(Dispatchers.IO) {
            (application as KurdistanApplication).compositionRoot.protectedStateFacade()?.readProjection()
        } ?: return DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_DEGRADED))
        val profile = projection.profiles.singleOrNull { it.localRecordId == profileId.value }
            ?: return DomainResult.Rejected(ProductFailure(ProductFailureCode.INVALID_INPUT))
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return interruptedPlatformAction()
        // Deliberately excludes aliases, IDs, endpoints, fingerprints, keys and configuration.
        val summary = "Kurdistan VPN\ngeneration=${profile.generation}\ntrust=${profile.trust.name}\nexpires=${profile.expiresAtEpochSeconds}"
        getSystemService(ClipboardManager::class.java).setPrimaryClip(android.content.ClipData.newPlainText("Kurdistan VPN", summary))
        return DomainResult.Success(Unit)
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
            profilesViewModel.rejectImport()
            return
        }
        previewCandidate(candidate, source)
    }

    private fun previewClipboard() {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip ?: run {
            profilesViewModel.rejectImport()
            return
        }
        val candidate = runCatching {
            AndroidImportSources.clipboard(clip, ArtifactClass.SIGNED_PUBLIC)
        }.getOrNull() ?: run {
            profilesViewModel.rejectImport()
            return
        }
        previewCandidate(candidate, ImportSource.CLIPBOARD)
    }

    private fun handleExternalIntent(value: Intent) {
        when (value.action) {
            Intent.ACTION_VIEW -> {
                val link = value.dataString ?: run {
                    profilesViewModel.rejectImport()
                    return
                }
                val candidate = runCatching {
                    AndroidImportSources.uri(link, ArtifactClass.SIGNED_PUBLIC)
                }.getOrNull() ?: run {
                    profilesViewModel.rejectImport()
                    return
                }
                previewCandidate(candidate, ImportSource.KURD_URI)
            }
            Intent.ACTION_SEND -> {
                val uri = IntentCompat.getParcelableExtra(
                    value,
                    Intent.EXTRA_STREAM,
                    Uri::class.java,
                ) ?: run {
                    profilesViewModel.rejectImport()
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

private fun org.kurdistanvpn.runtime.api.VpnRuntimeState.hasRuntimeSession(): Boolean = when (this) {
    org.kurdistanvpn.runtime.api.VpnRuntimeState.IDLE,
    org.kurdistanvpn.runtime.api.VpnRuntimeState.FAILED,
    org.kurdistanvpn.runtime.api.VpnRuntimeState.REVOKED,
    org.kurdistanvpn.runtime.api.VpnRuntimeState.BLOCKED,
    -> false
    else -> true
}

internal fun dispatchSupportedReset(scope: ResetScope, stop: () -> Unit, reset: (ResetScope) -> Unit): org.kurdistanvpn.core.model.OperationError? {
    scope.unavailableReason?.let { return it }
    stop()
    reset(scope)
    return null
}

private fun operatorProjection(
    state: AppState,
    settings: ProductSettings,
): DeploymentProjection {
    val profiles = (state as? AppState.Ready)?.profiles.orEmpty()
    val active = profiles.firstOrNull { it.localRecordId == settings.profiles.activeLocalRecordId }
        ?: profiles.firstOrNull()
    val expired = active?.expiresAtEpochSeconds?.let { it <= System.currentTimeMillis() / 1000 } == true
    return DeploymentProjection(
        alias = org.kurdistanvpn.core.model.SafeAlias("Local signed import"),
        publicationGeneration = null,
        profileGeneration = active?.generation,
        profileExpiryEpochSeconds = active?.expiresAtEpochSeconds,
        relayCompatibility = ProjectionStatus.UNAVAILABLE,
        rotationState = if (expired) ProjectionStatus.EXPIRED else ProjectionStatus.UNAVAILABLE,
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

internal enum class AppDestination : NavKey {
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
    fold: ProductFold?,
    state: AppState,
    backupState: BackupWorkflowState,
    diagnosticState: DiagnosticWorkflowState,
    diagnosticEvents: List<org.kurdistanvpn.core.model.DiagnosticEvent>,
    protectedRecovery: ProtectedRecoveryPresentation,
    settings: ProductSettings,
    compatibility: CompatibilitySummary?,
    probeState: ProbeExecutionState,
    enrollmentState: EnrollmentUiState,
    enrollmentQr: QrDisplayMatrix?,
    installedApplications: List<InstalledApplication>,
    capabilities: ProductCapabilities,
    vpnRuntime: org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot,
    onPickFile: () -> Unit,
    onRequestCamera: ((Boolean) -> Unit) -> Unit,
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
    onConfirmMigration: () -> Unit,
    onConfirmPresentationRecovery: () -> Unit,
    onResetAll: () -> Unit,
    onResetScope: (ResetScope) -> Unit,
    onReviewReset: (ResetScope) -> Unit,
    onCancelReset: () -> Unit,
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
    onReviewProfile: (String) -> Unit,
    onCancelProfileReview: () -> Unit,
    onToggleFavorite: (String) -> Unit,
    onRunLocalProbe: () -> Unit,
    onPrepareDiagnostic: () -> Unit,
    onConfirmDiagnostic: () -> Unit,
    onCancelDiagnostic: () -> Unit,
    onClearDiagnosticEvents: () -> Unit,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit,
    onRecoverInternet: () -> Unit,
    onPauseVpn: (Long?) -> Unit,
    onSystemVpnSettings: () -> Unit,
    onProxyCredentials: () -> Unit,
    onRestartProxy: () -> Unit,
    onApplyTunOnly: () -> Unit,
    connectionState: org.kurdistanvpn.core.model.ConnectionState? = null,
    settingsEditor: org.kurdistanvpn.feature.settingsrecovery.SettingsEditorState? = null,
    onOpenSettingsDraft: () -> Unit = {},
    onEditSettings: (ProductSettings) -> Unit = {},
    onApplySettingsDraft: () -> Unit = {},
    onCancelSettingsDraft: () -> Unit = {},
) {
    val homeStack = rememberProductBackStack(ProductDestination.Home)
    val navigationLifecycle = androidx.lifecycle.compose.LocalLifecycleOwner.current.lifecycle
    val profilesStack = rememberProductBackStack(ProductDestination.Profiles)
    val settingsStack = rememberProductBackStack(ProductDestination.Settings)
    val onboardingStack = rememberProductBackStack(ProductDestination.Welcome)
    var selectedName by rememberSaveable { mutableStateOf(ProductPrimary.HOME.savedId) }
    var navigationError by remember { mutableStateOf(false) }
    var onboardingCompleted by rememberSaveable { mutableStateOf(false) }
    androidx.compose.runtime.LaunchedEffect(state) {
        if (!onboardingCompleted && state in setOf(AppState.FirstLaunch, AppState.NoProfiles)) {
            selectedName = ProductPrimary.ONBOARDING.savedId
        }
        if (state is AppState.Ready) {
            onboardingCompleted = true
            resetToRoot(onboardingStack, ProductDestination.Welcome)
            if (selectedName == ProductPrimary.ONBOARDING.savedId) selectedName = ProductPrimary.HOME.savedId
        }
    }
    var showOperator by remember { mutableStateOf(false) }
    val selected = ProductPrimary.entries.firstOrNull { it.savedId == selectedName }
    val stacks = mapOf(ProductPrimary.HOME to homeStack, ProductPrimary.PROFILES to profilesStack,
        ProductPrimary.SETTINGS to settingsStack, ProductPrimary.ONBOARDING to onboardingStack)
    if (selected == null || stacks.values.any { stack -> stack.any { it !is ProductDestination } }) {
        ProductNavigationRecovery(onRestart = restart@ {
            if (!navigationLifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return@restart
            stacks.forEach { (primary, stack) -> resetToRoot(stack, primary.root) }
            selectedName = ProductPrimary.HOME.savedId
        })
        return
    }
    val backStack = stacks.getValue(selected)
    val navigate: (ProductDestination) -> Unit = navigate@ { destination ->
        if (!navigationLifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return@navigate
        onCancelProfileReview()
        if (pushDestination(stacks.getValue(destination.primary), destination))
            selectedName = destination.primary.savedId
        else navigationError = true
    }
    val currentState by rememberUpdatedState(state)
    val currentConnectionState by rememberUpdatedState(connectionState)
    val currentSettingsEditor by rememberUpdatedState(settingsEditor)
    val currentBackupState by rememberUpdatedState(backupState)
    val currentDiagnosticState by rememberUpdatedState(diagnosticState)
    val currentDiagnosticEvents by rememberUpdatedState(diagnosticEvents)
    val currentProtectedRecovery by rememberUpdatedState(protectedRecovery)
    val currentSettings by rememberUpdatedState(settings)
    val currentCompatibility by rememberUpdatedState(compatibility)
    val currentProbeState by rememberUpdatedState(probeState)
    val currentEnrollmentState by rememberUpdatedState(enrollmentState)
    val currentEnrollmentQr by rememberUpdatedState(enrollmentQr)
    val currentVpnRuntime by rememberUpdatedState(vpnRuntime)
    val qrAccumulator = remember { MultipartQrAccumulator() }
    var scanningQr by remember { mutableStateOf(false) }
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
    val navigatePrimary: (AppDestination) -> Unit = primary@ { destination ->
        if (!navigationLifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return@primary
        onCancelProfileReview()
        val target = when (destination) {
            AppDestination.HOME -> ProductPrimary.HOME
            AppDestination.PROFILES -> ProductPrimary.PROFILES
            AppDestination.SETTINGS -> ProductPrimary.SETTINGS
            else -> error("Not a primary destination")
        }
        resetToRoot(stacks.getValue(target), target.root)
        selectedName = target.savedId
    }
    val navigateBack: () -> Unit = back@ {
        if (!navigationLifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return@back
        onCancelProfileReview()
        when (backFrom(backStack, selected)) {
            NavigationBack.POPPED, NavigationBack.EXIT -> Unit
            NavigationBack.HOME -> {
                resetToRoot(homeStack, ProductDestination.Home)
                selectedName = ProductPrimary.HOME.savedId
            }
        }
    }
    BackHandler(enabled = handlesProductBack(backStack.size, selected), onBack = navigateBack)
    if (navigationError) androidx.compose.material3.AlertDialog(
        onDismissRequest = { navigationError = false },
        text = { Text(stringResource(R.string.navigation_history_full)) },
        confirmButton = { androidx.compose.material3.TextButton(onClick = { navigationError = false }) {
            Text(stringResource(android.R.string.ok))
        } },
    )
    if (showOperator) {
        OperatorProviderScreen(operatorProjection(currentState, currentSettings), onBack = { showOperator = false })
        BackHandler { showOperator = false }
        return
    }
    if (selected == ProductPrimary.ONBOARDING && backStack.lastOrNull() == ProductDestination.Welcome) {
        org.kurdistanvpn.core.ui.ProductStateContent(
            title = stringResource(R.string.route_title_1),
            message = stringResource(R.string.navigation_welcome),
            actionLabel = stringResource(R.string.route_title_2),
            onAction = { navigate(ProductDestination.ImportSource) },
            secondaryLabel = stringResource(R.string.navigation_continue),
            onSecondary = continueHome@ {
                if (!navigationLifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return@continueHome
                onboardingCompleted = true
                resetToRoot(onboardingStack, ProductDestination.Welcome)
                selectedName = ProductPrimary.HOME.savedId
            },
        )
        return
    }
    val provider: (NavKey) -> NavEntry<NavKey> = { rawKey ->
            require(rawKey is ProductDestination) { "Unsupported navigation key" }
            val key: ProductDestination = rawKey
            when (key) {
                ProductDestination.Home -> NavEntry(key) {
                    HomeScreen(
                        connectionState = currentConnectionState,
                        state = currentState,
                        settings = currentSettings,
                        vpnRuntime = currentVpnRuntime,
                        onStartVpn = onStartVpn,
                        onStopVpn = onStopVpn,
                        onSystemVpnSettings = onSystemVpnSettings,
                        onOpenProfiles = { navigate(ProductDestination.Profiles) },
                        onOpenSettings = { navigate(if (requiresStorageNavigationGate(currentState,
                            ProductDestination.Settings)) ProductDestination.RecoveryCenter else ProductDestination.Settings) },
                        onOpenDiagnostics = { navigate(ProductDestination.Diagnostics) },
                        onClearError = onClearError,
                    )
                }
                ProductDestination.Profiles, ProductDestination.ImportSource,
                is ProductDestination.ProfileDetail, is ProductDestination.TransferExport -> NavEntry(key) {
                    val detailId = when (key) {
                        is ProductDestination.ProfileDetail -> key.profileId
                        is ProductDestination.TransferExport -> key.profileId
                        else -> null
                    }
                    val profiles = (currentState as? AppState.Ready)?.profiles.orEmpty()
                    if (isMissingProfileDestination(key, profiles)) {
                        ProductRouteUnavailable(key, stale = true, onBack = navigateBack,
                            onRoot = { navigatePrimary(AppDestination.PROFILES) })
                    } else {

                    ProfilesScreen(
                        profiles = if (detailId == null) profiles else profiles.filter { it.localRecordId == detailId },
                        detailProfileId = detailId,
                        onOpenDetail = { navigate(ProductDestination.ProfileDetail(it)) },
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
                        onReviewProfile = onReviewProfile,
                        onToggleFavorite = onToggleFavorite,
                        onOpenOperator = { onCancelProfileReview(); showOperator = true },
                        onImportFile = onPickFile,
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
                            onRequestCamera { granted ->
                                scanningQr = granted
                                if (!granted) qrAccumulator.cancel()
                            }
                        },
                        onExportProfile = onExportProfile,
                        onDeleteProfile = onDeleteProfile,
                        onBack = navigateBack,
                        showBack = key != ProductDestination.Profiles,
                        connectionWillStopOnSelection = currentVpnRuntime.state.hasRuntimeSession(),
                    )
                }
                    }
                ProductDestination.Settings -> NavEntry(key) {
                    SettingsIndexScreen(
                        settings = currentSettings,
                        capabilities = capabilities,
                        onConnection = { navigate(ProductDestination.ConnectionPermissions) },
                        onTunnelDns = { navigate(ProductDestination.TunnelDns) },
                        onRouting = { navigate(ProductDestination.PerAppRouting) },
                        onUpdatesProbes = { navigate(ProductDestination.UpdatesProbes) },
                        onExpert = { navigate(ProductDestination.ExpertControls) },
                        onPrivacyRecovery = { navigate(ProductDestination.RecoveryCenter) },
                        onAppearance = { navigate(ProductDestination.AppearanceAccessibility) },
                        onDiagnostics = { navigate(ProductDestination.Diagnostics) },
                        onBack = navigateBack,
                        showBack = false,
                        proxyCredentials = {
                            ProxyRecoveryActions(
                                currentVpnRuntime.failure.takeIf {
                                    currentVpnRuntime.state == org.kurdistanvpn.runtime.api.VpnRuntimeState.DEGRADED
                                }, onRestartProxy, onApplyTunOnly)
                            androidx.compose.material3.TextButton(onClick = onProxyCredentials,
                                enabled = currentVpnRuntime.state == org.kurdistanvpn.runtime.api.VpnRuntimeState.ACTIVE_KURD_LIVE,
                                modifier = Modifier.testTag("settings_proxy_credentials")) {
                                Text(stringResource(R.string.proxy_credentials_title))
                            }
                        },
                    )
                }
                ProductDestination.ConnectionPermissions -> NavEntry(key) {
                    androidx.compose.runtime.LaunchedEffect(Unit) { if (currentSettingsEditor != null) onOpenSettingsDraft() }
                    ConnectionSettingsScreen(
                        value = currentSettings.connection,
                        onChange = { if (currentSettingsEditor != null) onApplySettingsDraft() else onConnection(it) },
                        draftValue = currentSettingsEditor?.requested?.connection,
                        onEdit = currentSettingsEditor?.let { { value -> onEditSettings((currentSettingsEditor?.requested ?: currentSettings).copy(connection = value)) } },
                        onCancelDraft = currentSettingsEditor?.let { onCancelSettingsDraft },
                        editorPhase = currentSettingsEditor?.phase,
                        onRecoverInternet = onRecoverInternet,
                        onBack = navigateBack,
                        paused = !currentSettings.pausePolicy.permitsAutoConnect,
                        canPause = vpnRuntime.alwaysOn == false && vpnRuntime.lockdown == false &&
                            vpnRuntime.state in setOf(org.kurdistanvpn.runtime.api.VpnRuntimeState.IDLE,
                                org.kurdistanvpn.runtime.api.VpnRuntimeState.ACTIVE_KURD_LIVE, org.kurdistanvpn.runtime.api.VpnRuntimeState.DEGRADED),
                        onPause = onPauseVpn,
                        onSystemVpnSettings = onSystemVpnSettings,
                    )
                }
                ProductDestination.TunnelDns -> NavEntry(key) {
                    androidx.compose.runtime.LaunchedEffect(Unit) { if (currentSettingsEditor != null) onOpenSettingsDraft() }
                    TunnelDnsSettingsScreen(
                        value = currentSettings.tunnel,
                        onChange = { if (currentSettingsEditor != null) onApplySettingsDraft() else onTunnel(it) },
                        draftValue = currentSettingsEditor?.requested?.tunnel,
                        onEdit = currentSettingsEditor?.let { { value -> onEditSettings((currentSettingsEditor?.requested ?: currentSettings).copy(tunnel = value)) } },
                        onCancelDraft = currentSettingsEditor?.let { onCancelSettingsDraft },
                        editorPhase = currentSettingsEditor?.phase,
                        onBack = navigateBack,
                    )
                }
                ProductDestination.PerAppRouting -> NavEntry(key) {
                    androidx.compose.runtime.LaunchedEffect(Unit) { if (currentSettingsEditor != null) onOpenSettingsDraft() }
                    RoutingSettingsScreen(
                        value = currentSettings.routing,
                        applications = installedApplications,
                        onChange = { if (currentSettingsEditor != null) onApplySettingsDraft() else onRouting(it) },
                        draftValue = currentSettingsEditor?.requested?.routing,
                        onEdit = currentSettingsEditor?.let { { value -> onEditSettings((currentSettingsEditor?.requested ?: currentSettings).copy(routing = value)) } },
                        onCancelDraft = currentSettingsEditor?.let { onCancelSettingsDraft },
                        editorPhase = currentSettingsEditor?.phase,
                        onBack = navigateBack,
                    )
                }
                ProductDestination.UpdatesProbes -> NavEntry(key) {
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
                ProductDestination.ExpertControls -> NavEntry(key) {
                    ExpertSettingsScreen(
                        expert = currentSettings.expert,
                        diagnostics = currentSettings.diagnostics,
                        onExpert = onExpert,
                        onDiagnostics = onDiagnosticsSettings,
                        onBack = navigateBack,
                    )
                }
                ProductDestination.RecoveryCenter -> NavEntry(key) {
                    val recoveryReason =
                        (currentProtectedRecovery as? ProtectedRecoveryPresentation.Required)?.reason
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
                        onReviewReset = onReviewReset,
                        onCancelReset = onCancelReset,
                        pendingCredentialResetLabel = stringResource(R.string.reset_scope_pending_credentials),
                        pendingCredentialResetHelp = stringResource(R.string.reset_pending_credentials_help),
                        migrationRequired = currentState is AppState.MigrationRequired,
                        migrationLabel = stringResource(R.string.prepare_protected_state_migration),
                        migrationHelp = stringResource(R.string.protected_state_migration_help),
                        migrationConfirmLabel = stringResource(R.string.confirm_protected_state_migration),
                        onConfirmMigration = onConfirmMigration,
                        protectedRecovery = currentProtectedRecovery,
                        recoveryTitle = recoveryReason?.let {
                            stringResource(R.string.protected_recovery_title)
                        },
                        recoveryMessage = recoveryReason?.let {
                            stringResource(
                                when (it) {
                                    ProtectedRecoveryReason.RECOVERY_REQUIRED ->
                                        R.string.protected_recovery_required
                                    ProtectedRecoveryReason.QUARANTINED ->
                                        R.string.protected_recovery_quarantined
                                    ProtectedRecoveryReason.INCONSISTENT ->
                                        R.string.protected_recovery_inconsistent
                                    ProtectedRecoveryReason.CLEANUP_UNPROVEN ->
                                        R.string.protected_recovery_cleanup_unproven
                                    ProtectedRecoveryReason.MUTATION_UNPROVEN ->
                                        R.string.protected_recovery_mutation_unproven
                                },
                            )
                        },
                        recoveryPrepareLabel = stringResource(R.string.prepare_presentation_recovery),
                        recoveryConfirmLabel = stringResource(R.string.confirm_presentation_recovery),
                        recoveryDiagnosticsLabel = stringResource(R.string.open_privacy_safe_diagnostics),
                        onConfirmPresentationRecovery = onConfirmPresentationRecovery,
                        onOpenDiagnostics = { navigate(ProductDestination.Diagnostics) },
                    )
                }
                ProductDestination.Diagnostics -> NavEntry(key) {
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
                ProductDestination.Welcome -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                is ProductDestination.FirstTrust -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = true, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.VpnPermissionEducation -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                is ProductDestination.RouteDetail -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                is ProductDestination.DeploymentDetail -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                is ProductDestination.StrategyMatrix -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = isMissingProfileDestination(key,
                        (currentState as? AppState.Ready)?.profiles.orEmpty()), onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                is ProductDestination.ProbeHistory -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = isMissingProfileDestination(key,
                        (currentState as? AppState.Ready)?.profiles.orEmpty()), onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.TrustedNetworks -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.ExcludedRoutes -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.LocalProxy -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.AppearanceAccessibility -> NavEntry(key) {
                    androidx.compose.runtime.LaunchedEffect(Unit) { onOpenSettingsDraft() }
                    org.kurdistanvpn.feature.settingsrecovery.AppearanceSettingsScreen(
                        currentSettings, currentSettingsEditor, onEditSettings, onApplySettingsDraft,
                        onCancelSettingsDraft, navigateBack)
                }
                ProductDestination.PrivacyAppLock -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.BackupCreation -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                is ProductDestination.RestorePreview -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = true, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.ScopedReset -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                is ProductDestination.DiagnosticExport -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = true, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.Troubleshooting -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.NotificationsPerformance -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.Automation -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.About -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
                ProductDestination.Legal -> NavEntry(key) {
                    ProductRouteUnavailable(key, stale = false, onBack = navigateBack,
                        onRoot = { navigatePrimary(when (key.primary) {
                            ProductPrimary.PROFILES -> AppDestination.PROFILES
                            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
                            else -> AppDestination.HOME
                        }) })
                }
            }
        }
    val companionState = rememberSaveableStateHolder()
    val reducedMotion = org.kurdistanvpn.core.ui.LocalReducedMotion.current
    val entryDecorator = rememberSaveableStateHolderNavEntryDecorator<NavKey>()
    val gated = requiresStorageNavigationGate(currentState, backStack.last() as ProductDestination)
    val hasCompanion = !gated && selected != ProductPrimary.ONBOARDING && backStack.lastOrNull() != selected.root
    ProductNavigationChrome(
        current = when (selected) {
            ProductPrimary.HOME, ProductPrimary.ONBOARDING -> AppDestination.HOME
            ProductPrimary.PROFILES -> AppDestination.PROFILES
            ProductPrimary.SETTINGS -> AppDestination.SETTINGS
        },
        onNavigate = navigatePrimary,
        fold = fold,
        companionContent = if (hasCompanion) ({
            companionState.SaveableStateProvider(selected.savedId) { provider(selected.root).Content() }
        }) else null,
    ) {
        if (gated) provider(ProductDestination.Home).Content() else NavDisplay(
            backStack = backStack,
            onBack = navigateBack,
            entryDecorators = listOf(entryDecorator),
            entryProvider = provider,
            transitionSpec = { productNavigationTransition(reducedMotion) },
            popTransitionSpec = { productNavigationTransition(reducedMotion) },
            predictivePopTransitionSpec = { productNavigationTransition(reducedMotion) },
        )
    }
}

@Composable
internal fun ProductNavigationChrome(
    current: AppDestination,
    onNavigate: (AppDestination) -> Unit,
    fold: ProductFold? = null,
    companionContent: (@Composable () -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    val primary = listOf(AppDestination.HOME, AppDestination.PROFILES, AppDestination.SETTINGS)
    val selectedRoot = when (current) {
        AppDestination.HOME -> AppDestination.HOME
        AppDestination.PROFILES, AppDestination.OPERATOR_PROVIDER -> AppDestination.PROFILES
        else -> AppDestination.SETTINGS
    }
    var contentOrigin by remember { mutableStateOf(Offset.Zero) }
    val paneDensity = LocalDensity.current
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    // This boundary owns and consumes safe insets for both navigation and child Scaffolds.
    BoxWithConstraints(
        Modifier.fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .onGloballyPositioned { contentOrigin = it.positionInWindow() },
        contentAlignment = androidx.compose.ui.AbsoluteAlignment.TopLeft,
    ) {
        val origin = with(paneDensity) { Offset(contentOrigin.x / density, contentOrigin.y / density) }
        val panes = adaptiveProductLayout(ProductRect(origin.x, origin.y,
            origin.x + maxWidth.value, origin.y + maxHeight.value), fold, rtl, companionContent != null)
        fun placement(rect: ProductRect) = Modifier.absoluteOffset(rect.left.dp, rect.top.dp)
            .size(rect.width.dp, rect.height.dp)
        val sorani = androidx.compose.ui.platform.LocalConfiguration.current.locales[0].language == "ckb"
        val labelStyle = if (sorani) MaterialTheme.typography.labelMedium.copy(
            fontFamily = MaterialTheme.typography.labelLarge.fontFamily,
        ) else MaterialTheme.typography.labelMedium
        val label: @Composable (AppDestination) -> Unit = { destination ->
            Text(
                primaryLabel(destination),
                style = labelStyle,
                fontWeight = if (sorani) FontWeight.Normal else if (destination == selectedRoot) FontWeight.SemiBold else FontWeight.Medium,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
            )
        }
        if (panes.mode == ProductLayoutMode.COMPACT) {
            val density = LocalDensity.current
            val measurer = rememberTextMeasurer()
            val minimumWidths = primary.map { destination ->
                maxOf(
                    with(density) { 64.dp.toPx() },
                    measurer.measure(primaryLabel(destination), style = labelStyle, softWrap = false).size.width +
                        with(density) { 8.dp.toPx() },
                )
            }
            // Keep equal Material items normally. At large Sorani text scales, use the
            // available row width to fit each whole label without shrinking its type.
            val availableWidth = with(density) { (panes.current.width.dp - 16.dp).toPx() }
            val balanceLabels = sorani && minimumWidths.any { it > availableWidth / primary.size } &&
                minimumWidths.sum() <= availableWidth
            Column(placement(panes.current)) {
                Box(Modifier.weight(1f).fillMaxWidth()) { content() }
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface,
                    tonalElevation = 0.dp,
                    windowInsets = WindowInsets(0, 0, 0, 0),
                    modifier = Modifier.testTag("primary_navigation_bar"),
                ) {
                    primary.forEachIndexed { index, destination ->
                        NavigationBarItem(
                            selected = selectedRoot == destination,
                            onClick = { onNavigate(destination) },
                            icon = { PrimaryNavigationIcon(destination) },
                            label = { label(destination) },
                            modifier = Modifier.weight(if (balanceLabels) minimumWidths[index] else 1f)
                                .heightIn(min = 72.dp)
                                .testTag("primary_${destination.name.lowercase()}"),
                        )
                    }
                }
            }
        } else {
            Box(Modifier.fillMaxSize(), contentAlignment = androidx.compose.ui.AbsoluteAlignment.TopLeft) {
                if (panes.rail != null) NavigationRail(
                    containerColor = MaterialTheme.colorScheme.surface,
                    windowInsets = WindowInsets(0, 0, 0, 0),
                    modifier = placement(requireNotNull(panes.rail))
                        .verticalScroll(rememberScrollState()).testTag("primary_navigation_rail"),
                ) {
                    primary.forEach { destination ->
                        NavigationRailItem(
                            selected = selectedRoot == destination,
                            onClick = { onNavigate(destination) },
                            icon = { PrimaryNavigationIcon(destination) },
                            label = { label(destination) },
                            modifier = Modifier.width(80.dp).heightIn(min = 72.dp)
                                .testTag("primary_${destination.name.lowercase()}"),
                        )
                    }
                }
                panes.companion?.let { rect ->
                    Box(placement(rect).testTag("navigation_companion")) { companionContent?.invoke() }
                }
                Box(placement(panes.current).testTag("navigation_current")) { content() }
            }
        }
    }
}

@Composable
private fun PrimaryNavigationIcon(destination: AppDestination) {
    val accents = org.kurdistanvpn.core.ui.LocalNavigationAccents.current
    Icon(
        primaryIcon(destination), contentDescription = null,
        tint = when (destination) {
            AppDestination.HOME -> accents.home
            AppDestination.SETTINGS -> accents.settings
            else -> MaterialTheme.colorScheme.onSurface
        },
    )
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
