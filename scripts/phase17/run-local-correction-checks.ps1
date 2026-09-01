param(
    [ValidateSet('VerifyWorkspace','FunctionsOnly','KotlinTests','KotlinBoundaryChecks','GradleChecks','Lockfiles')][string]$Mode = 'VerifyWorkspace',
    [string]$RepositoryRoot = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent),
    [string[]]$Sources = @(),
    [string[]]$TestClasses = @(),
    [ValidateSet('secure','metadata','model','native-api','runtime-api','settings','protected-state')][string[]]$BuiltModules = @(),
    [ValidatePattern('^[a-z0-9-]{1,64}$')][string]$OutputName = 'unit',
    [string[]]$Tasks = @(),
    [switch]$AndroidCompileClasspath,
    [switch]$DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Explicit host compilation/testing is opt-in. Packaging, devices and downloads are never admitted.
$script:HistoricalCorrectionBaseline = '8ef19dd57520c2930d12e81ed7769a6ec6cf3326'
$script:HistoricalCorrectionTree = '3a51879991388775abffa9e3df7984d624b63852'
$script:CorrectionBaseline = 'c84473e28249e1d165da23a4bc9be6d4d219784a'
$script:CorrectionTree = 'b29fac42992b04e072c727b79a33bcd904e5d9aa'
$script:CorrectionRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$script:CorrectionPaths = @'
M|android/settings.gradle.kts
M|android/app/build.gradle.kts
M|android/core/native-jni/src/main/cpp/CMakeLists.txt
M|android/core/native-jni/src/main/kotlin/org/kurdistanvpn/core/nativejni/NativeBridge.kt
N|android/data/protected-state/build.gradle.kts
N|android/data/protected-state/gradle.lockfile
N|android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/DurableFilePrimitives.kt
N|android/core/native-api/src/test/kotlin/org/kurdistanvpn/core/nativeapi/DurableFilePrimitivesTest.kt
N|android/core/native-jni/src/main/cpp/kvpn_durable_fs.h
N|android/core/native-jni/src/main/cpp/kvpn_durable_fs.c
N|android/core/native-jni/src/main/cpp/kvpn_durable_fs_jni.c
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateContracts.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateCompositionRoot.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateOperationJournal.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateMutationBroker.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateSnapshotReader.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateMigrationCoordinator.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateResetRecoveryCoordinator.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateAuthorityFactory.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStatePreviewBackupPolicy.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ActiveSessionMutationPolicy.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateJournalCodecTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateMutationBrokerTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateCrashMatrixTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateValidatorTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateMigrationCoordinatorTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateResetRecoveryCoordinatorTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateAuthorityFactoryTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStatePreviewBackupPolicyTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateStructuralBoundaryTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ActiveSessionMutationPolicyTest.kt
M|android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/AndroidKeystoreKek.kt
M|android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/BackupPayloadCodec.kt
M|android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/ClientKeyBundleStore.kt
M|android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/ProfileAdmissionJournal.kt
M|android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SecureBlobStore.kt
M|android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SecureEnvelope.kt
M|android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SecureRoutingPolicyStore.kt
M|android/data/secure/src/test/kotlin/org/kurdistanvpn/data/secure/ClientKeyBundleStoreTest.kt
M|android/data/secure/src/test/kotlin/org/kurdistanvpn/data/secure/SecureEnvelopeTest.kt
M|android/data/secure/src/test/kotlin/org/kurdistanvpn/data/secure/SecureRoutingPolicyStoreTest.kt
N|android/data/secure/src/test/kotlin/org/kurdistanvpn/data/secure/SecureBlobStoreDurabilityTest.kt
N|android/data/secure/src/test/kotlin/org/kurdistanvpn/data/secure/BackupPayloadCodecV2Test.kt
M|android/data/metadata/src/main/kotlin/org/kurdistanvpn/data/metadata/ProfileCatalog.kt
M|android/data/metadata/src/test/kotlin/org/kurdistanvpn/data/metadata/MetadataBoundaryTest.kt
M|android/data/settings/src/main/kotlin/org/kurdistanvpn/data/settings/Phase9SettingsStore.kt
M|android/data/settings/src/test/kotlin/org/kurdistanvpn/data/settings/Phase13SettingsCodecTest.kt
M|android/core/model/src/main/kotlin/org/kurdistanvpn/core/model/AppState.kt
M|android/core/model/src/main/kotlin/org/kurdistanvpn/core/model/ProductSettings.kt
M|android/core/model/src/test/kotlin/org/kurdistanvpn/core/model/ProductSettingsTest.kt
M|internal/androidbridge/backup.go
M|internal/androidbridge/backup_test.go
M|internal/product/backup/backup.go
M|internal/product/backup/backup_test.go
N|android/data/metadata/schemas/org.kurdistanvpn.data.metadata.KurdistanMetadataDatabase/2.json
N|android/data/metadata/src/test/kotlin/org/kurdistanvpn/data/metadata/ProfileCatalogMigrationTest.kt
M|android/app/src/main/kotlin/org/kurdistanvpn/app/KurdistanApplication.kt
M|android/app/src/main/kotlin/org/kurdistanvpn/app/Phase9CompositionRoot.kt
M|android/app/src/main/kotlin/org/kurdistanvpn/app/Phase9ExportWire.kt
M|android/app/src/main/kotlin/org/kurdistanvpn/app/Phase9ViewModel.kt
M|android/app/src/main/kotlin/org/kurdistanvpn/app/VpnNetworkTeardownBarrier.kt
M|android/app/src/main/kotlin/org/kurdistanvpn/app/VpnRuntimeController.kt
D|android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeReconnectCoordinator.kt
D|android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeReconnectPolicy.kt
N|android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueService.kt
N|android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueAdmission.kt
N|android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueIpcAdapter.kt
M|android/app/src/main/AndroidManifest.xml
M|android/app/src/main/res/values/strings.xml
M|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/SettingsRecoveryScreen.kt
M|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ProductSettingsScreens.kt
M|android/app/src/test/kotlin/org/kurdistanvpn/app/Phase9ExportWireTest.kt
M|android/app/src/test/kotlin/org/kurdistanvpn/app/VpnNetworkTeardownBarrierTest.kt
D|android/app/src/test/kotlin/org/kurdistanvpn/app/RuntimeReconnectCoordinatorTest.kt
D|android/app/src/test/kotlin/org/kurdistanvpn/app/Phase17RuntimeReconnectPolicyTest.kt
N|android/app/src/test/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueServiceTest.kt
N|android/app/src/test/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueAdmissionTest.kt
N|android/app/src/test/kotlin/org/kurdistanvpn/app/VpnRuntimeControllerTest.kt
N|android/app/src/test/kotlin/org/kurdistanvpn/app/PreviewPurityIntegrationTest.kt
M|android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/LiveRuntimeModels.kt
M|android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStartWire.kt
M|android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStatus.kt
N|android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeAuthorityReissueContract.kt
N|android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeAuthorityPurpose.kt
N|android/runtime/api/src/test/kotlin/org/kurdistanvpn/runtime/api/RuntimeAuthorityReissueContractTest.kt
N|android/runtime/api/src/test/kotlin/org/kurdistanvpn/runtime/api/RuntimeStartWireTest.kt
N|android/runtime/api/src/test/kotlin/org/kurdistanvpn/runtime/api/RuntimeStatusTest.kt
M|android/runtime/android/src/main/AndroidManifest.xml
M|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt
M|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/NativeTunnelController.kt
M|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/PendingRuntimeTermination.kt
M|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityTimeoutPolicy.kt
M|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/UnderlyingNetworkMonitor.kt
D|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityHandoffService.kt
N|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeStartCoordinator.kt
N|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeServiceCommand.kt
N|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityFrameCodec.kt
N|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityReissueClient.kt
N|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeActivationGuard.kt
N|android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeRevisionLeaseClient.kt
M|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/NativeTunnelControllerTest.kt
M|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/PendingRuntimeTerminationTest.kt
M|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityTimeoutPolicyTest.kt
M|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/UnderlyingNetworkMonitorTest.kt
M|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/VpnRuntimeContractTest.kt
N|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/RuntimeStartCoordinatorTest.kt
N|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityFrameCodecTest.kt
N|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityReissueClientTest.kt
N|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/RuntimeActivationGuardTest.kt
N|android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/RuntimeRevisionLeaseClientTest.kt
M|android/config/phase17-required-device-tests.txt
M|android/app/src/androidTest/AndroidManifest.xml
M|android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17FieldHarness.kt
M|android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17LiveDataPlaneDeviceTest.kt
N|android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17CanonicalDeviceEvidenceHarness.kt
N|android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17BootQualificationDeviceTest.kt
N|android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17ProtectedStateIntegrityDeviceTest.kt
N|config/phase17-acceptance-registry-v2.json
N|testdata/schemas/phase17-acceptance-registry-v2.schema.json
N|testdata/schemas/phase17-device-evidence-v1.schema.json
N|testdata/schemas/phase17-device-verifier-result-v1.schema.json
N|internal/phase17qualification/acceptance_registry.go
N|internal/phase17qualification/acceptance_registry_test.go
N|internal/phase17qualification/device_evidence.go
N|internal/phase17qualification/device_evidence_test.go
N|internal/phase17qualification/device_verifier.go
N|internal/phase17qualification/device_verifier_test.go
M|internal/phase17qualification/canonical.go
M|internal/phase17qualification/canonical_test.go
M|internal/phase17qualification/ledger.go
M|internal/phase17qualification/ledger_test.go
M|internal/phase17qualification/policy.go
M|internal/phase17qualification/policy_test.go
M|internal/phase17qualification/readiness.go
M|internal/phase17qualification/readiness_test.go
M|internal/phase17qualification/receipt.go
M|internal/phase17qualification/receipt_test.go
M|internal/phase17qualification/schema_test.go
M|cmd/phase17devicegate/main.go
M|cmd/phase17devicegate/main_test.go
M|cmd/phase17verify/inventory.go
M|cmd/phase17verify/inventory_test.go
M|cmd/phase17verify/qualification.go
M|cmd/phase17verify/qualification_test.go
N|cmd/phase17verify/native_durable_fs_linux_test.go
M|scripts/phase17/build-qualification-candidate.ps1
M|scripts/phase17/run-qualified-campaign.ps1
M|scripts/phase17/sanitize-field-evidence.ps1
M|scripts/phase17/owned-vps-scripts.Tests.ps1
M|android/build.gradle.kts
M|android/core/native-jni/build.gradle.kts
M|android/app/gradle.lockfile
M|android/app/src/main/kotlin/org/kurdistanvpn/app/MainActivity.kt
M|android/app/src/main/kotlin/org/kurdistanvpn/app/Phase13Coordinators.kt
M|android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase9FoundationUiTest.kt
M|android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/EncryptedDiagnosticEventStore.kt
M|android/data/secure/src/test/kotlin/org/kurdistanvpn/data/secure/EncryptedDiagnosticEventStoreTest.kt
M|android/data/secure/src/test/kotlin/org/kurdistanvpn/data/secure/ProtectedStateBoundaryTest.kt
D|android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SensitiveActionAuthorizer.kt
N|android/app/src/main/kotlin/org/kurdistanvpn/app/SensitiveActionAuthorizer.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateJournalLifecycle.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateJournalLifecycleTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateJournalCompactionTest.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateJournalRecoveryTest.kt
N|android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateProjectionWitness.kt
N|android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateProjectionWitnessTest.kt
N|scripts/phase17/run-local-correction-checks.ps1
N|scripts/phase17/local-correction-checks.Tests.ps1
M|cmd/phase17verify/artifact.go
M|cmd/phase17verify/artifact_test.go
M|internal/androidartifact/inspect.go
M|internal/androidartifact/inspect_test.go
M|android/settings-gradle.lockfile
M|android/core/native-api/build.gradle.kts
M|android/core/native-api/gradle.lockfile
M|internal/androidbridge/runtime_session_v2.go
M|internal/androidbridge/runtime_session_v2_test.go
M|internal/androidbridge/handles.go
M|internal/androidbridge/abi_test.go
M|cmd/kandroidbridge/phase17_release_unix.go
M|cmd/kandroidbridge/environment_internal.go
M|cmd/kandroidbridge/environment_internal_test.go
M|cmd/kandroidbridge/environment_selfhost.go
M|cmd/kandroidbridge/environment_selfhost_test.go
M|android/runtime/android/src/debug/kotlin/org/kurdistanvpn/runtime/android/LiveTunnelInvariantProbe.kt
M|android/app/src/androidTest/kotlin/org/kurdistanvpn/app/ProtectedStateResetDeviceTest.kt
M|internal/testkit/evidenceoverlay/successor.go
M|internal/testkit/evidenceoverlay/successor_test.go
M|internal/audit/security.go
M|internal/testkit/importrules/importrules_test.go
M|internal/phase17evidence/evidence.go
M|cmd/phase9verify/phase11_overlay_test.go
M|internal/audit/codegen_test.go
M|internal/audit/security_test.go
M|internal/runtime/policy_enforcement_test.go
M|internal/selfhost/backup.go
M|internal/selfhost/private_path_windows.go
N|internal/selfhost/restore_acl_windows_test.go
M|cmd/kurdctl/localpath_windows.go
M|cmd/kurdctl/main_test.go
M|cmd/kurdctl/localpath_windows_test.go
M|.github/workflows/ci.yml
M|android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase11ControlSurfaceDeviceTest.kt
N|android/app/src/androidTest/kotlin/org/kurdistanvpn/app/ProtectedStateStartupDeviceTest.kt
N|android/app/src/test/kotlin/org/kurdistanvpn/app/FirstUseStartupTest.kt
M|cmd/phase9devicegate/main.go
M|cmd/phase9devicegate/main_test.go
N|cmd/phase9devicegate/startup_observer.go
N|cmd/phase9devicegate/startup_observer_test.go
M|cmd/assure/main_test.go
M|cmd/phase17qual/main_test.go
'@
function Get-LocalCorrectionWhitelist {
    foreach ($line in ($script:CorrectionPaths -split "\r?\n")) {
        $parts = $line.Split('|', 2)
        [pscustomobject]@{ Kind=$parts[0]; Path=$parts[1] }
    }
}
function Assert-LocalCorrectionPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('\') -or
        $Path.StartsWith('/') -or $Path.Contains(':') -or
        @($Path.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0) {
        throw 'Noncanonical or escaping correction path'
    }
    if (@(Get-LocalCorrectionWhitelist | Where-Object { $_.Path -ceq $Path }).Count -ne 1) {
        throw 'Path is outside the owner-approved whitelist'
    }
}
function Assert-LocalCorrectionTaskGraph([object[]]$Tasks) {
    $allowedExec = @(
        ':core:native-jni:buildDebugArm64v8aGoBridge',
        ':core:native-jni:buildDebugX8664GoBridge',
        ':core:native-jni:buildInternalArm64v8aGoBridge',
        ':core:native-jni:buildInternalX8664GoBridge'
    )
    $lintModules = @(':app', ':core:model', ':core:ui', ':domain', ':core:native-api', ':core:native-jni',
        ':data:metadata', ':data:secure', ':data:settings', ':data:protected-state', ':platform:import',
        ':runtime:api', ':runtime:android', ':feature:home', ':feature:profiles',
        ':feature:settings-recovery', ':feature:diagnostics-about', ':test:fixtures')
    foreach ($task in $Tasks) {
        # AGP 9.2.1's exact task only copies an optional local lint JAR. It does
        # not publish remotely. Its class, project, sole output and empty
        # command are all required; a name-only exception would be unsafe.
        $lintPreparation = $task.Type -ceq 'com.android.build.gradle.internal.tasks.PrepareLintJarForPublish_Decorated' -and
            @($lintModules | Where-Object { $task.Path -ceq ($_ + ':prepareLintJarForPublish') }).Count -eq 1 -and
            @($task.Outputs).Count -eq 1 -and [string]$task.Outputs[0] -cmatch '/lint\.jar$' -and
            @($task.Command).Count -eq 0
        $lintAarLabel = if ($task.Path -cmatch ':bundle(Debug|Internal)LocalLintAar$') { $Matches[1] } else { '' }
        $lintAarVariant = $lintAarLabel.ToLowerInvariant()
        $localLintAar = $task.Type -ceq 'com.android.build.gradle.tasks.BundleAar_Decorated' -and
            $lintAarVariant -in @('debug','internal') -and
            @($lintModules | Where-Object { $task.Path -ceq ($_ + ':bundle' + $lintAarLabel + 'LocalLintAar') }).Count -eq 1 -and
            @($task.Outputs).Count -eq 1 -and [string]$task.Outputs[0] -cmatch ('/local_aar_for_lint/' + $lintAarVariant + '/out\.aar$') -and
            @($task.Command).Count -eq 0
        foreach ($name in (@($task.Path) + @($task.Finalizers))) {
            $classJar = $name -cin @(':app:bundleInternalClassesToCompileJar', ':app:bundleInternalClassesToRuntimeJar')
            $localLint = ($lintPreparation -or $localLintAar) -and $name -ceq $task.Path
            if (-not $classJar -and -not $localLint -and $name -match '(?i)(assemble|bundle(?!Lib(Compile|Runtime)To(Jar|Dir))|package.*(Internal|Debug|Release)$|install|uninstall|connected|devicegate|phase17gate|campaign|stress|soak|publish|upload|deploy|sign.*(apk|bundle|release))') {
                throw 'Prohibited task or finalizer'
            }
        }
        foreach ($output in $task.Outputs) {
            if ([string]$output -match '(?i)\.(apk|aab|apks|keystore|jks)$' -or
                [string]$output -match '(^|[/\\])\.\.([/\\]|$)' -or
                [IO.Path]::IsPathRooted([string]$output)) { throw 'Prohibited task output' }
        }
        if ($task.Type -match '(?i)(Exec|JavaExec)' -and $task.Path -notin $allowedExec) { throw 'Unaudited executable task' }
        if (@($task.Command).Count -gt 0) {
            if ($task.Path -notin $allowedExec -or $task.Command[0] -cne 'go' -or
                @($task.Command).Count -lt 3 -or $task.Command[1] -cne 'build' -or
                $task.Command[-1] -cne './cmd/kandroidbridge') { throw 'Unaudited external command' }
            if (@($task.Command | Where-Object { $_ -match '(?i)(https?://|download|install|toolchain@)' }).Count -ne 0) { throw 'External resolution rejected' }
        }
    }
}
function Get-LocalCorrectionLockOutputs {
    @('android/settings-gradle.lockfile','android/app/gradle.lockfile',
        'android/core/native-api/gradle.lockfile','android/data/protected-state/gradle.lockfile')
}
function Assert-LocalCorrectionLockOutput([string]$Path) {
    Assert-LocalCorrectionPath $Path
    if ($Path -cnotin @(Get-LocalCorrectionLockOutputs)) { throw 'Unapproved lock output' }
}
function Assert-LocalCorrectionDependencySelection([string[]]$Existing, [string[]]$Selected) {
    foreach ($module in $Selected) {
        if ($module -cnotmatch '^[^:\s]+:[^:\s]+:[^:\s]+$' -or $module -cnotin $Existing) {
            throw ('Unapproved dependency identity: ' + $module)
        }
    }
}
function Get-LocalCorrectionLockSnapshot {
    $paths = @(& git -C $script:CorrectionRoot ls-files --cached --others --exclude-standard -- 'android/*lockfile')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inventory tracked locks' }
    $paths += @(Get-LocalCorrectionLockOutputs)
    $snapshot = @{}
    foreach ($path in @($paths | Sort-Object -Unique)) {
        $file = Join-Path $script:CorrectionRoot $path
        if (Test-Path -LiteralPath $file) {
            if (((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Reparse lock output rejected'
            }
            $snapshot[$path] = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        } else { $snapshot[$path] = $null }
    }
    return $snapshot
}
function Assert-LocalCorrectionLockChanges([hashtable]$Before, [hashtable]$After, [bool]$AllowLockWrite) {
    foreach ($path in @(($Before.Keys + $After.Keys) | Sort-Object -Unique)) {
        if ($Before[$path] -cne $After[$path]) {
            if (-not $AllowLockWrite) { throw 'Lock changed outside authorized lock operation' }
            Assert-LocalCorrectionLockOutput $path
        }
    }
}
function Assert-LocalOfflineEnvironment([hashtable]$Values) {
    $prefix = $script:CorrectionRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    foreach ($name in @('GRADLE_USER_HOME','GOCACHE','GOMODCACHE','GOTMPDIR','TEMP','TMP','KOTLIN_DAEMON_RUN_FILES_PATH')) {
        if (-not $Values.ContainsKey($name) -or [string]::IsNullOrWhiteSpace($Values[$name])) { throw 'Missing confined writable environment' }
        $path = [IO.Path]::GetFullPath([string]$Values[$name])
        if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Writable cache escapes worktree' }
    }
    if ($Values['GOPROXY'] -cne 'off' -or $Values['GOTOOLCHAIN'] -cne 'local') { throw 'Go network/toolchain resolution is not disabled' }
}
function Assert-ExpectedCompilerDenial([int]$ExitCode, [object[]]$Diagnostics, [string]$Name) {
    $text = $Diagnostics -join "`n"
    if ($ExitCode -eq 0 -or
        $text -notmatch 'Cannot access|cannot access|invisible|private|internal' -or
        $text -match 'Unresolved reference|unresolved reference|ClassNotFoundException|NoClassDefFoundError') {
        throw ('External-module denial was not proven: ' + $Name)
    }
    # The nonzero compiler result is the expected assertion for this negative fixture. Do not
    # leak it as the terminal status of a completely successful validation script.
    $global:LASTEXITCODE = 0
}
function Assert-LocalCorrectionWorkspace {
    $env:GIT_OPTIONAL_LOCKS = '0'
    $head = & git -C $script:CorrectionRoot rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($head)) { throw 'Cannot resolve current HEAD' }
    $baselineType = & git -C $script:CorrectionRoot cat-file -t $script:CorrectionBaseline
    if ($LASTEXITCODE -ne 0 -or $baselineType -cne 'commit') { throw 'Missing immutable baseline commit' }
    $tree = & git -C $script:CorrectionRoot rev-parse ($script:CorrectionBaseline + '^{tree}')
    if ($LASTEXITCODE -ne 0 -or $tree -cne $script:CorrectionTree) { throw 'Wrong immutable tree' }
    & git -C $script:CorrectionRoot merge-base --is-ancestor $script:CorrectionBaseline $head
    if ($LASTEXITCODE -ne 0) { throw 'Current HEAD does not descend from the immutable baseline' }
    $merges = @(& git -C $script:CorrectionRoot rev-list --merges ($script:CorrectionBaseline + '..' + $head))
    if ($LASTEXITCODE -ne 0 -or $merges.Count -ne 0) { throw 'Merge commits are not admitted in the correction branch' }
    $index = @(& git -C $script:CorrectionRoot diff --cached --name-only)
    if ($LASTEXITCODE -ne 0 -or $index.Count -ne 0) { throw 'Staging is not authorized' }
    $tracked = @(& git -C $script:CorrectionRoot ls-tree -r --name-only $script:CorrectionBaseline)
    foreach ($entry in Get-LocalCorrectionWhitelist) {
        Assert-LocalCorrectionPath $entry.Path
        if (($entry.Kind -eq 'N') -eq ($entry.Path -cin $tracked)) { throw 'Whitelist kind does not match baseline' }
    }
    $committedPaths = @(& git -C $script:CorrectionRoot log --format= --name-only ($script:CorrectionBaseline + '..' + $head) --)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect committed correction history' }
    foreach ($path in @($committedPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)) {
        Assert-LocalCorrectionPath $path
    }
    $changes = @(& git -C $script:CorrectionRoot -c core.fsmonitor=false -c core.quotepath=true diff --name-status --no-renames $script:CorrectionBaseline --)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect correction delta' }
    $changedPaths = [Collections.Generic.List[string]]::new()
    foreach ($change in $changes) {
        $parts = @($change -split "`t", 2)
        if ($parts.Count -ne 2 -or $parts[0] -cnotin @('A','M','D')) { throw 'Unexpected correction delta state' }
        $path = $parts[1]
        Assert-LocalCorrectionPath $path
        $entry = @(Get-LocalCorrectionWhitelist | Where-Object { $_.Path -ceq $path })[0]
        $wantKind = switch ($parts[0]) { 'A' {'N'}; 'M' {'M'}; 'D' {'D'} }
        if ($entry.Kind -cne $wantKind) { throw 'Correction delta does not match whitelist disposition' }
        $changedPaths.Add($path) | Out-Null
    }
    $untracked = @(& git -C $script:CorrectionRoot ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect untracked correction files' }
    foreach ($path in $untracked) {
        if ($path.StartsWith('.gradle-user-home/', [StringComparison]::Ordinal)) { continue }
        Assert-LocalCorrectionPath $path
        $entry = @(Get-LocalCorrectionWhitelist | Where-Object { $_.Path -ceq $path })[0]
        if ($entry.Kind -cne 'N') { throw 'Untracked correction path is not an approved addition' }
        $changedPaths.Add($path) | Out-Null
    }
    $trackedLocalGradle = @(& git -C $script:CorrectionRoot ls-files -- '.gradle-user-home/*')
    if ($LASTEXITCODE -ne 0 -or $trackedLocalGradle.Count -ne 0) { throw 'Local Gradle user home must remain untracked' }
    if ($changedPaths.Count -ne @($changedPaths | Sort-Object -Unique).Count) { throw 'Duplicate correction path accounting' }
    Write-Output ('PASS: immutable baseline/tree ancestor, linear correction history, 211-path whitelist, zero staged paths; changed paths=' + $changedPaths.Count)
}
function Resolve-VerifiedLocalJar([string]$Group, [string]$Artifact, [string]$Version) {
    $cache = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.gradle/caches/modules-2/files-2.1'
    $base = Join-Path $cache ($Group + '/' + $Artifact + '/' + $Version)
    if (-not (Test-Path -LiteralPath $base)) { throw ('Missing offline artifact: ' + $Group + ':' + $Artifact + ':' + $Version) }
    $name = $Artifact + '-' + $Version + '.jar'
    $files = @(Get-ChildItem -LiteralPath $base -Recurse -File -Filter $name)
    if ($files.Count -ne 1) { throw ('Missing or ambiguous offline artifact: ' + $name) }
    $file = $files[0]
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse artifact rejected' }
    $metadata = [xml](Get-Content -LiteralPath (Join-Path $script:CorrectionRoot 'android/gradle/verification-metadata.xml') -Raw)
    $component = @($metadata.'verification-metadata'.components.component | Where-Object {
        $_.group -ceq $Group -and $_.name -ceq $Artifact -and $_.version -ceq $Version
    })
    $artifactEntry = @($component.artifact | Where-Object { $_.name -ceq $name })
    $expected = @($artifactEntry.sha256 | ForEach-Object { $_.value })
    $actual = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cnotin $expected) { throw ('Unverified offline artifact: ' + $name) }
    return $file.FullName
}
function Invoke-LocalKotlinTests {
    Assert-LocalCorrectionWorkspace
    if ($Sources.Count -eq 0 -or $TestClasses.Count -eq 0) { throw 'Explicit source and test lists required' }
    $resolvedSources = foreach ($source in $Sources) {
        if ($source -match '(^|/)\.\.(/|$)|[:\\]' -or $source.StartsWith('/') -or
            $source -notmatch '\.kt$' -or $source -match '/androidTest/') { throw 'Invalid host source input' }
        $file = Get-Item -LiteralPath (Join-Path $script:CorrectionRoot $source)
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse source rejected' }
        $file.FullName
    }
    foreach ($test in $TestClasses) { if ($test -cnotmatch '^[A-Za-z][A-Za-z0-9_.]+$') { throw 'Invalid test class' } }
    $java = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Android/Android Studio/jbr/bin/java.exe'
    if ((Get-AuthenticodeSignature -LiteralPath $java).Status -ne 'Valid') { throw 'Unverified local JVM' }
    $compiler = @(
        Resolve-VerifiedLocalJar 'org.jetbrains.kotlin' 'kotlin-compiler-embeddable' '2.3.10'
        Resolve-VerifiedLocalJar 'org.jetbrains.kotlin' 'kotlin-stdlib' '2.3.10'
        Resolve-VerifiedLocalJar 'org.jetbrains.kotlin' 'kotlin-script-runtime' '2.3.10'
        Resolve-VerifiedLocalJar 'org.jetbrains.kotlin' 'kotlin-reflect' '1.6.10'
        Resolve-VerifiedLocalJar 'org.jetbrains.kotlin' 'kotlin-daemon-embeddable' '2.3.10'
        Resolve-VerifiedLocalJar 'org.jetbrains.kotlinx' 'kotlinx-coroutines-core-jvm' '1.8.0'
        Resolve-VerifiedLocalJar 'org.jetbrains' 'annotations' '23.0.0'
    )
    $libraries = @(
        Resolve-VerifiedLocalJar 'org.jetbrains.kotlin' 'kotlin-stdlib' '2.3.10'
        Resolve-VerifiedLocalJar 'org.jetbrains.kotlinx' 'kotlinx-coroutines-core-jvm' '1.10.2'
        Resolve-VerifiedLocalJar 'junit' 'junit' '4.13.2'
        Resolve-VerifiedLocalJar 'org.hamcrest' 'hamcrest-core' '1.3'
        Resolve-VerifiedLocalJar 'org.jetbrains' 'annotations' '23.0.0'
    )
    foreach ($module in $BuiltModules) {
        $modulePath = switch ($module) {
            'model' {'core/model'}; 'native-api' {'core/native-api'}
            'runtime-api' {'runtime/api'}; default {'data/' + $module}
        }
        $jar = Get-Item -LiteralPath (Join-Path $script:CorrectionRoot (
            'android/' + $modulePath + '/build/intermediates/runtime_library_classes_jar/debug/bundleLibRuntimeToJarDebug/classes.jar'))
        if (($jar.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse built module rejected' }
        $libraries += $jar.FullName
    }
    $out = Join-Path $script:CorrectionRoot ('.tools/local-correction/' + $OutputName)
    $temp = Join-Path $out 'tmp'
    $testHome = Join-Path $out 'home'
    $classes = Join-Path $out 'classes'
    foreach ($directory in @($temp, $testHome, $classes)) {
        if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory | Out-Null }
        if (((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse output rejected' }
    }
    if ($AndroidCompileClasspath) {
        # Compile-time stubs only. This fingerprint preserves the already installed SDK
        # used by the authorized local checks; it is not claimed as an upstream signature.
        $sdk = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Android/Sdk/platforms/android-36/android.jar'
        if (-not (Test-Path -LiteralPath $sdk) -or
            ((Get-Item -LiteralPath $sdk).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-FileHash -LiteralPath $sdk -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                'd9eb9da824d9e247a352f570f01e1169e725b2954bca9e283a71786c59b59f9a') {
            throw 'Missing or changed installed Android 36 compile stubs; no acquisition permitted'
        }
        $libraries += $sdk
        $libraries += Resolve-VerifiedLocalJar 'androidx.room' 'room-common-jvm' '2.8.4'
        $libraries += Resolve-VerifiedLocalJar 'androidx.annotation' 'annotation-jvm' '1.9.1'
        $libraries += Resolve-VerifiedLocalJar 'androidx.datastore' 'datastore-preferences-proto' '1.2.1'
        $libraries += Resolve-VerifiedLocalJar 'androidx.datastore' 'datastore-preferences-external-protobuf' '1.2.1'
        foreach ($spec in @(
            @('androidx.room','room-runtime-android','2.8.4','room-runtime.aar'),
            @('androidx.sqlite','sqlite-android','2.6.2','sqlite.aar'),
            @('androidx.sqlite','sqlite-framework-android','2.6.2','sqlite-framework.aar'),
            @('androidx.datastore','datastore-core-android','1.2.1','datastore-core.aar')
        )) {
            $base = Join-Path ([Environment]::GetFolderPath('UserProfile')) ('.gradle/caches/modules-2/files-2.1/' + ($spec[0..2] -join '/'))
            if (-not (Test-Path -LiteralPath $base)) { throw ('Missing offline artifact: ' + ($spec -join ':')) }
            $found = @(Get-ChildItem -LiteralPath $base -Recurse -File -Filter $spec[3])
            if ($found.Count -ne 1 -or ($found[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('Missing, ambiguous or reparse offline artifact: ' + ($spec -join ':'))
            }
            $metadata = [xml](Get-Content -LiteralPath (Join-Path $script:CorrectionRoot 'android/gradle/verification-metadata.xml') -Raw)
            $component = @($metadata.'verification-metadata'.components.component | Where-Object {
                $_.group -ceq $spec[0] -and $_.name -ceq $spec[1] -and $_.version -ceq $spec[2]
            })
            $expected = @($component.artifact | Where-Object { $_.name -ceq $spec[3] } | ForEach-Object { $_.sha256.value })
            if ((Get-FileHash -LiteralPath $found[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cnotin $expected) {
                throw ('Unverified offline artifact: ' + ($spec -join ':'))
            }
            $zip = [IO.Compression.ZipFile]::OpenRead($found[0].FullName)
            try {
                $entry = $zip.GetEntry('classes.jar')
                if ($null -eq $entry -or $entry.Length -le 0 -or $entry.Length -gt 16777216) { throw 'Invalid AAR class entry' }
                $destination = Join-Path $out ('verified-' + $spec[1] + '-classes.jar')
                $input = $entry.Open()
                try {
                    $output = [IO.File]::Open($destination, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
                    try { $input.CopyTo($output) } finally { $output.Dispose() }
                } finally { $input.Dispose() }
                $libraries += $destination
            } finally { $zip.Dispose() }
        }
    }
    if ($BuiltModules -contains 'settings') {
        # This is an existing verified Android library, not dependency resolution. Extract only
        # its JVM classes to the confined test output so canonical preference codecs can run.
        $artifactName = 'datastore-preferences-core.aar'
        $base = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.gradle/caches/modules-2/files-2.1/androidx.datastore/datastore-preferences-core-android/1.2.1'
        $artifacts = @(Get-ChildItem -LiteralPath $base -Recurse -File -Filter $artifactName)
        if ($artifacts.Count -ne 1) { throw 'Missing offline datastore-preferences-core-android:1.2.1 AAR' }
        $artifact = $artifacts[0]
        if (($artifact.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse dependency rejected' }
        $metadata = [xml](Get-Content -LiteralPath (Join-Path $script:CorrectionRoot 'android/gradle/verification-metadata.xml') -Raw)
        $component = @($metadata.'verification-metadata'.components.component | Where-Object {
            $_.group -ceq 'androidx.datastore' -and $_.name -ceq 'datastore-preferences-core-android' -and $_.version -ceq '1.2.1'
        })
        $expected = @($component.artifact | Where-Object { $_.name -ceq $artifactName } | ForEach-Object { $_.sha256.value })
        if ((Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cnotin $expected) {
            throw 'Unverified offline preference classes'
        }
        $zip = [IO.Compression.ZipFile]::OpenRead($artifact.FullName)
        try {
            $entry = $zip.GetEntry('classes.jar')
            if ($null -eq $entry -or $entry.Length -le 0 -or $entry.Length -gt 16777216) { throw 'Invalid AAR class entry' }
            $destination = Join-Path $out 'verified-preferences-classes.jar'
            $input = $entry.Open()
            try {
                $output = [IO.File]::Open($destination, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try { $input.CopyTo($output) } finally { $output.Dispose() }
            } finally { $input.Dispose() }
            $libraries += $destination
        } finally { $zip.Dispose() }
    }
    $savedTemp = $env:TEMP
    $savedTmp = $env:TMP
    try {
        $env:TEMP = $temp
        $env:TMP = $temp
        $vm = @(('-Duser.home=' + $testHome), ('-Djava.io.tmpdir=' + $temp), ('-Dkurdistan.test.sourceRoot=' + $script:CorrectionRoot), '-XX:-UsePerfData')
        $compilerArguments = @('-cp', ($compiler -join [IO.Path]::PathSeparator),
            'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
            '-jvm-target', '17', '-classpath', ($libraries -join [IO.Path]::PathSeparator), '-d', $classes) + @($resolvedSources)
        & $java @vm @compilerArguments
        if ($LASTEXITCODE -ne 0) { throw 'Local Kotlin compilation failed; no tests executed' }
        $testArguments = @('-cp', ((@($classes) + $libraries) -join [IO.Path]::PathSeparator), 'org.junit.runner.JUnitCore') + $TestClasses
        & $java @vm @testArguments
        if ($LASTEXITCODE -ne 0) { throw 'Local Kotlin regression failure' }
        if ($Mode -eq 'KotlinBoundaryChecks') {
            if ($BuiltModules -notcontains 'protected-state') { throw 'Compiled protected-state module required for external-module denials' }
            # These generated compiler inputs are confined test outputs, never product sources.
            # The positive control rules out missing classpaths/toolchains as a false denial.
            $boundary = Join-Path $out 'external-boundary'
            if (-not (Test-Path -LiteralPath $boundary)) { New-Item -ItemType Directory -Path $boundary | Out-Null }
            if (((Get-Item -LiteralPath $boundary).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse compiler fixture root rejected' }
            $cases = @(
                @{Name='public-control'; Accept=$true; Source='package boundary; fun observe(x: org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade) = x.snapshot()'},
                @{Name='writer-denied'; Accept=$false; Source='package boundary; fun mutate(x: org.kurdistanvpn.data.protectedstate.JournalStorage) { x.compareAndReplace("x", null, byteArrayOf(1)) }'},
                @{Name='digest-retag-denied'; Accept=$false; Source='package boundary; fun forge() = org.kurdistanvpn.data.protectedstate.JournalDigest.checkpoint(byteArrayOf(1))'},
                @{Name='broker-denied'; Accept=$false; Source='package boundary; fun bypass(x: org.kurdistanvpn.data.protectedstate.ProtectedStateMutationBroker) = x.replaceRouting(emptySet())'},
                @{Name='store-field-denied'; Accept=$false; Source='package boundary; fun bypass(x: org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade) = x.storage'},
                @{Name='reset-capability-denied'; Accept=$false; Source='package boundary; fun bypass(x: org.kurdistanvpn.data.protectedstate.ProtectedStateResetRecoveryCoordinator) = x.start(ByteArray(32))'},
                @{Name='receipt-construction-denied'; Accept=$false; Source='package boundary; fun forge() = org.kurdistanvpn.data.protectedstate.BrokerMutation<Any>(org.kurdistanvpn.data.protectedstate.ProtectedMutationStatus.COMMITTED)'},
                @{Name='command-construction-denied'; Accept=$false; Source='package boundary; fun forge(display: org.kurdistanvpn.core.model.RedactedProfilePreview) = org.kurdistanvpn.data.protectedstate.ConfirmedProtectedImport(byteArrayOf(1), display, null, 2L, ByteArray(16))'},
                @{Name='snapshot-construction-denied'; Accept=$false; Source='package boundary; fun forge() = org.kurdistanvpn.data.protectedstate.ProtectedStateSnapshot.create(ByteArray(16), 2L, null, emptyList(), byteArrayOf(1), byteArrayOf(1), ByteArray(32))'},
                @{Name='raw-digest-construction-denied'; Accept=$false; Source='package boundary; fun forge() = org.kurdistanvpn.data.protectedstate.JournalDigest(1, ByteArray(32))'}
            )
            foreach ($case in $cases) {
                $source = Join-Path $boundary ($case.Name + '.kt')
                $destination = Join-Path $boundary ($case.Name + '-classes')
                if (Test-Path -LiteralPath $source) { throw 'External compiler fixture already exists; use a fresh output name' }
                [IO.File]::WriteAllText($source, $case.Source, [Text.UTF8Encoding]::new($false))
                $arguments = @('-cp', ($compiler -join [IO.Path]::PathSeparator),
                    'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','17',
                    '-module-name','external_boundary_consumer','-classpath',($libraries -join [IO.Path]::PathSeparator),
                    '-d',$destination,$source)
                $diagnostics = @(& $java @vm @arguments 2>&1)
                $compilerExit = $LASTEXITCODE
                if ($case.Accept) {
                    if ($compilerExit -ne 0) { throw 'External-module positive control did not compile' }
                } else { Assert-ExpectedCompilerDenial $compilerExit $diagnostics $case.Name }
                Write-Output ('PASS: external-module boundary ' + $case.Name)
            }
        }
    } finally {
        $env:TEMP = $savedTemp
        $env:TMP = $savedTmp
    }
}
function Invoke-LocalGradleChecks {
    Assert-LocalCorrectionWorkspace
    if ($Tasks.Count -eq 0) { throw 'Explicit host task list required' }
    if ($Mode -eq 'Lockfiles' -and ($Tasks.Count -ne 1 -or $Tasks[0] -cne ':resolveLocalCorrectionLocks')) {
        throw 'Lock writing requires only the audited lock-resolution task'
    }
    foreach ($task in $Tasks) {
        if (($Mode -ne 'Lockfiles' -or $task -cne ':resolveLocalCorrectionLocks') -and $task -cnotmatch '^:(app|core:(model|native-api|native-jni)|data:(secure|metadata|settings|protected-state)|runtime:(api|android)):(compile(Internal|Debug)(AndroidTest|UnitTest)?Kotlin|test(Internal|Debug)UnitTest|process(Internal|Debug)(Main|AndroidTest)?Manifest|lint(Internal|Debug))$') {
            throw 'Task is not an approved non-device check'
        }
    }
    $local = Join-Path $script:CorrectionRoot '.tools/offline-validation'
    $writable = @{
        GRADLE_USER_HOME=(Join-Path $local 'gradle-home'); ANDROID_USER_HOME=(Join-Path $local 'android-home')
        TEMP=(Join-Path $local 'tmp'); TMP=(Join-Path $local 'tmp')
        KOTLIN_DAEMON_RUN_FILES_PATH=(Join-Path $local 'kotlin')
        GOCACHE=(Join-Path $local 'go-cache'); GOMODCACHE=(Join-Path $local 'go-mod'); GOTMPDIR=(Join-Path $local 'go-tmp')
        GOPROXY='off'; GOTOOLCHAIN='local'
    }
    Assert-LocalOfflineEnvironment $writable
    foreach ($name in $writable.Keys) {
        if ($name -notin @('GOPROXY','GOTOOLCHAIN')) {
            $directory = $writable[$name]
            if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory | Out-Null }
            if (((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse output rejected' }
        }
    }
    $values = $writable.Clone()
    $values.GRADLE_RO_DEP_CACHE = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.gradle/caches'
    $values.JAVA_HOME = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Android/Android Studio/jbr'
    $values.ANDROID_HOME = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Android/Sdk'
    $values.GOSUMDB = 'off'
    $goBin = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.windows-amd64/bin'
    if (-not (Test-Path -LiteralPath (Join-Path $goBin 'go.exe'))) { throw 'Missing installed Go 1.26.6; no download permitted' }
    $values.PATH = $goBin + [IO.Path]::PathSeparator + $env:PATH
    $values.GRADLE_OPTS = '-Duser.home=' + (Join-Path $local 'home') + ' -Djava.io.tmpdir=' + $writable.TEMP + ' -XX:-UsePerfData'
    $saved = @{}
    $lockBefore = Get-LocalCorrectionLockSnapshot
    $identityPaths = @('android/gradle/libs.versions.toml','android/gradle/verification-metadata.xml',
        'android/gradle/wrapper/gradle-wrapper.properties','go.mod','go.sum')
    $identities = @{}
    foreach ($path in $identityPaths) {
        $identities[$path] = (Get-FileHash -LiteralPath (Join-Path $script:CorrectionRoot $path) -Algorithm SHA256).Hash
    }
    try {
        foreach ($name in $values.Keys) {
            $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            [Environment]::SetEnvironmentVariable($name, $values[$name], 'Process')
        }
        $gradle = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.gradle/wrapper/dists/gradle-9.4.1-bin/arn2x92ynaizyzdaamcbpbhtj/gradle-9.4.1/bin/gradle.bat'
        if (-not (Test-Path -LiteralPath $gradle)) { throw 'Missing installed Gradle 9.4.1; no download permitted' }
        $arguments = @('-p',(Join-Path $script:CorrectionRoot 'android'),'--offline','--no-daemon','--no-watch-fs',
            '--no-configuration-cache','--no-build-cache','--dependency-verification','strict',
            '-PlocalCorrection=true','-Pandroid.builder.sdkDownload=false','-Pkotlin.compiler.execution.strategy=in-process',
            '-Dorg.gradle.java.installations.auto-download=false')
        if ($DryRun) { $arguments += '--dry-run' }
        if ($Mode -eq 'Lockfiles') { $arguments += @('--write-locks','-PlocalCorrectionLockWrite=true') }
        & $gradle @arguments @Tasks
        if ($LASTEXITCODE -ne 0) { throw 'Offline non-device Gradle check failed' }
    } finally {
        foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
        foreach ($path in $identityPaths) {
            if ((Get-FileHash -LiteralPath (Join-Path $script:CorrectionRoot $path) -Algorithm SHA256).Hash -cne $identities[$path]) {
                throw 'Dependency or toolchain identity file changed during validation'
            }
        }
        $lockAfter = Get-LocalCorrectionLockSnapshot
        Assert-LocalCorrectionLockChanges $lockBefore $lockAfter ($Mode -eq 'Lockfiles')
        Assert-LocalCorrectionWorkspace
    }
}
if ($Mode -eq 'VerifyWorkspace') { Assert-LocalCorrectionWorkspace }
if ($Mode -eq 'KotlinTests') { Invoke-LocalKotlinTests }
if ($Mode -eq 'KotlinBoundaryChecks') { Invoke-LocalKotlinTests }
if ($Mode -eq 'GradleChecks') { Invoke-LocalGradleChecks }
if ($Mode -eq 'Lockfiles') { Invoke-LocalGradleChecks }
