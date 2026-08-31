param(
    [string]$RepositoryRoot = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent),
    [string]$NativeBridgeGradle = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$guard = Join-Path $PSScriptRoot 'run-local-correction-checks.ps1'
if (-not (Test-Path -LiteralPath $guard)) { throw 'BV-01: approved whitelist guard is missing' }
. $guard -Mode FunctionsOnly -RepositoryRoot $RepositoryRoot
function Assert-Rejected([scriptblock]$Action, [string]$Id) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw ($Id + ': unsafe input was admitted') }
}
$global:LASTEXITCODE = 23
Assert-ExpectedCompilerDenial 1 @("Cannot access 'JournalStorage': it is internal") 'expected-denial'
if ($global:LASTEXITCODE -ne 0) {
    throw 'BV-04: an accepted negative compiler fixture leaked its native exit status'
}
Assert-Rejected { Assert-ExpectedCompilerDenial 0 @() 'unexpected-success' } 'BV-04'
Assert-Rejected { Assert-ExpectedCompilerDenial 1 @('unresolved reference: missing') 'wrong-failure' } 'BV-04'
$paths = @(Get-LocalCorrectionWhitelist)
if ($paths.Count -ne 209 -or @($paths.Path | Sort-Object -Unique).Count -ne 209) {
    throw 'BV-01: whitelist accounting mismatch'
}
if (@($paths | Where-Object Kind -eq 'M').Count -ne 121 -or
    @($paths | Where-Object Kind -eq 'N').Count -ne 82 -or
    @($paths | Where-Object Kind -eq 'D').Count -ne 6) { throw 'BV-01: whitelist disposition mismatch' }
foreach ($aclPath in @('internal/selfhost/backup.go','internal/selfhost/private_path_windows.go',
    'internal/selfhost/restore_acl_windows_test.go','cmd/kurdctl/localpath_windows.go',
    'cmd/kurdctl/main_test.go','cmd/kurdctl/localpath_windows_test.go')) {
    Assert-LocalCorrectionPath $aclPath
}
foreach ($followupPath in @('.github/workflows/ci.yml',
    'android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase11ControlSurfaceDeviceTest.kt',
    'android/app/src/androidTest/kotlin/org/kurdistanvpn/app/ProtectedStateStartupDeviceTest.kt',
    'android/app/src/test/kotlin/org/kurdistanvpn/app/FirstUseStartupTest.kt',
    'cmd/phase9devicegate/main.go','cmd/phase9devicegate/main_test.go',
    'cmd/phase9devicegate/startup_observer.go','cmd/phase9devicegate/startup_observer_test.go')) {
    Assert-LocalCorrectionPath $followupPath
}
Assert-LocalCorrectionWorkspace
$savedBaseline = $script:CorrectionBaseline
$savedTree = $script:CorrectionTree
try {
    $script:CorrectionBaseline = '0000000000000000000000000000000000000000'
    Assert-Rejected { Assert-LocalCorrectionWorkspace } 'BV-01'
    $script:CorrectionBaseline = $savedBaseline
    $script:CorrectionTree = '0000000000000000000000000000000000000000'
    Assert-Rejected { Assert-LocalCorrectionWorkspace } 'BV-01'
} finally {
    $script:CorrectionBaseline = $savedBaseline
    $script:CorrectionTree = $savedTree
}
Assert-LocalCorrectionPath 'android/settings-gradle.lockfile'
foreach ($historicalVerifier in @('internal/testkit/evidenceoverlay/successor.go',
    'internal/testkit/evidenceoverlay/successor_test.go','internal/audit/security.go',
    'internal/testkit/importrules/importrules_test.go','internal/phase17evidence/evidence.go',
    'cmd/phase9verify/phase11_overlay_test.go','internal/audit/codegen_test.go',
    'internal/audit/security_test.go','internal/runtime/policy_enforcement_test.go')) {
    Assert-LocalCorrectionPath $historicalVerifier
}
foreach ($lock in @('android/settings-gradle.lockfile','android/app/gradle.lockfile',
    'android/core/native-api/gradle.lockfile','android/data/protected-state/gradle.lockfile')) {
    Assert-LocalCorrectionLockOutput $lock
}
Assert-Rejected { Assert-LocalCorrectionLockOutput 'android/data/secure/gradle.lockfile' } 'BV-03'
Assert-Rejected { Assert-LocalCorrectionLockOutput 'android/gradle/libs.versions.toml' } 'BV-03'
Assert-Rejected { Assert-LocalCorrectionLockOutput '../settings-gradle.lockfile' } 'BV-03'
Assert-Rejected { Assert-LocalCorrectionLockChanges @{} @{'android/new/gradle.lockfile'='abc'} $true } 'BV-03'
Assert-Rejected { Assert-LocalCorrectionLockChanges @{'android/app/gradle.lockfile'='abc'} @{'android/app/gradle.lockfile'='def'} $false } 'BV-03'
Assert-LocalCorrectionLockChanges @{} @{'android/data/protected-state/gradle.lockfile'='abc'} $true
$locked = @('junit:junit:4.13.2', 'org.hamcrest:hamcrest-core:1.3')
Assert-LocalCorrectionDependencySelection $locked @('junit:junit:4.13.2')
Assert-Rejected { Assert-LocalCorrectionDependencySelection $locked @('junit:junit:4.14.0') } 'BV-03'
Assert-Rejected { Assert-LocalCorrectionDependencySelection $locked @('unapproved:artifact:1.0') } 'BV-03'
Assert-LocalCorrectionPath 'android/app/src/main/AndroidManifest.xml'
Assert-Rejected { Assert-LocalCorrectionPath '../escape.kt' } 'BV-01'
Assert-Rejected { Assert-LocalCorrectionPath 'android/../go.mod' } 'BV-01'
Assert-Rejected { Assert-LocalCorrectionPath 'C:/outside.kt' } 'BV-01'
Assert-Rejected { Assert-LocalCorrectionPath '.codex-private/ENGINEERING.md' } 'BV-01'
Assert-Rejected { Assert-LocalCorrectionPath 'android/gradle/libs.versions.toml' } 'BV-01'
$allowed = [pscustomobject]@{ Path=':app:compileInternalKotlin'; Type='KotlinCompile'; Outputs=@('app/build/classes'); Command=@(); Finalizers=@() }
Assert-LocalCorrectionTaskGraph @($allowed)
Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':core:model:bundleLibCompileToJarDebug';Type='BundleLibraryClassesJar';Outputs=@('core/model/build/classes.jar');Command=@();Finalizers=@()})
Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':app:bundleInternalClassesToCompileJar';Type='BundleAllClasses';Outputs=@('app/build/classes.jar');Command=@();Finalizers=@()})
Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':app:bundleInternalClassesToRuntimeJar';Type='BundleAllClasses';Outputs=@('app/build/runtime.jar');Command=@();Finalizers=@()})
$lintPreparation = [pscustomobject]@{Path=':core:ui:prepareLintJarForPublish';Type='com.android.build.gradle.internal.tasks.PrepareLintJarForPublish_Decorated';Outputs=@('core/ui/build/intermediates/lint_publish_jar/global/prepareLintJarForPublish/lint.jar');Command=@();Finalizers=@()}
Assert-LocalCorrectionTaskGraph @($lintPreparation)
$lintAar = [pscustomobject]@{Path=':core:ui:bundleDebugLocalLintAar';Type='com.android.build.gradle.tasks.BundleAar_Decorated';Outputs=@('core/ui/build/intermediates/local_aar_for_lint/debug/out.aar');Command=@();Finalizers=@()}
Assert-LocalCorrectionTaskGraph @($lintAar)
Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':core:native-jni:bundleInternalLocalLintAar';Type=$lintAar.Type;Outputs=@('core/native-jni/build/intermediates/local_aar_for_lint/internal/out.aar');Command=@();Finalizers=@()})
Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':test:fixtures:prepareLintJarForPublish';Type=$lintPreparation.Type;Outputs=@('test/fixtures/build/intermediates/lint_publish_jar/global/prepareLintJarForPublish/lint.jar');Command=@();Finalizers=@()})
foreach ($invalid in @(
    [pscustomobject]@{Path=':core:ui:prepareLintJarForPublish';Type='DefaultTask';Outputs=@('core/ui/build/lint.jar');Command=@();Finalizers=@()},
    [pscustomobject]@{Path=':outside:prepareLintJarForPublish';Type=$lintPreparation.Type;Outputs=$lintPreparation.Outputs;Command=@();Finalizers=@()},
    [pscustomobject]@{Path=$lintPreparation.Path;Type=$lintPreparation.Type;Outputs=@('core/ui/build/app.apk');Command=@();Finalizers=@()},
    [pscustomobject]@{Path=$lintPreparation.Path;Type=$lintPreparation.Type;Outputs=$lintPreparation.Outputs;Command=@();Finalizers=@(':publish')},
    [pscustomobject]@{Path=':core:ui:bundleDebugAar';Type=$lintAar.Type;Outputs=$lintAar.Outputs;Command=@();Finalizers=@()},
    [pscustomobject]@{Path=$lintAar.Path;Type='DefaultTask';Outputs=$lintAar.Outputs;Command=@();Finalizers=@()},
    [pscustomobject]@{Path=$lintAar.Path;Type=$lintAar.Type;Outputs=@('core/ui/build/release.aar');Command=@();Finalizers=@()},
    [pscustomobject]@{Path=':core:ui:bundleInternalLocalLintAar';Type=$lintAar.Type;Outputs=@('core/ui/build/intermediates/local_aar_for_lint/debug/out.aar');Command=@();Finalizers=@()}
)) { Assert-Rejected { Assert-LocalCorrectionTaskGraph @($invalid) } 'BV-02' }
Assert-Rejected { Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':app:bundleInternal';Type='BundleTask';Outputs=@();Command=@();Finalizers=@()}) } 'BV-02'
foreach ($task in @(':app:assembleInternal', ':app:packageInternal', ':app:installInternal', ':phase17Gate', ':app:connectedInternalAndroidTest', ':publish')) {
    Assert-Rejected { Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=$task;Type='DefaultTask';Outputs=@();Command=@();Finalizers=@()}) } 'BV-02'
}
Assert-Rejected { Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':app:compileInternalKotlin';Type='KotlinCompile';Outputs=@('out.apk');Command=@();Finalizers=@()}) } 'BV-02'
Assert-Rejected { Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':app:compileInternalKotlin';Type='Exec';Outputs=@();Command=@('adb','devices');Finalizers=@()}) } 'BV-02'
Assert-Rejected { Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':app:compileInternalKotlin';Type='KotlinCompile';Outputs=@();Command=@();Finalizers=@(':publish')}) } 'BV-02'
Assert-Rejected { Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':app:compileInternalKotlin';Type='KotlinCompile';Outputs=@('../escape');Command=@();Finalizers=@()}) } 'BV-02'
Assert-Rejected { Assert-LocalCorrectionTaskGraph @([pscustomobject]@{Path=':app:compileInternalKotlin';Type='KotlinCompile';Outputs=@();Command=@('curl','example.invalid');Finalizers=@()}) } 'BV-02'
Assert-Rejected { Assert-LocalOfflineEnvironment -Values @{ GRADLE_USER_HOME='C:/outside' } } 'BV-03'
Write-Output 'PASS: BV-01 whitelist and confinement; BV-02 prohibited task/output/command/finalizer rejection; BV-03 external writable environment rejection. No build task executed.'

if ($NativeBridgeGradle) {
    # Opt-in integration regression against the real project and pinned, already installed Gradle.
    # These are dry runs only: no producer, APK, native compiler, or device task is executed.
    if (-not (Test-Path -LiteralPath $NativeBridgeGradle -PathType Leaf)) {
        throw 'An existing offline Gradle executable is required; acquisition is not permitted'
    }
    $arguments = @('-p', (Join-Path $RepositoryRoot 'android'), '--offline', '--no-daemon',
        '--no-watch-fs', '--no-configuration-cache', '--no-build-cache', '--dependency-verification', 'strict',
        '-Pandroid.builder.sdkDownload=false', '-Pkotlin.compiler.execution.strategy=in-process',
        '-Dorg.gradle.java.installations.auto-download=false', '--console=plain', '--dry-run')
    $failures = [Collections.Generic.List[string]]::new()
    function Read-NativeTaskGraph([string]$Task) {
        $output = @(& $NativeBridgeGradle @arguments $Task 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw ('Native task graph could not be evaluated for ' + $Task + "`n" + ($output -join "`n"))
        }
        $graph = @($output | ForEach-Object {
            if ([string]$_ -cmatch '^(:\S+) SKIPPED$') { $Matches[1] }
        })
        if ($graph.Count -eq 0 -or $graph[-1] -cne (':' + $Task.TrimStart(':'))) {
            throw ('Missing or incomplete dry-run graph: ' + $Task)
        }
        foreach ($node in $graph) {
            if ($node -match '(?i):(install|uninstall|connected|.*DeviceGate|.*Campaign|.*Stress|.*Soak|publish|upload|deploy|.*EngineeringCandidate)') {
                $failures.Add($Task + ': prohibited device, publication, or candidate task ' + $node)
            }
        }
        return ,$graph
    }
    function Assert-NoAppPackaging([string]$Task, [string[]]$Graph) {
        foreach ($node in $Graph) {
            if ($node -cmatch '^:app:(assemble|package|bundle|sign|validateSigning)' -and
                $node -cnotmatch '^:app:bundle\w+ClassesTo(Compile|Runtime)Jar$') {
                $failures.Add($Task + ': unrelated application packaging task ' + $node)
            }
        }
    }
    function Assert-BridgeOrder([string]$Task, [string[]]$Graph, [string]$Producer, [string[]]$Consumers) {
        $producerIndex = [Array]::IndexOf($Graph, $Producer)
        if ($producerIndex -lt 0) { $failures.Add($Task + ': missing prerequisite ' + $Producer) }
        foreach ($consumer in $Consumers) {
            $consumerIndex = [Array]::IndexOf($Graph, $consumer)
            if ($consumerIndex -lt 0) { $failures.Add($Task + ': missing native consumer ' + $consumer) }
            elseif ($producerIndex -ge $consumerIndex) {
                $failures.Add($Task + ': bridge does not precede ' + $consumer)
            }
        }
    }
    $variants = @(
        @{ Name='Internal'; Producers=@{ 'arm64-v8a'='buildInternalArm64v8aGoBridge'; 'x86_64'='buildInternalX8664GoBridge' } },
        @{ Name='Release'; Producers=@{ 'arm64-v8a'='buildReleaseArm64v8aGoBridge' } }
    )
    $consumers = @{}
    foreach ($variant in $variants) {
        $task = ':core:native-jni:externalNativeBuild' + $variant.Name
        $graph = Read-NativeTaskGraph $task
        Assert-NoAppPackaging $task $graph
        $consumers[$variant.Name] = @{}
        foreach ($abi in $variant.Producers.Keys) {
            # Discover AGP's observable task identities from a direct variant graph, not from
            # production task-name inference. The producer and ABI expectations are independent.
            $suffix = '\[' + [regex]::Escape($abi) + '\](?:-\d+)?$'
            $configure = @($graph | Where-Object { $_ -cmatch ('^:core:native-jni:configureCMake\w+' + $suffix) })
            $build = @($graph | Where-Object { $_ -cmatch ('^:core:native-jni:buildCMake\w+' + $suffix) })
            if ($configure.Count -ne 1 -or $build.Count -ne 1) {
                throw ('Expected one configure/build pair for ' + $task + '/' + $abi)
            }
            $consumers[$variant.Name][$abi] = @($configure[0], $build[0])
            $producer = ':core:native-jni:' + $variant.Producers[$abi]
            Assert-BridgeOrder $task $graph $producer $consumers[$variant.Name][$abi]
            if ([Array]::IndexOf($graph, $configure[0]) -ge [Array]::IndexOf($graph, $build[0])) {
                $failures.Add($task + ': native build precedes configuration for ' + $abi)
            }
        }
        foreach ($node in $graph | Where-Object { $_ -cmatch '^:core:native-jni:build.+GoBridge$' }) {
            if ($node -cnotin @($variant.Producers.Values | ForEach-Object { ':core:native-jni:' + $_ })) {
                $failures.Add($task + ': unrelated variant producer ' + $node)
            }
        }
        Write-Output ('CHECKED: direct native graph ' + $task)
    }
    foreach ($task in @('ciDeviceArtifacts', 'ciPrHostGate', 'ciAssuranceHostGate')) {
        $graph = Read-NativeTaskGraph $task
        $required = if ($task -ceq 'ciDeviceArtifacts') { @('Internal') } else { @('Internal', 'Release') }
        foreach ($variant in $variants | Where-Object { $_.Name -cin $required }) {
            foreach ($abi in $variant.Producers.Keys) {
                Assert-BridgeOrder $task $graph (':core:native-jni:' + $variant.Producers[$abi]) $consumers[$variant.Name][$abi]
            }
        }
        if ($task -ceq 'ciDeviceArtifacts' -and @($graph | Where-Object { $_ -cmatch ':\w*Release\w*(?:\[.*\])?$' }).Count -ne 0) {
            $failures.Add($task + ': unrelated release task')
        }
        if ($task -cne 'ciDeviceArtifacts' -and @($graph | Where-Object { $_ -cmatch '^:app:(assemble|package).*AndroidTest$' }).Count -ne 0) {
            $failures.Add($task + ': unrequested test APK packaging')
        }
        Write-Output ('CHECKED: aggregate native graph ' + $task)
    }
    foreach ($task in @('help', ':core:model:testDebugUnitTest')) {
        $graph = Read-NativeTaskGraph $task
        Assert-NoAppPackaging $task $graph
        if (@($graph | Where-Object { $_ -cmatch '^:core:native-jni:.*(GoBridge|CMake)' }).Count -ne 0) {
            $failures.Add($task + ': unrelated native build was realized')
        }
    }
    if ($failures.Count -ne 0) { throw ("Native bridge prerequisite regression:`n" + ($failures -join "`n")) }
    Write-Output 'PASS: direct and all three CI aggregate graphs order every required bridge before CMake; unrelated packaging, device, release, and native tasks remain absent.'
}
