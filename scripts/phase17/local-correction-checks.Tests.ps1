param([string]$RepositoryRoot = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent))
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
$paths = @(Get-LocalCorrectionWhitelist)
if ($paths.Count -ne 194 -or @($paths.Path | Sort-Object -Unique).Count -ne 194) {
    throw 'BV-01: whitelist accounting mismatch'
}
if (@($paths | Where-Object Kind -eq 'M').Count -ne 112 -or
    @($paths | Where-Object Kind -eq 'N').Count -ne 76 -or
    @($paths | Where-Object Kind -eq 'D').Count -ne 6) { throw 'BV-01: whitelist disposition mismatch' }
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
