# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(26, 34, 36)]
    [int]$Api,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^android-device-api(26|34|36)$')]
    [string]$Proof,
    [Parameter(Mandatory = $true)]
    [string]$GateReceipt,
    [Parameter(Mandatory = $true)]
    [string]$Timings
)

$ErrorActionPreference = 'Stop'
if ($Proof -ne "android-device-api$Api") {
    throw 'Proof identity does not match the requested emulator API.'
}
if (-not $IsLinux) {
    throw 'Authoritative headless emulator lanes currently require a Linux runner.'
}
if ([string]::IsNullOrWhiteSpace($env:ANDROID_HOME)) {
    throw 'ANDROID_HOME is required.'
}
if (-not (Test-Path -LiteralPath '/dev/kvm')) {
    throw 'The Linux runner does not expose /dev/kvm for hardware-accelerated Android emulation.'
}
& sudo chmod 666 /dev/kvm
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to grant the current runner access to /dev/kvm.'
}

$sdkManager = Join-Path $env:ANDROID_HOME 'cmdline-tools/latest/bin/sdkmanager'
$avdManager = Join-Path $env:ANDROID_HOME 'cmdline-tools/latest/bin/avdmanager'
$emulator = Join-Path $env:ANDROID_HOME 'emulator/emulator'
$adb = Join-Path $env:ANDROID_HOME 'platform-tools/adb'
$systemImage = "system-images;android-$Api;google_apis;x86_64"
$avdName = "kurdistan_phase17_api$Api"
$avdParent = if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$avdHome = [IO.Path]::GetFullPath((Join-Path $avdParent "kurdistan-avd-api$Api"))
$rawEmulatorLog = Join-Path $avdParent "kurdistan-emulator-api$Api.stdout.log"
$rawEmulatorError = Join-Path $avdParent "kurdistan-emulator-api$Api.stderr.log"
$rawPostRunLogcat = Join-Path $avdParent "kurdistan-logcat-api$Api.txt"
$emulatorSummary = ".tools/phase17/emulator-api$Api-summary.txt"
$deviceSummary = ".tools/phase17/logcat-api$Api-summary.txt"
$emulatorIdentity = ".tools/phase17/emulator-api$Api-identity.json"

function Resolve-SdkPackageMetadata {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)
    foreach ($name in @('package.xml', 'source.properties')) {
        $candidate = Join-Path $PackageRoot $name
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw "required SDK package metadata is missing under: $PackageRoot"
}

function Get-SdkPackageRevision {
    param([Parameter(Mandatory = $true)][string]$MetadataPath)
    if (-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf)) { throw "required SDK package metadata is missing: $MetadataPath" }
    if ([IO.Path]::GetFileName($MetadataPath) -eq 'source.properties') {
        $revisionLine = Get-Content -LiteralPath $MetadataPath | Where-Object { $_ -match '^Pkg\.Revision\s*=\s*([0-9]+(?:\.[0-9]+){0,2})\s*$' } | Select-Object -First 1
        if ($null -eq $revisionLine) { throw "SDK package revision is missing: $MetadataPath" }
        if ($revisionLine -notmatch '^Pkg\.Revision\s*=\s*([0-9]+(?:\.[0-9]+){0,2})\s*$') { throw "SDK package revision is invalid: $MetadataPath" }
        return $Matches[1]
    }
    [xml]$metadata = Get-Content -LiteralPath $MetadataPath -Raw
    $revision = $metadata.SelectSingleNode("//*[local-name()='revision']")
    if ($null -eq $revision) { throw "SDK package revision is missing: $MetadataPath" }
    $major = $revision.SelectSingleNode("./*[local-name()='major']").InnerText
    $minorNode = $revision.SelectSingleNode("./*[local-name()='minor']")
    $microNode = $revision.SelectSingleNode("./*[local-name()='micro']")
    if ($major -notmatch '^\d+$') { throw "SDK package major revision is invalid: $MetadataPath" }
    $minor = if ($null -eq $minorNode) { '0' } else { $minorNode.InnerText }
    $micro = if ($null -eq $microNode) { '0' } else { $microNode.InnerText }
    if ($minor -notmatch '^\d+$' -or $micro -notmatch '^\d+$') { throw "SDK package revision is invalid: $MetadataPath" }
    return "$major.$minor.$micro"
}

function Write-CategoricalSummary {
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$Kind
    )
    $counts = [ordered]@{ error = 0; fatal = 0; crash = 0; anr = 0; panic = 0; target_package = 0 }
    $lineCount = 0
    $inputTruncated = $false
    if (Test-Path -LiteralPath $InputPath) {
        foreach ($line in [IO.File]::ReadLines($InputPath)) {
            $lineCount++
            if ($lineCount -gt 200000) { $inputTruncated = $true; break }
            $lower = $line.ToLowerInvariant()
            if ($lower.Contains('error')) { $counts.error++ }
            if ($lower.Contains('fatal')) { $counts.fatal++ }
            if ($lower.Contains('crash')) { $counts.crash++ }
            if ($lower.Contains('anr in ')) { $counts.anr++ }
            if ($lower.Contains('panic')) { $counts.panic++ }
            if ($lower.Contains('org.kurdistanvpn.app.internal')) { $counts.target_package++ }
        }
    }
    @(
        'schema=kurdistan-emulator-diagnostic-summary-v1'
        "kind=$Kind"
        "input_truncated=$($inputTruncated.ToString().ToLowerInvariant())"
        "lines_examined=$([Math]::Min($lineCount, 200000))"
        "error_events=$($counts.error)"
        "fatal_events=$($counts.fatal)"
        "crash_events=$($counts.crash)"
        "anr_events=$($counts.anr)"
        "panic_events=$($counts.panic)"
        "target_package_events=$($counts.target_package)"
    ) | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
    if ((Get-Item -LiteralPath $OutputPath).Length -gt 4096) {
        throw "categorical $Kind summary exceeded 4096 bytes"
    }
}

New-Item -ItemType Directory -Force '.tools/phase17' | Out-Null
New-Item -ItemType Directory -Force $avdHome | Out-Null
New-Item -ItemType Directory -Force (Split-Path -Parent $GateReceipt) | Out-Null
New-Item -ItemType Directory -Force (Split-Path -Parent $Timings) | Out-Null
$env:ANDROID_AVD_HOME = $avdHome
& $sdkManager 'platform-tools' 'emulator' $systemImage
if ($LASTEXITCODE -ne 0) { throw 'sdkmanager failed' }
$emulatorDigest = (Get-FileHash -LiteralPath $emulator -Algorithm SHA256).Hash.ToLowerInvariant()
$adbDigest = (Get-FileHash -LiteralPath $adb -Algorithm SHA256).Hash.ToLowerInvariant()
$emulatorPackage = Resolve-SdkPackageMetadata -PackageRoot (Join-Path $env:ANDROID_HOME 'emulator')
$platformToolsPackage = Resolve-SdkPackageMetadata -PackageRoot (Join-Path $env:ANDROID_HOME 'platform-tools')
$commandLineToolsPackage = Resolve-SdkPackageMetadata -PackageRoot (Join-Path $env:ANDROID_HOME 'cmdline-tools/latest')
$systemImagePackage = Resolve-SdkPackageMetadata -PackageRoot (Join-Path $env:ANDROID_HOME "system-images/android-$Api/google_apis/x86_64")
$emulatorPackageRevision = Get-SdkPackageRevision -MetadataPath $emulatorPackage
$emulatorVersionText = (@(& $emulator -version 2>&1) | ForEach-Object { [string]$_ }) -join "`n"
$adbVersionText = (@(& $adb version 2>&1) | ForEach-Object { [string]$_ }) -join "`n"
$emulatorVersionMatch = [regex]::Match($emulatorVersionText, '(?im)Android\s+emulator\s+version\s+([0-9]+(?:\.[0-9]+){1,3})(?:\s|$)')
$adbVersionMatch = [regex]::Match($adbVersionText, '(?m)^Android Debug Bridge version ([0-9]+(?:\.[0-9]+){1,3})(?:\s|$)')
if (-not $adbVersionMatch.Success) { throw 'adb version is unavailable' }
$emulatorVersion = if ($emulatorVersionMatch.Success) { $emulatorVersionMatch.Groups[1].Value } else { $emulatorPackageRevision }
$emulatorVersionSource = if ($emulatorVersionMatch.Success) { 'executable-output' } else { 'sdk-package-metadata' }
$adbVersion = $adbVersionMatch.Groups[1].Value
$identity = [ordered]@{
    schema = 'kurdistan-emulator-package-identity-v1'
    api = $Api
    abi = 'x86_64'
    systemImage = [ordered]@{
        package = $systemImage
        revision = Get-SdkPackageRevision -MetadataPath $systemImagePackage
        metadataSha256 = (Get-FileHash -LiteralPath $systemImagePackage -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    emulator = [ordered]@{
        version = $emulatorVersion
        versionSource = $emulatorVersionSource
        packageRevision = $emulatorPackageRevision
        executableSha256 = $emulatorDigest
        metadataSha256 = (Get-FileHash -LiteralPath $emulatorPackage -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    platformTools = [ordered]@{
        adbVersion = $adbVersion
        packageRevision = Get-SdkPackageRevision -MetadataPath $platformToolsPackage
        adbSha256 = $adbDigest
        metadataSha256 = (Get-FileHash -LiteralPath $platformToolsPackage -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    commandLineTools = [ordered]@{
        packageRevision = Get-SdkPackageRevision -MetadataPath $commandLineToolsPackage
        metadataSha256 = (Get-FileHash -LiteralPath $commandLineToolsPackage -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$identity | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $emulatorIdentity -Encoding utf8NoBOM
if ((Get-Item -LiteralPath $emulatorIdentity).Length -gt 4096) { throw 'emulator identity manifest exceeded 4096 bytes' }

try {
    & $avdManager delete avd --name $avdName 2>$null | Out-Null
} catch {
    # Absence is expected on a clean runner.
}
'no' | & $avdManager create avd --force --name $avdName --package $systemImage --device 'pixel_6'
if ($LASTEXITCODE -ne 0) { throw 'avdmanager failed' }
$knownAVDs = @(& $emulator '-list-avds')
if ($LASTEXITCODE -ne 0 -or $knownAVDs -notcontains $avdName) {
    throw "created AVD $avdName is not visible to the emulator under ANDROID_AVD_HOME=$avdHome"
}

$process = $null
$gateExit = 1
$failure = $null
Remove-Item -LiteralPath $rawPostRunLogcat, $rawEmulatorLog, $rawEmulatorError -Force -ErrorAction SilentlyContinue
try {
    $process = Start-Process -FilePath $emulator -ArgumentList @(
        '-avd', $avdName,
        '-no-window',
        '-no-audio',
        '-no-boot-anim',
        '-no-snapshot',
        '-wipe-data',
        '-gpu', 'swiftshader_indirect',
        '-accel', 'on'
    ) -RedirectStandardOutput $rawEmulatorLog -RedirectStandardError $rawEmulatorError -PassThru

    $discovered = $false
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        if ($process.HasExited) { throw "emulator exited before adb discovery with code $($process.ExitCode)" }
        $devices = @(& $adb devices 2>$null)
        if ($devices -match '^emulator-\d+\s+device$') {
            $discovered = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $discovered) { throw 'adb emulator discovery timed out' }
    $booted = $false
    for ($attempt = 0; $attempt -lt 180; $attempt++) {
        if ($process.HasExited) { throw "emulator exited before boot with code $($process.ExitCode)" }
        $state = (& $adb shell getprop sys.boot_completed 2>$null).Trim()
        if ($state -eq '1') {
            $booted = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $booted) { throw 'emulator boot timed out' }
    & $adb shell input keyevent 82 | Out-Null
    & go run ./cmd/gate -proof $Proof -receipt $GateReceipt -timings $Timings
    $gateExit = $LASTEXITCODE
} catch {
    $failure = $_.Exception.Message
} finally {
    try {
        & $adb logcat -b crash -d -v brief 1> $rawPostRunLogcat 2>&1
        Write-CategoricalSummary -InputPath $rawPostRunLogcat -OutputPath $deviceSummary -Kind 'post-run-crash-buffer'
    } catch {}
    try {
        Write-CategoricalSummary -InputPath $rawEmulatorLog -OutputPath $emulatorSummary -Kind 'emulator-stdout'
        $stderrSummary = ".tools/phase17/emulator-api$Api-stderr-summary.txt"
        Write-CategoricalSummary -InputPath $rawEmulatorError -OutputPath $stderrSummary -Kind 'emulator-stderr'
    } catch {}
    try { & $adb emu kill | Out-Null } catch {}
    if ($null -ne $process -and -not $process.HasExited) {
        $process.Kill($true)
    }
    Remove-Item -LiteralPath $rawPostRunLogcat, $rawEmulatorLog, $rawEmulatorError -Force -ErrorAction SilentlyContinue
}

if ($null -ne $failure) {
    Write-Host "::error::$failure"
    if (-not (Test-Path -LiteralPath $GateReceipt)) {
        & go run ./cmd/gate -proof $Proof -receipt $GateReceipt -timings $Timings
    }
    exit 1
}

exit $gateExit
