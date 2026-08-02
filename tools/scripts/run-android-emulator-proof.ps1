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
$avdName = "kurdistan_phase16_api$Api"
$emulatorLog = ".tools/phase16/emulator-api$Api.log"
$logcat = ".tools/phase16/logcat-api$Api.txt"

New-Item -ItemType Directory -Force '.tools/phase16' | Out-Null
New-Item -ItemType Directory -Force (Split-Path -Parent $GateReceipt) | Out-Null
New-Item -ItemType Directory -Force (Split-Path -Parent $Timings) | Out-Null
& $sdkManager 'platform-tools' 'emulator' $systemImage
if ($LASTEXITCODE -ne 0) { throw 'sdkmanager failed' }

try {
    & $avdManager delete avd --name $avdName 2>$null | Out-Null
} catch {
    # Absence is expected on a clean runner.
}
'no' | & $avdManager create avd --force --name $avdName --package $systemImage --device 'pixel_6'
if ($LASTEXITCODE -ne 0) { throw 'avdmanager failed' }

$process = $null
$gateExit = 1
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
    ) -RedirectStandardOutput $emulatorLog -RedirectStandardError "$emulatorLog.stderr" -PassThru

    & $adb wait-for-device
    if ($LASTEXITCODE -ne 0) { throw 'adb did not discover the emulator' }
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
    & $adb logcat -c

    & go run ./cmd/gate -proof $Proof -receipt $GateReceipt -timings $Timings
    $gateExit = $LASTEXITCODE
} finally {
    try { & $adb logcat -d | Set-Content -LiteralPath $logcat -Encoding utf8NoBOM } catch {}
    try { & $adb emu kill | Out-Null } catch {}
    if ($null -ne $process -and -not $process.HasExited) {
        $process.Kill($true)
    }
}

exit $gateExit
