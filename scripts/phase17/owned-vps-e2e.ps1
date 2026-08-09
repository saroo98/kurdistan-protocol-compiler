# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$SshAlias,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$AvdName,
    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot,
    [ValidateSet('Functional', 'Stress', 'Soak12h')]
    [string]$Mode = 'Functional',
    [ValidateRange(1, 65535)]
    [int]$RelayPort = 8443,
    [string]$PackagePath = '',
    [string]$AppApk = '',
    [string]$TestApk = '',
    [string]$AdbExecutable = '',
    [string]$SshExecutable = 'ssh',
    [string]$ScpExecutable = 'scp'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $PackagePath) {
    $packageVersion = '0.17.0-field.' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddHHmmss')
    $packageRoot = Join-Path $repoRoot ('.tools\phase17\packages-field-' + [Guid]::NewGuid().ToString('N'))
    Push-Location $repoRoot
    try {
        go run ./cmd/kurdpackage build -root . -out $packageRoot -version $packageVersion -arches amd64 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'PHASE17_PACKAGE_BUILD_FAILED'
        }
    } finally {
        Pop-Location
    }
    $packages = @(Get-ChildItem $packageRoot -Filter '*linux-amd64.tar.gz' -File)
    if ($packages.Count -ne 1) {
        throw 'PHASE17_PACKAGE_OUTPUT_REJECTED'
    }
    $PackagePath = $packages[0].FullName
}
if (-not $AppApk) {
    $AppApk = Join-Path $repoRoot 'android\app\build\outputs\apk\internal\app-internal.apk'
}
if (-not $TestApk) {
    $TestApk = Join-Path $repoRoot 'android\app\build\outputs\apk\androidTest\internal\app-internal-androidTest.apk'
}
if (-not $AdbExecutable) {
    $AdbExecutable = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
}

foreach ($path in @($PackagePath, $AppApk, $TestApk, $AdbExecutable)) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'PHASE17_FIELD_INPUT_UNAVAILABLE'
    }
}

Push-Location $repoRoot
try {
    go run ./cmd/phase17field `
        -ssh-alias $SshAlias `
        -avd-name $AvdName `
        -evidence-root ([IO.Path]::GetFullPath($EvidenceRoot)) `
        -mode $Mode `
        -relay-port $RelayPort `
        -package ([IO.Path]::GetFullPath($PackagePath)) `
        -app-apk ([IO.Path]::GetFullPath($AppApk)) `
        -test-apk ([IO.Path]::GetFullPath($TestApk)) `
        -adb ([IO.Path]::GetFullPath($AdbExecutable)) `
        -ssh $SshExecutable `
        -scp $ScpExecutable
    if ($LASTEXITCODE -ne 0) {
        throw 'PHASE17_FIELD_MATRIX_FAILED'
    }
    $result = Get-ChildItem -LiteralPath ([IO.Path]::GetFullPath($EvidenceRoot)) -Recurse -Filter 'field-result.json' -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $result) {
        throw 'PHASE17_FIELD_RESULT_MISSING'
    }
} finally {
    Pop-Location
}
