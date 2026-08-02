# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($RepositoryRoot)
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
$policyPath = Join-Path $root 'config/ci/tools.json'
$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
$version = [string]$policy.osvScanner.version

if ($version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') {
    throw 'OSV Scanner version is not a pinned semantic version.'
}

if ($IsWindows) {
    $asset = 'osv-scanner_windows_amd64.exe'
    $expected = [string]$policy.osvScanner.windowsAmd64Sha256
} elseif ($IsLinux) {
    $asset = 'osv-scanner_linux_amd64'
    $expected = [string]$policy.osvScanner.linuxAmd64Sha256
} else {
    throw "Unsupported host for pinned OSV Scanner: $([System.Environment]::OSVersion.Platform)"
}

if ($expected -notmatch '^[0-9a-f]{64}$') {
    throw 'OSV Scanner policy digest is invalid.'
}

New-Item -ItemType Directory -Force -Path $output | Out-Null
$destination = Join-Path $output $asset
$temporary = "$destination.download"
$uri = "https://github.com/google/osv-scanner/releases/download/$version/$asset"

try {
    Invoke-WebRequest -Uri $uri -OutFile $temporary -MaximumRedirection 5
    $actual = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $expected) {
        throw "OSV Scanner digest mismatch: expected $expected, got $actual"
    }
    Move-Item -LiteralPath $temporary -Destination $destination -Force
    if ($IsLinux) {
        & chmod 0755 $destination
        if ($LASTEXITCODE -ne 0) {
            throw 'chmod failed for OSV Scanner.'
        }
    }
    Write-Output $destination
} finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}
