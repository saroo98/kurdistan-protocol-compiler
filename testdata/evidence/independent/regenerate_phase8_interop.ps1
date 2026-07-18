# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd([IO.Path]::DirectorySeparatorChar)
$venv = Join-Path $tempRoot 'kurdistan-phase8-interop-py312'
$generated = Join-Path $tempRoot 'kurdistan-phase8-independent-interop-report.json'
$lock = Join-Path $PSScriptRoot 'requirements-win-amd64-py312.lock'
$script = Join-Path $PSScriptRoot 'phase8_interop.py'
$expected = Join-Path $repo 'testdata\evidence\phase8-independent-interop-report.json'

if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName($venv), $tempRoot) -or
    [IO.Path]::GetFileName($venv) -ne 'kurdistan-phase8-interop-py312') {
    throw "Refusing to manage an unexpected virtual-environment path: $venv"
}

if (Test-Path -LiteralPath $venv) {
    Remove-Item -Recurse -Force -LiteralPath $venv
}
if (Test-Path -LiteralPath $generated) {
    Remove-Item -Force -LiteralPath $generated
}

py -3.12 -m venv $venv
$python = Join-Path $venv 'Scripts\python.exe'
& $python -m pip install --disable-pip-version-check --no-cache-dir --require-hashes -r $lock
& $python $script --output $generated --compare $expected

$expectedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $expected).Hash
$generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generated).Hash
if ($expectedHash -ne $generatedHash) {
    throw "Generated report hash $generatedHash differs from committed $expectedHash"
}

Write-Output "PHASE8 INTEROP REGENERATION PASSED: $generatedHash"
