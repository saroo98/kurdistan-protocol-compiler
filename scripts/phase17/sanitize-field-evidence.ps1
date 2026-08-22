# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][Alias('Input')][string]$RawEvidence,
    [Parameter(Mandatory = $true)][Alias('Output')][string]$SanitizedEvidence,
    [Parameter(Mandatory = $true)][string]$EvidenceTool
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($null -ne $item.LinkType) -or ($item.Length -lt 1)) {
        throw 'PHASE17_SANITIZER_REGULAR_FILE_REJECTED'
    }
}

$rawEvidencePath = [IO.Path]::GetFullPath($RawEvidence)
$sanitizedEvidencePath = [IO.Path]::GetFullPath($SanitizedEvidence)
$toolPath = [IO.Path]::GetFullPath($EvidenceTool)
if ($rawEvidencePath -eq $sanitizedEvidencePath) {
    throw 'PHASE17_SANITIZER_PATH_OVERLAP_REJECTED'
}
Assert-RegularFile -Path $rawEvidencePath
Assert-RegularFile -Path $toolPath
if (Test-Path -LiteralPath $sanitizedEvidencePath) {
    throw 'PHASE17_SANITIZER_OUTPUT_EXISTS'
}
$outputDirectory = Split-Path -Parent $sanitizedEvidencePath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}
$directoryItem = Get-Item -LiteralPath $outputDirectory -Force
if ((-not $directoryItem.PSIsContainer) -or ($null -ne $directoryItem.LinkType)) {
    throw 'PHASE17_SANITIZER_OUTPUT_DIRECTORY_REJECTED'
}

$toolOutput = @(& $toolPath '-sanitize-v3-input' $rawEvidencePath '-sanitize-v3-output' $sanitizedEvidencePath 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw 'PHASE17_SANITIZER_TOOL_REJECTED'
}
Assert-RegularFile -Path $sanitizedEvidencePath
[ordered]@{ schema = 'kurdistan-phase17-field-sanitizer-result-v2'; status = 'PASS' } | ConvertTo-Json -Compress
