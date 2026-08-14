# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Input,
    [Parameter(Mandatory = $true)][string]$Output,
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

$inputPath = [IO.Path]::GetFullPath($Input)
$outputPath = [IO.Path]::GetFullPath($Output)
$toolPath = [IO.Path]::GetFullPath($EvidenceTool)
if ($inputPath -eq $outputPath) {
    throw 'PHASE17_SANITIZER_PATH_OVERLAP_REJECTED'
}
Assert-RegularFile -Path $inputPath
Assert-RegularFile -Path $toolPath
if (Test-Path -LiteralPath $outputPath) {
    throw 'PHASE17_SANITIZER_OUTPUT_EXISTS'
}
$outputDirectory = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}
$directoryItem = Get-Item -LiteralPath $outputDirectory -Force
if ((-not $directoryItem.PSIsContainer) -or ($null -ne $directoryItem.LinkType)) {
    throw 'PHASE17_SANITIZER_OUTPUT_DIRECTORY_REJECTED'
}

$toolOutput = @(& $toolPath '-sanitize-v3-input' $inputPath '-sanitize-v3-output' $outputPath 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw 'PHASE17_SANITIZER_TOOL_REJECTED'
}
Assert-RegularFile -Path $outputPath
[ordered]@{ schema = 'kurdistan-phase17-field-sanitizer-result-v2'; status = 'PASS' } | ConvertTo-Json -Compress
