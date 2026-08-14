# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputRoot,
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$files = @(Get-ChildItem -LiteralPath $InputRoot -Recurse -Filter 'field-result.json' -File | Sort-Object LastWriteTimeUtc -Descending)
if ($files.Count -eq 0) { throw 'FIELD_EVIDENCE_MISSING' }
$raw = Get-Content -Raw -LiteralPath $files[0].FullName
$lower = $raw.ToLowerInvariant()
foreach ($marker in @('private key', 'begin openssh', 'ssh-rsa', 'ssh-ed25519', 'password', 'passphrase', 'bearer token', 'c:\users\', '/home/')) {
    if ($lower.Contains($marker)) { throw 'FIELD_EVIDENCE_SENSITIVE' }
}
$ipCandidates = [regex]::Matches($raw, '[0-9A-Fa-f:.%]+')
foreach ($match in $ipCandidates) {
    $candidate = $match.Value
    $zone = $candidate.IndexOf('%')
    if ($zone -ge 0) { $candidate = $candidate.Substring(0, $zone) }
    if (-not $candidate.Contains('.') -and -not $candidate.Contains(':')) { continue }
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($candidate, [ref]$parsed)) { throw 'FIELD_EVIDENCE_ENDPOINT_PRESENT' }
    if (@($candidate.ToCharArray() | Where-Object { $_ -eq ':' }).Count -eq 1) {
        $addressHost = $candidate.Substring(0, $candidate.IndexOf(':'))
        if ([System.Net.IPAddress]::TryParse($addressHost, [ref]$parsed)) { throw 'FIELD_EVIDENCE_ENDPOINT_PRESENT' }
    }
}
$record = $raw | ConvertFrom-Json
if ($record.schema -ne 'kurdistan-phase17-owned-vps-raw-v2' -or $record.result -ne 'PASS') { throw 'FIELD_EVIDENCE_INCOMPLETE' }
$safe = [ordered]@{
    schema = 'kurdistan-phase17-owned-vps-evidence-v2'
    result = 'PASS'
    subject = $record.subject
    environment = $record.environment
    checks = $record.checks
    metrics = $record.metrics
    privacy = $record.privacy
    limitations = @($record.limitations)
    campaign = $record.campaign
}
$destination = [IO.Path]::GetFullPath($Output)
$directory = Split-Path -Parent $destination
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$temporary = Join-Path $directory ('.phase17-field-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    $safe | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding utf8NoBOM
    Move-Item -LiteralPath $temporary -Destination $destination -Force
} finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}
[ordered]@{ schema = 'kurdistan-phase17-field-sanitizer-result-v1'; status = 'PASS' } | ConvertTo-Json -Compress
