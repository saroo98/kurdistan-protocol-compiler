# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$required = @(
    'owned-vps-preflight.ps1',
    'owned-vps-e2e.ps1',
    'sanitize-field-evidence.ps1'
)

foreach ($name in $required) {
    $path = Join-Path $PSScriptRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "missing Phase 17 field script: $name"
    }
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "PowerShell syntax rejected for ${name}: $($errors[0].Message)"
    }
}

$preflight = Get-Content -Raw (Join-Path $PSScriptRoot 'owned-vps-preflight.ps1')
foreach ($marker in @(
    'BatchMode=yes',
    'StrictHostKeyChecking=yes',
    'OWNER_CONTROLLED_VPS',
    'rawLogRetained',
    'ipv6Global',
    'ipv6DefaultRoute',
    'ipv6Forwarding',
    'ipv6NftPolicy',
    'ipv6External'
)) {
    if (-not $preflight.Contains($marker)) {
        throw "preflight script is missing $marker"
    }
}

$nativePreflight = Get-Content -Raw (Join-Path $root 'deploy/selfhost/native/preflight.sh')
if ($nativePreflight.Contains('fail NO_IPV6_ROUTE')) {
    throw 'native preflight still rejects valid IPv4-only self-hosted nodes'
}
foreach ($marker in @('ipv6Global', 'ipv6DefaultRoute', 'ipv6Forwarding', 'ipv6NftPolicy')) {
    if (-not $nativePreflight.Contains($marker)) {
        throw "native preflight is missing categorical IPv6 capability marker: $marker"
    }
}

$e2e = Get-Content -Raw (Join-Path $PSScriptRoot 'owned-vps-e2e.ps1')
foreach ($marker in @('go run ./cmd/phase17field', '-ssh-alias', '-relay-port', '-mode', 'field-result.json')) {
    if (-not $e2e.Contains($marker)) {
        throw "owned VPS e2e script is missing $marker"
    }
}
foreach ($placeholder in @("= 'PENDING'", 'FIELD_MATRIX_INCOMPLETE', "result = 'IN_PROGRESS'")) {
    if ($e2e.Contains($placeholder)) {
        throw "owned VPS e2e script still contains incomplete field behavior: $placeholder"
    }
}
foreach ($marker in @('RelayPort', '-relay-port')) {
    if (-not $e2e.Contains($marker)) {
        throw "owned VPS e2e script does not preserve configurable relay port marker $marker"
    }
}

$sanitizer = Get-Content -Raw (Join-Path $PSScriptRoot 'sanitize-field-evidence.ps1')
foreach ($marker in @('kurdistan-phase17-owned-vps-evidence-v2', 'campaign', 'private key', 'System.Net.IPAddress')) {
    if (-not $sanitizer.Contains($marker)) {
        throw "field sanitizer is missing $marker"
    }
}

$sanitizerTestRoot = Join-Path ([IO.Path]::GetTempPath()) ('phase17-sanitizer-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $sanitizerTestRoot | Out-Null
    $numericInputRoot = Join-Path $sanitizerTestRoot 'numeric-record'
    New-Item -ItemType Directory -Path $numericInputRoot | Out-Null
    $numericRecord = [ordered]@{
        schema = 'kurdistan-phase17-owned-vps-raw-v2'
        result = 'PASS'
        subject = [ordered]@{}
        environment = [ordered]@{ androidApi = 36 }
        checks = [ordered]@{}
        metrics = [ordered]@{ durationMs = 43413312; reconnects = 200 }
        privacy = [ordered]@{}
        limitations = @('external evidence remains')
        campaign = [ordered]@{ soakDurationMs = 43413312; soakCycles = 142 }
    }
    $numericRecord | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $numericInputRoot 'field-result.json') -Encoding utf8NoBOM
    $numericOutput = Join-Path $numericInputRoot 'safe.json'
    & (Join-Path $PSScriptRoot 'sanitize-field-evidence.ps1') -InputRoot $numericInputRoot -Output $numericOutput | Out-Null
    if (-not (Test-Path -LiteralPath $numericOutput -PathType Leaf)) {
        throw 'field sanitizer rejected an endpoint-free record containing ordinary numeric evidence'
    }

    foreach ($endpoint in @('192.0.2.10:443', 'https://198.51.100.20/check', '[2001:db8::10]:443', 'fe80::1%eth0')) {
        $inputRoot = Join-Path $sanitizerTestRoot ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $inputRoot | Out-Null
        $raw = [ordered]@{
            schema = 'kurdistan-phase17-owned-vps-raw-v2'
            result = 'PASS'
            endpoint = $endpoint
            subject = [ordered]@{}
            environment = [ordered]@{}
            checks = [ordered]@{}
            metrics = [ordered]@{}
            privacy = [ordered]@{}
            limitations = @()
            campaign = [ordered]@{}
        }
        $raw | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $inputRoot 'field-result.json') -Encoding utf8NoBOM
        $rejected = $false
        try {
            & (Join-Path $PSScriptRoot 'sanitize-field-evidence.ps1') -InputRoot $inputRoot -Output (Join-Path $inputRoot 'safe.json') | Out-Null
        } catch {
            if (-not $_.ToString().Contains('FIELD_EVIDENCE_ENDPOINT_PRESENT')) {
                throw "unexpected field-sanitizer failure: $($_.ToString())"
            }
            $rejected = $true
        }
        if (-not $rejected) { throw "field sanitizer accepted endpoint form: $endpoint" }
    }
} finally {
    Remove-Item -LiteralPath $sanitizerTestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$upgrade = Get-Content -Raw (Join-Path $root 'deploy/selfhost/native/upgrade.sh')
foreach ($marker in @(
    'recipient_registry=$data_dir/recipient-registry',
    '--recipient-registry-dir "$recipient_registry"',
    'state_digest=$(sha256sum "$state_file" | cut -d'' '' -f1)',
    'backup_file=$backup_dir/pre-upgrade-$candidate_version-$state_digest.kurd-backup',
    'backup_reused=true'
)) {
    if (-not $upgrade.Contains($marker)) {
        throw "native upgrade does not preserve the owner recipient registry: $marker"
    }
}

Write-Output 'PHASE 17 OWNED-VPS SCRIPT TESTS PASSED'
