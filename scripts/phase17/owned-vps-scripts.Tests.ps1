# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$required = @(
    'build-qualification-candidate.ps1',
    'owned-vps-preflight.ps1',
    'owned-vps-e2e.ps1',
    'run-qualified-campaign.ps1',
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
    'ipv6External',
    'hostClockToVps',
    'preflightId',
    'environmentSha256',
    'remoteEpoch'
)) {
    if (-not $preflight.Contains($marker)) {
        throw "preflight script is missing $marker"
    }
}
foreach ($marker in @('[string]$PrivateEnvironment', '[string]$Environment', '[string]$PreflightId', '[string]$Output')) {
    if (-not $preflight.Contains($marker)) {
        throw "preflight script is missing private-file interface: $marker"
    }
}
foreach ($forbidden in @('[string]$SshAlias', '[string]$EvidenceRoot', '[string]$SshExecutable', 'Set-Content')) {
    if ($preflight.Contains($forbidden)) {
        throw "preflight script retains an unsafe interface or publication primitive: $forbidden"
    }
}

$preflightFixture = Join-Path ([IO.Path]::GetTempPath()) ('phase17-preflight-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $preflightFixture | Out-Null
try {
    $fakeSsh = Join-Path $preflightFixture 'fake-ssh.ps1'
    $privateEnvironment = Join-Path $preflightFixture 'private-environment.json'
    $environmentContext = Join-Path $preflightFixture 'environment.json'
    $preflightResult = Join-Path $preflightFixture 'preflight.json'
    [IO.File]::WriteAllText($fakeSsh, @'
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
$epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
Write-Output ('{"schema":"kurdistan-phase17-owned-vps-preflight-v1","hostClass":"OWNER_CONTROLLED_VPS","os":true,"arch":true,"systemd":true,"networkd":true,"nft":true,"unbound":true,"tun":true,"timeSynchronized":true,"memory":true,"disk":true,"ipv4":true,"ipv6":false,"ipv6Global":false,"ipv6DefaultRoute":false,"ipv6Forwarding":false,"ipv6NftPolicy":false,"ipv6External":false,"sudo":true,"remoteEpoch":' + $epoch + ',"rawLogRetained":false}')
'@, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($privateEnvironment, ([ordered]@{
        schema = 'kurdistan-phase17-private-environment-v1'
        sshAlias = 'fixture-node'
        avdName = 'fixture-avd'
        deviceSerial = ''
        probeUrlFile = (Join-Path $preflightFixture 'probe-url.txt')
        probeDigestFile = (Join-Path $preflightFixture 'probe-digest.txt')
        ipv6ProbeAddress = '2001:db8::1'
        relayPort = 8443
        pythonExecutable = $fakeSsh
        adbExecutable = $fakeSsh
        sshExecutable = $fakeSsh
        scpExecutable = $fakeSsh
        powershellExecutable = $fakeSsh
    } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($environmentContext, ([ordered]@{
        schema = 'kurdistan-phase17-environment-context-v1'
        vpsOs = 'linux'
        vpsArch = 'amd64'
    } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    $preflightId = '11111111111111111111111111111111'
    $resultLine = & (Join-Path $PSScriptRoot 'owned-vps-preflight.ps1') -PrivateEnvironment $privateEnvironment -Environment $environmentContext -PreflightId $preflightId -Output $preflightResult
    if ($resultLine -cne 'PHASE17_OWNER_VPS_PREFLIGHT_PASS') {
        throw 'preflight fixture did not emit the categorical PASS marker'
    }
    $result = Get-Content -LiteralPath $preflightResult -Raw | ConvertFrom-Json
    $environmentDigest = (Get-FileHash -LiteralPath $environmentContext -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($result.preflightId -cne $preflightId -or $result.environmentSha256 -cne $environmentDigest -or
        $result.status -cne 'PASS' -or $result.hostClass -cne 'OWNER_CONTROLLED_VPS' -or
        $result.hostClockToVps -ne $true -or $result.rawLogRetained -ne $false) {
        throw 'preflight fixture did not publish sanitized PASS evidence'
    }
    try {
        & (Join-Path $PSScriptRoot 'owned-vps-preflight.ps1') -PrivateEnvironment $privateEnvironment -Environment $environmentContext -PreflightId $preflightId -Output $preflightResult | Out-Null
        throw 'preflight overwrote an existing result'
    } catch {
        if ($_.Exception.Message -cne 'PHASE17_PREFLIGHT_OUTPUT_REJECTED') {
            throw
        }
    }
} finally {
    Remove-Item -LiteralPath $preflightFixture -Recurse -Force
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
foreach ($marker in @('candidate-A\QHS\scripts\run-qualified-campaign.ps1', 'CandidateRoot', 'TrustedPublicKey', 'PriorStressResult', 'PrivateEnvironment', 'EnvironmentSalt')) {
    if (-not $e2e.Contains($marker)) {
        throw "owned VPS e2e script is missing $marker"
    }
}
if ($e2e.Contains('go run')) {
    throw 'owned VPS e2e script still permits a dynamically compiled qualified runner'
}
foreach ($placeholder in @("= 'PENDING'", 'FIELD_MATRIX_INCOMPLETE', "result = 'IN_PROGRESS'")) {
    if ($e2e.Contains($placeholder)) {
        throw "owned VPS e2e script still contains incomplete field behavior: $placeholder"
    }
}
foreach ($forbidden in @('[string]$SshAlias', '[string]$AvdName', '[string]$DeviceSerial', '[string]$ProbeUrlFile', '[int]$RelayPort')) {
    if ($e2e.Contains($forbidden)) {
        throw "owned VPS e2e command line still carries a private selector: $forbidden"
    }
}

$builder = Get-Content -Raw (Join-Path $PSScriptRoot 'build-qualification-candidate.ps1')
foreach ($marker in @(
    'candidate-A',
    'candidate-B',
    'worktree',
    "'candidate', 'validate'",
    "'source', 'create'",
    "'candidate', 'create'",
    'IsReadOnly',
    "'status', '--porcelain=v1', '--untracked-files=all'",
    "('p17q-' +",
    'Remove-QualificationWorktree',
    "'-c', 'core.longpaths=true'",
    "'--no-daemon'",
    "'-Pkotlin.compiler.execution.strategy=in-process'",
    'throw $primaryFailure',
    'PHASE17_BUILD_CLEANUP_FAILED'
)) {
    if (-not $builder.Contains($marker)) {
        throw "qualification candidate builder is missing $marker"
    }
}
if ($builder.Contains('go run')) {
    throw 'qualification candidate builder contains go run'
}
if ($builder.Contains('--untracked-files=no')) {
    throw 'qualification candidate builder ignores untracked source inputs'
}

$qualified = Get-Content -Raw (Join-Path $PSScriptRoot 'run-qualified-campaign.ps1')
foreach ($marker in @(
    "'attempt', 'begin'",
    "'attempt', 'finish'",
    "'attempt', 'close'",
    "'soak', 'consume'",
    'candidate-A',
    'PHASE17_CAMPAIGN_EXACT_RESULT_MISSING',
    'RUNNER_LAUNCH_FAILED',
    'RUNNER_RESULT_MISSING',
    'RUNNER_RESULT_AMBIGUOUS',
    'RUNNER_RESULT_INVALID',
    'EndsWith(',
    '& $runner @runnerArguments 2> $null',
    "'-wrapper', `$PSCommandPath",
    "'-wrapper-entry', 'scripts/run-qualified-campaign.ps1'",
    "'-private-environment', `$PrivateEnvironment",
    "'-environment-salt', `$EnvironmentSalt",
    "'candidate', 'artifact', 'verify'",
    "'scripts/owned-vps-preflight.ps1'",
    "'-preflight', `$preflight",
    "'-preflight-entry', 'scripts/owned-vps-preflight.ps1'"
)) {
    if (-not $qualified.Contains($marker)) {
        throw "qualified campaign wrapper is missing $marker"
    }
}
$preflightVerifyIndex = $qualified.IndexOf("'candidate', 'artifact', 'verify'", [StringComparison]::Ordinal)
$preflightRunIndex = $qualified.IndexOf('& $preflight', [StringComparison]::Ordinal)
$soakConsumeIndex = $qualified.IndexOf("'soak', 'consume'", [StringComparison]::Ordinal)
$attemptBeginIndex = $qualified.IndexOf("'attempt', 'begin'", [StringComparison]::Ordinal)
if ($preflightVerifyIndex -lt 0 -or $preflightRunIndex -lt 0 -or $soakConsumeIndex -lt 0 -or $attemptBeginIndex -lt 0 -or
    $preflightVerifyIndex -ge $preflightRunIndex -or $preflightRunIndex -ge $soakConsumeIndex -or $preflightRunIndex -ge $attemptBeginIndex) {
    throw 'qualified campaign does not verify and run preflight before authorization consumption and attempt begin'
}
foreach ($forbidden in @('runner.stdout.tmp', 'runner.stderr.tmp', 'PHASE17_CAMPAIGN_EPHEMERAL_OUTPUT_RETENTION_REJECTED')) {
    if ($qualified.Contains($forbidden)) {
        throw "qualified campaign wrapper retains crash-surviving child output through $forbidden"
    }
}
foreach ($forbidden in @("'-ssh-alias',", "'-avd-name',", "'-device-serial',", "'-probe-url-file',", "'-probe-digest-file',", "'-python',", "'-adb',", "'-ssh',", "'-scp',", "'-relay-port',")) {
    if ($qualified.Contains($forbidden)) {
        throw "qualified campaign command line still carries a private selector: $forbidden"
    }
}
foreach ($forbidden in @('go run', 'Sort-Object LastWriteTimeUtc', 'Select-Object -First 1')) {
    if ($qualified.Contains($forbidden)) {
        throw "qualified campaign wrapper contains forbidden behavior: $forbidden"
    }
}

$sanitizer = Get-Content -Raw (Join-Path $PSScriptRoot 'sanitize-field-evidence.ps1')
foreach ($marker in @('-sanitize-v3-input', '-sanitize-v3-output', 'EvidenceTool', 'PHASE17_SANITIZER_OUTPUT_EXISTS')) {
    if (-not $sanitizer.Contains($marker)) {
        throw "field sanitizer is missing $marker"
    }
}
foreach ($forbidden in @('Sort-Object LastWriteTimeUtc', 'Get-ChildItem -Recurse', 'kurdistan-phase17-owned-vps-evidence-v2')) {
    if ($sanitizer.Contains($forbidden)) {
        throw "field sanitizer contains obsolete or ambiguous behavior: $forbidden"
    }
}

$upgrade = Get-Content -Raw (Join-Path $root 'deploy/selfhost/native/upgrade.sh')
foreach ($marker in @(
    'recipient_registry=$data_dir/recipient-registry',
    '--recipient-registry-dir "$recipient_registry"',
    'state_digest=$(sha256sum "$state_file" | cut -d'' '' -f1)',
    'backup_file=$backup_dir/pre-upgrade-$candidate_version-$state_digest.kurd-backup',
    'backup_reused=true',
    'node_state_transition()',
    '[ "$status" -eq 0 ] || [ "$status" -eq 7 ]',
    'node_state_transition drain || fail DRAIN_FAILED',
    'node_state_transition resume || fail RESUME_FAILED',
    'stage_candidate_bridge()',
    'stage_candidate_package()',
    'verify_candidate_package()',
    'verify_candidate_bridge()',
    'cleanup_candidate_bridge()',
    'cleanup_candidate_bridge_bounded()',
    'candidate_kurdctl_digest=$(sed -n',
    'candidate_inventory_digest=$(sha256sum SHA256SUMS',
    'candidate_package_dir=$candidate_bridge_dir/package',
    'cp -R -- "$script_dir/." "$candidate_package_dir/"',
    'candidate_bridge_digest=$candidate_kurdctl_digest',
    'preinstall_kurdctl=$candidate_bridge',
    'verify_candidate_bridge || fail CANDIDATE_BRIDGE_INVALID',
    'trap ''cleanup_and_exit 143'' TERM',
    'trap ''rollback_and_exit 143'' TERM',
    '[ "$installed_kurdctl_digest" = "$candidate_kurdctl_digest" ]'
)) {
    if (-not $upgrade.Contains($marker)) {
        throw "native upgrade does not preserve the owner recipient registry: $marker"
    }
}

Write-Output 'PHASE 17 OWNED-VPS SCRIPT TESTS PASSED'
