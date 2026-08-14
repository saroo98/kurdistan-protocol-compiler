# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PrivateEnvironment,
    [Parameter(Mandatory = $true)][string]$Environment,
    [Parameter(Mandatory = $true)][string]$PreflightId,
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-RegularUtf8 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -or ($null -ne $item.LinkType) -or $item.Length -lt 1 -or $item.Length -gt $MaximumBytes) {
        throw 'PHASE17_PREFLIGHT_INPUT_REJECTED'
    }
    $stream = [IO.FileStream]::new($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $item.Length -or $stream.Length -gt $MaximumBytes) {
            throw 'PHASE17_PREFLIGHT_INPUT_CHANGED'
        }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true, 4096, $true)
        try {
            $raw = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
        if ($stream.Length -ne $item.Length) {
            throw 'PHASE17_PREFLIGHT_INPUT_CHANGED'
        }
        return $raw
    } finally {
        $stream.Dispose()
    }
}

function Write-ExclusiveUtf8Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $full = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $full
    $parentItem = Get-Item -LiteralPath $parent -Force
    if ((-not $parentItem.PSIsContainer) -or ($null -ne $parentItem.LinkType) -or (Test-Path -LiteralPath $full)) {
        throw 'PHASE17_PREFLIGHT_OUTPUT_REJECTED'
    }
    $temporary = Join-Path $parent ('.preflight-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $raw = ($Value | ConvertTo-Json -Depth 4 -Compress) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($raw)
    try {
        $stream = [IO.FileStream]::new(
            $temporary,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        Move-Item -LiteralPath $temporary -Destination $full
        $published = Get-Item -LiteralPath $full -Force
        if ($published.PSIsContainer -or ($null -ne $published.LinkType) -or $published.Length -ne $bytes.Length) {
            throw 'PHASE17_PREFLIGHT_OUTPUT_PUBLICATION_REJECTED'
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

$privateRaw = Read-RegularUtf8 -Path $PrivateEnvironment -MaximumBytes (64KB)
$environmentRaw = Read-RegularUtf8 -Path $Environment -MaximumBytes (64KB)
if ($PreflightId -cnotmatch '^[0-9a-f]{32}$') {
    throw 'PHASE17_PREFLIGHT_ID_REJECTED'
}
$environmentBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($environmentRaw)
$environmentHasher = [Security.Cryptography.SHA256]::Create()
try {
    $environmentDigest = ([BitConverter]::ToString($environmentHasher.ComputeHash($environmentBytes))).Replace('-', '').ToLowerInvariant()
} finally {
    $environmentHasher.Dispose()
    [Array]::Clear($environmentBytes, 0, $environmentBytes.Length)
}
$private = ConvertFrom-Json -InputObject $privateRaw
$environmentDocument = ConvertFrom-Json -InputObject $environmentRaw
if ($environmentDocument -is [Array]) {
    throw 'PHASE17_PREFLIGHT_ENVIRONMENT_REJECTED_ARRAY'
}
$outputFull = [IO.Path]::GetFullPath($Output)
$outputParent = Get-Item -LiteralPath (Split-Path -Parent $outputFull) -Force
if ((-not $outputParent.PSIsContainer) -or ($null -ne $outputParent.LinkType) -or (Test-Path -LiteralPath $outputFull)) {
    throw 'PHASE17_PREFLIGHT_OUTPUT_REJECTED'
}
foreach ($field in @('schema', 'sshAlias', 'sshExecutable', 'powershellExecutable')) {
    if ($null -eq $private.PSObject.Properties[$field]) {
        throw 'PHASE17_PREFLIGHT_PRIVATE_ENVIRONMENT_REJECTED'
    }
}
foreach ($field in @('schema', 'vpsOs', 'vpsArch')) {
    if ($null -eq $environmentDocument.PSObject.Properties[$field]) {
        throw ('PHASE17_PREFLIGHT_ENVIRONMENT_REJECTED_' + $field.ToUpperInvariant())
    }
}
if ([string]$private.schema -cne 'kurdistan-phase17-private-environment-v1' -or
    [string]$environmentDocument.schema -cne 'kurdistan-phase17-environment-context-v1' -or
    [string]$environmentDocument.vpsOs -cne 'linux' -or [string]$environmentDocument.vpsArch -cne 'amd64' -or
    [string]::IsNullOrWhiteSpace([string]$private.sshAlias) -or
    [string]::IsNullOrWhiteSpace([string]$private.sshExecutable) -or
    [string]::IsNullOrWhiteSpace([string]$private.powershellExecutable)) {
    throw 'PHASE17_PREFLIGHT_ENVIRONMENT_REJECTED'
}

$remote = @'
set -eu
has() { command -v "$1" >/dev/null 2>&1 && printf true || printf false; }
os=false; [ "$(uname -s)" = Linux ] && os=true
arch=false; case "$(uname -m)" in x86_64) arch=true ;; esac
systemd=false; command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1 && systemd=true
networkd=false; command -v networkctl >/dev/null 2>&1 && systemctl cat systemd-networkd.service >/dev/null 2>&1 && networkd=true
tun=false; [ -c /dev/net/tun ] && tun=true
time_sync=false; [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" = yes ] && time_sync=true
memory_kib=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)
disk_kib=$(df -Pk /var/lib | awk 'NR == 2 {print $4}')
memory=false; [ "${memory_kib:-0}" -ge 786432 ] && memory=true
disk=false; [ "${disk_kib:-0}" -ge 524288 ] && disk=true
ipv4=false; ip -o -4 route show default | grep -q . && ipv4=true
ipv6Global=false; ip -o -6 addr show scope global | grep -qv ' tentative' && ipv6Global=true
ipv6DefaultRoute=false; ip -o -6 route show default | grep -q . && ipv6DefaultRoute=true
ipv6Forwarding=false; [ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || true)" = 1 ] && ipv6Forwarding=true
ipv6NftPolicy=false; rules=$(sudo -n nft list table inet kurd_node 2>/dev/null || true); printf '%s' "$rules" | grep -F 'ip6 saddr fd4b:7572:6400::/64' >/dev/null && printf '%s' "$rules" | grep -F 'masquerade' >/dev/null && ipv6NftPolicy=true
ipv6External=false; command -v ping >/dev/null 2>&1 && ping -6 -n -c 1 -W 5 2606:4700:4700::1111 >/dev/null 2>&1 && ipv6External=true
ipv6=false; [ "$ipv6Global:$ipv6DefaultRoute:$ipv6Forwarding:$ipv6NftPolicy:$ipv6External" = true:true:true:true:true ] && ipv6=true
sudo_ready=false; sudo -n true >/dev/null 2>&1 && sudo_ready=true
remote_epoch=$(date -u +%s)
case "$remote_epoch" in ''|*[!0-9]*) exit 1 ;; esac
printf '{"schema":"kurdistan-phase17-owned-vps-preflight-v1","hostClass":"OWNER_CONTROLLED_VPS","os":%s,"arch":%s,"systemd":%s,"networkd":%s,"nft":%s,"unbound":%s,"tun":%s,"timeSynchronized":%s,"memory":%s,"disk":%s,"ipv4":%s,"ipv6":%s,"ipv6Global":%s,"ipv6DefaultRoute":%s,"ipv6Forwarding":%s,"ipv6NftPolicy":%s,"ipv6External":%s,"sudo":%s,"remoteEpoch":%s,"rawLogRetained":false}\n' \
  "$os" "$arch" "$systemd" "$networkd" "$(has nft)" "$(has unbound-checkconf)" "$tun" "$time_sync" "$memory" "$disk" "$ipv4" "$ipv6" "$ipv6Global" "$ipv6DefaultRoute" "$ipv6Forwarding" "$ipv6NftPolicy" "$ipv6External" "$sudo_ready" "$remote_epoch"
'@

$global:LASTEXITCODE = 0
$hostClockBefore = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$clockProbe = [Diagnostics.Stopwatch]::StartNew()
$sshResult = & ([string]$private.sshExecutable) '-o' 'BatchMode=yes' '-o' 'StrictHostKeyChecking=yes' '-o' 'ConnectTimeout=15' '--' ([string]$private.sshAlias) $remote 2>&1
$sshExitCode = $global:LASTEXITCODE
$clockProbe.Stop()
$hostClockAfter = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ($sshExitCode -ne 0) {
    throw 'PHASE17_PREFLIGHT_SSH_FAILED'
}
try {
    $record = ($sshResult -join "`n") | ConvertFrom-Json
} catch {
    throw 'PHASE17_PREFLIGHT_REMOTE_RECORD_REJECTED'
}
foreach ($field in @('schema', 'hostClass', 'os', 'arch', 'systemd', 'networkd', 'nft', 'unbound', 'tun', 'timeSynchronized', 'memory', 'disk', 'ipv4', 'ipv6', 'ipv6Global', 'ipv6DefaultRoute', 'ipv6Forwarding', 'ipv6NftPolicy', 'ipv6External', 'sudo', 'remoteEpoch', 'rawLogRetained')) {
    if ($null -eq $record.PSObject.Properties[$field]) {
        throw 'PHASE17_PREFLIGHT_REMOTE_RECORD_REJECTED'
    }
}
$remoteEpoch = 0L
if (-not [long]::TryParse([string]$record.remoteEpoch, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$remoteEpoch) -or
    $clockProbe.Elapsed -gt [TimeSpan]::FromSeconds(30) -or
    $remoteEpoch -lt ($hostClockBefore - 5) -or $remoteEpoch -gt ($hostClockAfter + 5)) {
    throw 'PHASE17_PREFLIGHT_HOST_CLOCK_REJECTED'
}
foreach ($field in @('os', 'arch', 'systemd', 'networkd', 'nft', 'unbound', 'tun', 'timeSynchronized', 'memory', 'disk', 'ipv4', 'sudo')) {
    if ($record.$field -ne $true) {
        throw ('PHASE17_PREFLIGHT_CAPABILITY_REJECTED_' + $field.ToUpperInvariant())
    }
}
if ([string]$record.schema -cne 'kurdistan-phase17-owned-vps-preflight-v1' -or
    [string]$record.hostClass -cne 'OWNER_CONTROLLED_VPS' -or $record.rawLogRetained -ne $false) {
    throw 'PHASE17_PREFLIGHT_REMOTE_RECORD_REJECTED'
}

$safe = [ordered]@{
    schema = 'kurdistan-phase17-owned-vps-preflight-v1'
    preflightId = $PreflightId
    environmentSha256 = $environmentDigest
    status = 'PASS'
    hostClass = 'OWNER_CONTROLLED_VPS'
    os = 'linux'
    arch = 'amd64'
    systemd = $true
    networkd = $true
    nft = $true
    unbound = $true
    tun = $true
    timeSynchronized = $true
    hostClockToVps = $true
    memory = $true
    disk = $true
    ipv4 = $true
    ipv6 = [bool]$record.ipv6
    ipv6Global = [bool]$record.ipv6Global
    ipv6DefaultRoute = [bool]$record.ipv6DefaultRoute
    ipv6Forwarding = [bool]$record.ipv6Forwarding
    ipv6NftPolicy = [bool]$record.ipv6NftPolicy
    ipv6External = [bool]$record.ipv6External
    sudo = $true
    rawLogRetained = $false
}
Write-ExclusiveUtf8Json -Value $safe -Path $Output
Write-Output 'PHASE17_OWNER_VPS_PREFLIGHT_PASS'
