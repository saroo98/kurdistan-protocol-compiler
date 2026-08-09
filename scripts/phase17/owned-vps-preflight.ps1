# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$SshAlias,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot,

    [string]$SshExecutable = 'ssh'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-StrictSsh {
    param([Parameter(Mandatory = $true)][string]$RemoteCommand)
    $output = & $SshExecutable '-o' 'BatchMode=yes' '-o' 'StrictHostKeyChecking=yes' '-o' 'ConnectTimeout=15' '--' $SshAlias $RemoteCommand 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw 'owned VPS preflight SSH failed'
    }
    return ($output -join "`n")
}

$runId = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$runRoot = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) $runId
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

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
printf '{"schema":"kurdistan-phase17-owned-vps-preflight-v1","hostClass":"OWNER_CONTROLLED_VPS","os":%s,"arch":%s,"systemd":%s,"networkd":%s,"nft":%s,"unbound":%s,"tun":%s,"timeSynchronized":%s,"memory":%s,"disk":%s,"ipv4":%s,"ipv6":%s,"ipv6Global":%s,"ipv6DefaultRoute":%s,"ipv6Forwarding":%s,"ipv6NftPolicy":%s,"ipv6External":%s,"sudo":%s,"rawLogRetained":false}\n' \
  "$os" "$arch" "$systemd" "$networkd" "$(has nft)" "$(has unbound-checkconf)" "$tun" "$time_sync" "$memory" "$disk" "$ipv4" "$ipv6" "$ipv6Global" "$ipv6DefaultRoute" "$ipv6Forwarding" "$ipv6NftPolicy" "$ipv6External" "$sudo_ready"
'@

$raw = Invoke-StrictSsh -RemoteCommand $remote
$record = $raw | ConvertFrom-Json
$requiredTrue = @('os', 'arch', 'systemd', 'networkd', 'nft', 'unbound', 'tun', 'timeSynchronized', 'memory', 'disk', 'ipv4', 'sudo')
foreach ($field in $requiredTrue) {
    if ($record.$field -ne $true) {
        throw "owned VPS preflight rejected capability: $field"
    }
}
if ($record.schema -ne 'kurdistan-phase17-owned-vps-preflight-v1' -or $record.hostClass -ne 'OWNER_CONTROLLED_VPS' -or $record.rawLogRetained -ne $false) {
    throw 'owned VPS preflight record rejected'
}

$safe = [ordered]@{
    schema = $record.schema
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
$safe | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $runRoot 'preflight.json') -Encoding utf8NoBOM
[ordered]@{ schema = 'kurdistan-phase17-owned-vps-preflight-result-v1'; status = 'PASS'; runId = $runId } | ConvertTo-Json -Compress
