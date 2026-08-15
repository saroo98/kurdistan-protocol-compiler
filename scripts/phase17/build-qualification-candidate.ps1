# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$Commit,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$BaselineCommit,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$')]
    [string]$ExpectedRepository,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+$')]
    [string]$AssuranceRunId,
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$AssuranceRunAttempt,
    [Parameter(Mandatory = $true)]
    [string]$EngineeringCandidateRoot,
    [Parameter(Mandatory = $true)]
    [string]$EngineeringAssuranceRoot,
    [Parameter(Mandatory = $true)]
    [string]$EngineeringProvenance,
    [Parameter(Mandatory = $true)]
    [string]$EngineeringComparison,
    [ValidatePattern('^[A-Za-z0-9_./-]{1,200}$')]
    [string]$ExpectedMainRef = 'origin/main'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = [IO.Path]::GetFullPath((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$qualificationRoot = Join-Path $repoRoot '.tools\phase17\qualification'
$candidateRoot = Join-Path (Join-Path $qualificationRoot 'candidates') $Commit
$candidateA = Join-Path $candidateRoot 'candidate-A'
$candidateB = Join-Path $candidateRoot 'candidate-B'
$comparisonPath = Join-Path $candidateRoot 'candidate-comparison.json'
$manifestPath = Join-Path $candidateRoot 'candidate-manifest.json'
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('p17q-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
$worktreeA = Join-Path $temporaryRoot 'source-a'
$worktreeB = Join-Path $temporaryRoot 'source-b'

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Failure
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $Failure
    }
}

function Get-GitText {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Failure
    )
    $lines = @(& git -C $Root @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw $Failure
    }
    return (($lines -join "`n").Trim())
}

function Assert-SafeRelativePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path) -or $Path.Contains('\') -or $Path.Contains("`r") -or $Path.Contains("`n") -or $Path.Contains([char]0)) {
        throw 'PHASE17_BUILD_RELATIVE_PATH_REJECTED'
    }
    $normalized = [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
    $prefix = $repoRoot.TrimEnd('\') + '\'
    if (-not $normalized.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PHASE17_BUILD_RELATIVE_PATH_ESCAPES_ROOT'
    }
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    $childFull = [IO.Path]::GetFullPath($Child)
    if (-not $childFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PHASE17_BUILD_PATH_SCOPE_REJECTED'
    }
}

function Remove-QualificationWorktree {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$Worktree
    )
    $arguments = @('-c', 'core.longpaths=true', '-C', $RepositoryRoot, 'worktree', 'remove', '--force', $Worktree)
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $null = & git @arguments 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
}

function Remove-QualificationTree {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    Assert-ChildPath -Parent $Parent -Child $Child
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            if (Test-Path -LiteralPath $Child) {
                Remove-Item -LiteralPath $Child -Recurse -Force -ErrorAction Stop
            }
            if (-not (Test-Path -LiteralPath $Child)) {
                return $true
            }
        } catch {
            if ($attempt -eq 6) {
                return $false
            }
        }
        Start-Sleep -Milliseconds (250 * $attempt)
    }
    return $false
}

function Copy-ExactFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw 'PHASE17_BUILD_SOURCE_FILE_MISSING'
    }
    $directory = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    Copy-Item -LiteralPath $Source -Destination $Destination
}

function Write-Utf8NoBomJson {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Destination,
        [ValidateRange(2, 100)][int]$Depth = 20
    )
    $json = $Value | ConvertTo-Json -Depth $Depth
    [IO.File]::WriteAllText($Destination, $json + "`n", [Text.UTF8Encoding]::new($false))
}

function Write-ApkNativeInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Apk,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Apk)
    try {
        $entries = @($archive.Entries | Where-Object { $_.FullName.StartsWith('lib/', [StringComparison]::Ordinal) -and $_.FullName.EndsWith('.so', [StringComparison]::Ordinal) } | Sort-Object FullName)
        if ($entries.Count -lt 1) {
            throw 'PHASE17_BUILD_NATIVE_LIBRARY_INVENTORY_EMPTY'
        }
        $inventory = @()
        foreach ($entry in $entries) {
            $stream = $entry.Open()
            $hash = [Security.Cryptography.SHA256]::Create()
            try {
                $digest = ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
            } finally {
                $hash.Dispose()
                $stream.Dispose()
            }
            $inventory += [ordered]@{
                path = $entry.FullName
                size = [long]$entry.Length
                sha256 = $digest
            }
        }
        Write-Utf8NoBomJson -Value ([ordered]@{
            schema = 'kurdistan-phase17-apk-native-inventory-v1'
            entries = @($inventory)
        }) -Destination $Destination -Depth 6
    } finally {
        $archive.Dispose()
    }
}

function Copy-TreeFiles {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $sourceFull = [IO.Path]::GetFullPath($Source)
    foreach ($file in @(Get-ChildItem -LiteralPath $sourceFull -File -Recurse | Sort-Object FullName)) {
        $relative = [IO.Path]::GetRelativePath($sourceFull, $file.FullName)
        Copy-ExactFile -Source $file.FullName -Destination (Join-Path $Destination $relative)
    }
}

function Build-CandidateRoot {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('a', 'b')][string]$Builder,
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Tree,
        [Parameter(Mandatory = $true)][string]$SourceDateEpoch
    )
    foreach ($directory in @('PQS', 'QHS', 'QWS', 'OVS')) {
        New-Item -ItemType Directory -Path (Join-Path $OutputRoot $directory) | Out-Null
    }
    $cacheRoot = Join-Path $temporaryRoot ('cache-' + $Builder)
    $env:GOCACHE = Join-Path $cacheRoot 'go-build'
    $env:GOMODCACHE = Join-Path $cacheRoot 'go-mod'
    $env:GRADLE_USER_HOME = Join-Path $cacheRoot 'gradle'
    $env:CGO_ENABLED = '0'
    $env:SOURCE_DATE_EPOCH = $SourceDateEpoch
    $env:TZ = 'UTC'
    New-Item -ItemType Directory -Path $env:GOCACHE, $env:GOMODCACHE, $env:GRADLE_USER_HOME | Out-Null

    $commands = [ordered]@{
        'phase17field.exe' = './cmd/phase17field'
        'phase17qual.exe' = './cmd/phase17qual'
        'phase17scan.exe' = './cmd/phase17scan'
        'phase17boundary.exe' = './cmd/phase17boundary'
        'kurdpackage.exe' = './cmd/kurdpackage'
        'phase17evidence.exe' = './cmd/phase17evidence'
        'phase17verify.exe' = './cmd/phase17verify'
        'assure.exe' = './cmd/assure'
    }
    Push-Location $SourceRoot
    try {
        foreach ($entry in $commands.GetEnumerator()) {
            $output = Join-Path (Join-Path $OutputRoot 'QHS\bin') $entry.Key
            if ($entry.Key -in @('phase17evidence.exe', 'phase17verify.exe', 'assure.exe')) {
                $output = Join-Path (Join-Path $OutputRoot 'OVS\bin') $entry.Key
            }
            $outputDirectory = Split-Path -Parent $output
            if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
                New-Item -ItemType Directory -Path $outputDirectory | Out-Null
            }
            Invoke-Checked -FilePath 'go' -Arguments @('build', '-trimpath', '-buildvcs=false', '-ldflags=-buildid=', '-o', $output, $entry.Value) -Failure 'PHASE17_BUILD_GO_BINARY_FAILED'
        }
    } finally {
        Pop-Location
    }
    Copy-ExactFile -Source (Join-Path $OutputRoot 'QHS\bin\phase17qual.exe') -Destination (Join-Path $OutputRoot 'OVS\bin\phase17qual.exe')
    Copy-ExactFile -Source (Join-Path $OutputRoot 'QHS\bin\phase17scan.exe') -Destination (Join-Path $OutputRoot 'OVS\bin\phase17scan.exe')

    Push-Location (Join-Path $SourceRoot 'android')
    try {
        Invoke-Checked -FilePath (Join-Path $SourceRoot 'android\gradlew.bat') -Arguments @(
            'clean', ':app:assembleInternal', ':app:assembleInternalAndroidTest', 'cyclonedxBom',
            '--no-daemon', '-Pkotlin.compiler.execution.strategy=in-process',
            '--no-build-cache', '--no-configuration-cache', '--rerun-tasks'
        ) -Failure 'PHASE17_BUILD_ANDROID_FAILED'
    } finally {
        Pop-Location
    }

    $sbomPath = Join-Path $SourceRoot 'android\build\reports\cyclonedx\bom.json'
    $sbom = Get-Content -LiteralPath $sbomPath -Raw | ConvertFrom-Json
    if ($null -eq $sbom.metadata.timestamp) {
        throw 'PHASE17_BUILD_SBOM_TIMESTAMP_MISSING'
    }
    $sbom.metadata.PSObject.Properties.Remove('timestamp')
    Write-Utf8NoBomJson -Value $sbom -Destination $sbomPath -Depth 100

    $packageVersion = '0.17.0-qual.' + $Commit.Substring(0, 12)
    $packageOutput = Join-Path $temporaryRoot ('package-' + $Builder)
    New-Item -ItemType Directory -Path $packageOutput | Out-Null
    Invoke-Checked -FilePath (Join-Path $OutputRoot 'QHS\bin\kurdpackage.exe') -Arguments @(
        'build', '-root', $SourceRoot, '-out', $packageOutput, '-version', $packageVersion, '-arches', 'amd64'
    ) -Failure 'PHASE17_BUILD_NATIVE_PACKAGE_FAILED'
    $packages = @(Get-ChildItem -LiteralPath $packageOutput -Filter '*-linux-amd64.tar.gz' -File)
    if ($packages.Count -ne 1) {
        throw 'PHASE17_BUILD_NATIVE_PACKAGE_INVENTORY_REJECTED'
    }

    $pqs = Join-Path $OutputRoot 'PQS'
    $qhs = Join-Path $OutputRoot 'QHS'
    $qws = Join-Path $OutputRoot 'QWS'
    $ovs = Join-Path $OutputRoot 'OVS'
    Copy-ExactFile -Source $packages[0].FullName -Destination (Join-Path $pqs ('package\' + $packages[0].Name))
    Copy-ExactFile -Source (Join-Path $SourceRoot 'android\app\build\outputs\apk\internal\app-internal.apk') -Destination (Join-Path $pqs 'android\app-internal.apk')
    Copy-ExactFile -Source (Join-Path $SourceRoot 'android\app\build\outputs\apk\androidTest\internal\app-internal-androidTest.apk') -Destination (Join-Path $qhs 'android\app-internal-androidTest.apk')
    Copy-ExactFile -Source (Join-Path $SourceRoot 'android\app\build\intermediates\merged_manifests\internal\processInternalManifest\AndroidManifest.xml') -Destination (Join-Path $pqs 'android\AndroidManifest.xml')
    Copy-ExactFile -Source $sbomPath -Destination (Join-Path $pqs 'metadata\cyclonedx-bom.json')
    Copy-ExactFile -Source (Join-Path $SourceRoot 'config\release\products.json') -Destination (Join-Path $pqs 'metadata\release-products.json')
    Copy-ExactFile -Source (Join-Path $SourceRoot 'config\release\version.properties') -Destination (Join-Path $pqs 'metadata\release-version.properties')
    Copy-ExactFile -Source (Join-Path $SourceRoot 'testdata\evidence\phase9\android-licenses.spdx.json') -Destination (Join-Path $pqs 'metadata\android-licenses.spdx.json')
    Write-ApkNativeInventory -Apk (Join-Path $pqs 'android\app-internal.apk') -Destination (Join-Path $pqs 'android\native-libraries.json')

    $packageExtract = Join-Path $temporaryRoot ('package-extract-' + $Builder)
    New-Item -ItemType Directory -Path $packageExtract | Out-Null
    Invoke-Checked -FilePath 'tar.exe' -Arguments @('-xf', $packages[0].FullName, '-C', $packageExtract) -Failure 'PHASE17_BUILD_NATIVE_PACKAGE_EXTRACT_FAILED'
    $packageManifests = @(Get-ChildItem -LiteralPath $packageExtract -Filter 'manifest.json' -File -Recurse)
    if ($packageManifests.Count -ne 1) {
        throw 'PHASE17_BUILD_NATIVE_PACKAGE_MANIFEST_REJECTED'
    }
    Copy-ExactFile -Source $packageManifests[0].FullName -Destination (Join-Path $pqs 'package\manifest.json')

    foreach ($script in @('run-qualified-campaign.ps1', 'owned-vps-preflight.ps1', 'privacy_scanner_b.py')) {
        Copy-ExactFile -Source (Join-Path $SourceRoot ('scripts\phase17\' + $script)) -Destination (Join-Path $qhs ('scripts\' + $script))
    }
    Copy-ExactFile -Source (Join-Path $SourceRoot 'config\phase17\qualification-policy-v1.json') -Destination (Join-Path $qws 'qualification-policy-v1.json')
    Copy-ExactFile -Source (Join-Path $SourceRoot 'android\config\phase17-required-device-tests.txt') -Destination (Join-Path $qws 'phase17-required-device-tests.txt')

    foreach ($script in @('sanitize-field-evidence.ps1', 'privacy_scanner_b.py', 'privacy_scan_b_test.py')) {
        Copy-ExactFile -Source (Join-Path $SourceRoot ('scripts\phase17\' + $script)) -Destination (Join-Path $ovs ('scripts\' + $script))
    }
    $schemas = @(
        'phase17-qualification-policy-v1.schema.json',
        'phase17-qualification-envelope-v1.schema.json',
        'phase17-candidate-manifest-v1.schema.json',
        'phase17-candidate-comparison-v1.schema.json',
        'phase17-environment-context-v1.schema.json',
        'phase17-historical-gate-supersession-v1.schema.json',
        'phase17-owned-vps-preflight-v1.schema.json',
        'phase17-readiness-evidence-index-v1.schema.json',
        'phase17-readiness-proof-v1.schema.json',
        'phase17-owned-vps-evidence-v3.schema.json'
    )
    foreach ($schema in $schemas) {
        Copy-ExactFile -Source (Join-Path $SourceRoot ('testdata\schemas\' + $schema)) -Destination (Join-Path $ovs ('schemas\' + $schema))
    }
    Copy-TreeFiles -Source (Join-Path $SourceRoot 'testdata\fixtures\phase17\privacy-scanner') -Destination (Join-Path $ovs 'privacy-scanner-corpus')

    $builtTree = Get-GitText -Root $SourceRoot -Arguments @('show', '-s', '--format=%T', $Commit) -Failure 'PHASE17_BUILD_WORKTREE_TREE_UNAVAILABLE'
    if ($builtTree -cne $Tree) {
        throw 'PHASE17_BUILD_WORKTREE_IDENTITY_CHANGED'
    }
    $status = Get-GitText -Root $SourceRoot -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -Failure 'PHASE17_BUILD_WORKTREE_STATUS_FAILED'
    if (-not [string]::IsNullOrEmpty($status)) {
        throw 'PHASE17_BUILD_WORKTREE_DIRTY'
    }
}

foreach ($relative in @($EngineeringCandidateRoot, $EngineeringAssuranceRoot, $EngineeringProvenance, $EngineeringComparison)) {
    Assert-SafeRelativePath -Path $relative
}
Assert-ChildPath -Parent $repoRoot -Child $qualificationRoot
Assert-ChildPath -Parent $qualificationRoot -Child $candidateRoot
Assert-ChildPath -Parent ([IO.Path]::GetTempPath()) -Child $temporaryRoot

if (Test-Path -LiteralPath $candidateRoot) {
    throw 'PHASE17_BUILD_CANDIDATE_ALREADY_EXISTS'
}
$head = Get-GitText -Root $repoRoot -Arguments @('rev-parse', 'HEAD') -Failure 'PHASE17_BUILD_HEAD_UNAVAILABLE'
$tree = Get-GitText -Root $repoRoot -Arguments @('show', '-s', '--format=%T', $Commit) -Failure 'PHASE17_BUILD_TREE_UNAVAILABLE'
$main = Get-GitText -Root $repoRoot -Arguments @('rev-parse', $ExpectedMainRef) -Failure 'PHASE17_BUILD_MAIN_REF_UNAVAILABLE'
$baselineResolved = Get-GitText -Root $repoRoot -Arguments @('rev-parse', ($BaselineCommit + '^{commit}')) -Failure 'PHASE17_BUILD_BASELINE_UNAVAILABLE'
$sourceDateEpoch = Get-GitText -Root $repoRoot -Arguments @('show', '-s', '--format=%ct', $Commit) -Failure 'PHASE17_BUILD_COMMIT_TIME_UNAVAILABLE'
if (($head -cne $Commit) -or ($main -cne $Commit) -or ($baselineResolved -cne $BaselineCommit) -or
    ($tree -notmatch '^[0-9a-f]{40}$') -or ($sourceDateEpoch -notmatch '^[0-9]+$')) {
    throw 'PHASE17_BUILD_INTEGRATED_SOURCE_IDENTITY_REJECTED'
}
Invoke-Checked -FilePath 'git' -Arguments @('-C', $repoRoot, 'merge-base', '--is-ancestor', $BaselineCommit, $Commit) -Failure 'PHASE17_BUILD_BASELINE_NOT_ANCESTOR'
$sourceStatus = Get-GitText -Root $repoRoot -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -Failure 'PHASE17_BUILD_SOURCE_STATUS_FAILED'
if (-not [string]::IsNullOrEmpty($sourceStatus)) {
    throw 'PHASE17_BUILD_SOURCE_NOT_CLEAN'
}

$worktreeAAdded = $false
$worktreeBAdded = $false
$completed = $false
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
try {
    New-Item -ItemType Directory -Path $temporaryRoot, $candidateA, $candidateB | Out-Null
    Invoke-Checked -FilePath 'git' -Arguments @('-C', $repoRoot, 'worktree', 'add', '--detach', $worktreeA, $Commit) -Failure 'PHASE17_BUILD_WORKTREE_A_FAILED'
    $worktreeAAdded = $true
    Invoke-Checked -FilePath 'git' -Arguments @('-C', $repoRoot, 'worktree', 'add', '--detach', $worktreeB, $Commit) -Failure 'PHASE17_BUILD_WORKTREE_B_FAILED'
    $worktreeBAdded = $true

    Build-CandidateRoot -Builder 'a' -SourceRoot $worktreeA -OutputRoot $candidateA -Tree $tree -SourceDateEpoch $sourceDateEpoch
    Build-CandidateRoot -Builder 'b' -SourceRoot $worktreeB -OutputRoot $candidateB -Tree $tree -SourceDateEpoch $sourceDateEpoch

    $assure = Join-Path $candidateA 'OVS\bin\assure.exe'
    Invoke-Checked -FilePath $assure -Arguments @(
        'candidate', 'validate', '-root', $repoRoot,
        '-provenance', $EngineeringProvenance,
        '-candidate-root', $EngineeringCandidateRoot,
        '-assurance-root', $EngineeringAssuranceRoot,
        '-comparison', $EngineeringComparison,
        '-expected-repository', $ExpectedRepository,
        '-expected-commit', $Commit,
        '-expected-tree', $tree,
        '-expected-run-id', $AssuranceRunId,
        '-expected-run-attempt', [string]$AssuranceRunAttempt
    ) -Failure 'PHASE17_BUILD_ENGINEERING_CANDIDATE_ASSURANCE_FAILED'

    $phase17qual = Join-Path $candidateA 'QHS\bin\phase17qual.exe'
    $sourceRelative = [IO.Path]::GetRelativePath($repoRoot, (Join-Path $candidateA 'source-provenance.json')).Replace('\', '/')
    Invoke-Checked -FilePath $phase17qual -Arguments @(
        'source', 'create', '-root', $repoRoot, '-baseline', $BaselineCommit, '-out', $sourceRelative
    ) -Failure 'PHASE17_BUILD_SOURCE_PROVENANCE_FAILED'
    Copy-ExactFile -Source (Join-Path $candidateA 'source-provenance.json') -Destination (Join-Path $candidateB 'source-provenance.json')

    $candidateARelative = [IO.Path]::GetRelativePath($repoRoot, $candidateA).Replace('\', '/')
    $candidateBRelative = [IO.Path]::GetRelativePath($repoRoot, $candidateB).Replace('\', '/')
    $comparisonRelative = [IO.Path]::GetRelativePath($repoRoot, $comparisonPath).Replace('\', '/')
    $manifestRelative = [IO.Path]::GetRelativePath($repoRoot, $manifestPath).Replace('\', '/')
    Invoke-Checked -FilePath $phase17qual -Arguments @(
        'candidate', 'create', '-root', $repoRoot,
        '-artifacts', $candidateARelative,
        '-comparison-artifacts', $candidateBRelative,
        '-comparison', $comparisonRelative,
        '-out', $manifestRelative
    ) -Failure 'PHASE17_BUILD_REPRODUCIBILITY_FAILED'

    foreach ($file in @(Get-ChildItem -LiteralPath $candidateA -File -Recurse)) {
        $file.IsReadOnly = $true
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $candidateB -File -Recurse)) {
        $file.IsReadOnly = $true
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $candidateId = [string]$manifest.roots.candidateId
    if ($candidateId -notmatch '^[0-9a-f]{64}$') {
        throw 'PHASE17_BUILD_CANDIDATE_ID_REJECTED'
    }
    $completed = $true
    Write-Output ('PHASE17_QUALIFICATION_CANDIDATE_BUILT ' + $candidateId)
} catch {
    $primaryFailure = $_.Exception.Message
} finally {
    if ($worktreeAAdded) {
        if (-not (Remove-QualificationWorktree -RepositoryRoot $repoRoot -Worktree $worktreeA)) {
            $cleanupFailures.Add('WORKTREE_A')
        }
    }
    if ($worktreeBAdded) {
        if (-not (Remove-QualificationWorktree -RepositoryRoot $repoRoot -Worktree $worktreeB)) {
            $cleanupFailures.Add('WORKTREE_B')
        }
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        if (-not (Remove-QualificationTree -Parent ([IO.Path]::GetTempPath()) -Child $temporaryRoot)) {
            $cleanupFailures.Add('TEMPORARY_ROOT')
        }
    }
    if ((-not $completed) -and (Test-Path -LiteralPath $candidateRoot)) {
        if (-not (Remove-QualificationTree -Parent $qualificationRoot -Child $candidateRoot)) {
            $cleanupFailures.Add('CANDIDATE_ROOT')
        }
    }
}
if ($null -ne $primaryFailure) {
    if ($cleanupFailures.Count -gt 0) {
        throw ($primaryFailure + ' / PHASE17_BUILD_CLEANUP_FAILED')
    }
    throw $primaryFailure
}
if ($cleanupFailures.Count -gt 0) {
    throw 'PHASE17_BUILD_CLEANUP_FAILED'
}
