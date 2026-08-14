# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$CandidateRoot,
    [Parameter(Mandatory = $true)][string]$RCLock,
    [Parameter(Mandatory = $true)][string]$Environment,
    [Parameter(Mandatory = $true)][string]$Ledger,
    [Parameter(Mandatory = $true)][string]$PrivateKey,
    [Parameter(Mandatory = $true)][string]$TrustedPublicKey,
    [Parameter(Mandatory = $true)][string]$AttemptRoot,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [Parameter(Mandatory = $true)]
    [ValidateSet('Functional', 'Stress', 'Soak60m', 'Soak90m', 'Soak120m', 'Soak12h')]
    [string]$Mode,
    [Parameter(Mandatory = $true)][string]$PrivateEnvironment,
    [Parameter(Mandatory = $true)][string]$EnvironmentSalt,
    [string]$SoakReady = '',
    [string]$PriorStressResult = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($null -ne $item.LinkType) -or ($item.Length -lt 1)) {
        throw 'PHASE17_CAMPAIGN_REGULAR_FILE_REJECTED'
    }
}

function Assert-DirectoryNotLink {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ((-not $item.PSIsContainer) -or ($null -ne $item.LinkType)) {
        throw 'PHASE17_CAMPAIGN_DIRECTORY_REJECTED'
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
        throw 'PHASE17_CAMPAIGN_PATH_SCOPE_REJECTED'
    }
}

$repository = [IO.Path]::GetFullPath($RepositoryRoot)
$candidateState = [IO.Path]::GetFullPath($CandidateRoot)
$candidateA = Join-Path $candidateState 'candidate-A'
$candidateB = Join-Path $candidateState 'candidate-B'
$manifest = Join-Path $candidateState 'candidate-manifest.json'
$comparison = Join-Path $candidateState 'candidate-comparison.json'
Assert-DirectoryNotLink -Path $repository
Assert-DirectoryNotLink -Path $candidateState
Assert-DirectoryNotLink -Path $candidateA
Assert-DirectoryNotLink -Path $candidateB
foreach ($path in @($manifest, $comparison, $RCLock, $Environment, $PrivateEnvironment, $EnvironmentSalt, $PrivateKey, $TrustedPublicKey)) {
    Assert-RegularFile -Path $path
}
if (-not (Test-Path -LiteralPath $Ledger -PathType Container)) {
    New-Item -ItemType Directory -Path $Ledger | Out-Null
}
Assert-DirectoryNotLink -Path $Ledger
foreach ($directory in @($AttemptRoot, $EvidenceRoot)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    Assert-DirectoryNotLink -Path $directory
}

$phase17qual = Join-Path $candidateA 'QHS\bin\phase17qual.exe'
$runner = Join-Path $candidateA 'QHS\bin\phase17field.exe'
$preflight = Join-Path $candidateA 'QHS\scripts\owned-vps-preflight.ps1'
$packageVerifier = Join-Path $candidateA 'QHS\bin\kurdpackage.exe'
$scannerA = Join-Path $candidateA 'QHS\bin\phase17scan.exe'
$scannerB = Join-Path $candidateA 'QHS\scripts\privacy_scanner_b.py'
$boundary = Join-Path $candidateA 'QHS\bin\phase17boundary.exe'
$appApk = Join-Path $candidateA 'PQS\android\app-internal.apk'
$testApk = Join-Path $candidateA 'QHS\android\app-internal-androidTest.apk'
$policy = Join-Path $candidateA 'QWS\qualification-policy-v1.json'
$packages = @(Get-ChildItem -LiteralPath (Join-Path $candidateA 'PQS\package') -Filter '*-linux-amd64.tar.gz' -File)
if ($packages.Count -ne 1) {
    throw 'PHASE17_CAMPAIGN_PACKAGE_INVENTORY_REJECTED'
}
$package = $packages[0].FullName
foreach ($path in @($phase17qual, $runner, $preflight, $packageVerifier, $scannerA, $scannerB, $boundary, $appApk, $testApk, $policy, $package)) {
    Assert-RegularFile -Path $path
    Assert-ChildPath -Parent $candidateA -Child $path
}
Assert-RegularFile -Path $PSCommandPath
Assert-ChildPath -Parent $candidateA -Child $PSCommandPath

$policyRelative = [IO.Path]::GetRelativePath($repository, $policy).Replace('\', '/')
Invoke-Checked -FilePath $phase17qual -Arguments @('policy', 'verify', '-root', $repository, '-policy', $policyRelative) -Failure 'PHASE17_CAMPAIGN_POLICY_REJECTED'
Invoke-Checked -FilePath $phase17qual -Arguments @('verify', '-trusted-public-key', $TrustedPublicKey, '-statement', $RCLock) -Failure 'PHASE17_CAMPAIGN_RC_LOCK_REJECTED'
Invoke-Checked -FilePath $phase17qual -Arguments @(
    'environment', 'verify', '-candidate', $manifest, '-environment', $Environment,
    '-private-environment', $PrivateEnvironment, '-salt', $EnvironmentSalt
) -Failure 'PHASE17_CAMPAIGN_ENVIRONMENT_REJECTED'

$launchDirectory = Join-Path ([IO.Path]::GetFullPath($AttemptRoot)) ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $launchDirectory | Out-Null
$begin = Join-Path $launchDirectory 'attempt-begin.json'
$terminal = Join-Path $launchDirectory 'attempt-terminal.json'
$consumed = Join-Path $launchDirectory 'soak-consumed.json'
$wrapperResult = Join-Path $launchDirectory 'wrapper-result.json'
$preflightResult = Join-Path $launchDirectory 'preflight.json'
$preflightId = [Guid]::NewGuid().ToString('N')

Invoke-Checked -FilePath $phase17qual -Arguments @(
    'candidate', 'artifact', 'verify', '-candidate', $manifest, '-rc-lock', $RCLock,
    '-trusted-public-key', $TrustedPublicKey, '-subject', 'QHS',
    '-entry', 'scripts/owned-vps-preflight.ps1', '-path', $preflight
) -Failure 'PHASE17_CAMPAIGN_PREFLIGHT_IDENTITY_REJECTED'
& $preflight -PrivateEnvironment $PrivateEnvironment -Environment $Environment -PreflightId $preflightId -Output $preflightResult
Assert-RegularFile -Path $preflightResult
Invoke-Checked -FilePath $phase17qual -Arguments @(
    'environment', 'verify', '-candidate', $manifest, '-environment', $Environment,
    '-private-environment', $PrivateEnvironment, '-salt', $EnvironmentSalt
) -Failure 'PHASE17_CAMPAIGN_POST_PREFLIGHT_ENVIRONMENT_REJECTED'

if ($Mode -eq 'Soak12h') {
    foreach ($path in @($SoakReady, $PriorStressResult)) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            throw 'PHASE17_CAMPAIGN_FINAL_SOAK_PREREQUISITE_REJECTED'
        }
        Assert-RegularFile -Path $path
    }
    Invoke-Checked -FilePath $phase17qual -Arguments @(
        'verify', '-trusted-public-key', $TrustedPublicKey, '-statement', $SoakReady
    ) -Failure 'PHASE17_CAMPAIGN_SOAK_READY_REJECTED'
    Invoke-Checked -FilePath $phase17qual -Arguments @(
        'soak', 'consume', '-authorization', $SoakReady, '-environment', $Environment,
        '-preflight-result', $preflightResult,
        '-ledger', $Ledger, '-private-key', $PrivateKey, '-out', $consumed
    ) -Failure 'PHASE17_CAMPAIGN_SOAK_CONSUMPTION_REJECTED'
    $authorization = $consumed
} else {
    if ((-not [string]::IsNullOrWhiteSpace($SoakReady)) -or (-not [string]::IsNullOrWhiteSpace($PriorStressResult))) {
        throw 'PHASE17_CAMPAIGN_NONFINAL_AUTHORIZATION_REJECTED'
    }
    $authorization = $RCLock
}

Invoke-Checked -FilePath $phase17qual -Arguments @(
    'attempt', 'begin', '-authorization', $authorization, '-environment', $Environment,
    '-preflight-result', $preflightResult,
    '-mode', $Mode, '-ledger', $Ledger, '-private-key', $PrivateKey, '-out', $begin
) -Failure 'PHASE17_CAMPAIGN_ATTEMPT_BEGIN_FAILED'

$beginDocument = Get-Content -LiteralPath $begin -Raw | ConvertFrom-Json
$attemptId = [string]$beginDocument.payload.attemptId
if ($attemptId -notmatch '^[0-9a-f]{32}$') {
    throw 'PHASE17_CAMPAIGN_ATTEMPT_ID_REJECTED'
}

$packageEntry = 'package/' + $packages[0].Name
$closeArguments = @(
    'attempt', 'close', '-attempt', $begin, '-candidate', $manifest, '-environment', $Environment,
    '-policy', $policy, '-package-entry', $packageEntry,
    '-app-entry', 'android/app-internal.apk', '-test-entry', 'android/app-internal-androidTest.apk',
    '-ledger', $Ledger, '-private-key', $PrivateKey, '-result-out', $wrapperResult, '-out', $terminal
)
if ($Mode -eq 'Soak12h') {
    $closeArguments += @('-soak-ready', $SoakReady, '-prior-stress-result', $PriorStressResult)
}
function Close-AttemptCategorically {
    param([Parameter(Mandatory = $true)][string]$Reason)
    Invoke-Checked -FilePath $phase17qual -Arguments ($closeArguments + @('-reason', $Reason)) -Failure 'PHASE17_CAMPAIGN_ATTEMPT_CLOSE_FAILED'
}

$runnerArguments = @(
    '-evidence-root', ([IO.Path]::GetFullPath($EvidenceRoot)),
    '-mode', $Mode,
    '-policy', $policy,
    '-candidate', $manifest,
    '-rc-lock', $RCLock,
    '-attempt', $begin,
    '-environment', $Environment,
    '-private-environment', $PrivateEnvironment,
    '-environment-salt', $EnvironmentSalt,
    '-ledger', $Ledger,
    '-trusted-public-key', $TrustedPublicKey,
    '-package', $package,
    '-package-entry', $packageEntry,
    '-app-apk', $appApk,
    '-app-entry', 'android/app-internal.apk',
    '-test-apk', $testApk,
    '-test-entry', 'android/app-internal-androidTest.apk',
    '-runner-entry', 'bin/phase17field.exe',
    '-wrapper', $PSCommandPath,
    '-wrapper-entry', 'scripts/run-qualified-campaign.ps1',
    '-preflight', $preflight,
    '-preflight-entry', 'scripts/owned-vps-preflight.ps1',
    '-preflight-result', $preflightResult,
    '-policy-entry', 'qualification-policy-v1.json',
    '-package-verifier', $packageVerifier,
    '-package-verifier-entry', 'bin/kurdpackage.exe',
    '-privacy-scanner-a', $scannerA,
    '-privacy-scanner-a-entry', 'bin/phase17scan.exe',
    '-privacy-scanner-b', $scannerB,
    '-privacy-scanner-b-entry', 'scripts/privacy_scanner_b.py',
    '-boundary-monitor', $boundary,
    '-boundary-monitor-entry', 'bin/phase17boundary.exe'
)
if ($Mode -eq 'Soak12h') {
    $runnerArguments += @('-soak-ready', $SoakReady, '-prior-stress-result', $PriorStressResult)
}

$runnerExit = 1
$runnerLaunchFailed = $false
Push-Location $repository
try {
    try {
        # phase17field stdout is a bounded categorical progress channel. Its
        # potentially sensitive diagnostic stderr is discarded in memory and
        # is never materialized as a crash-surviving file.
        & $runner @runnerArguments 2> $null
        $runnerExit = $LASTEXITCODE
    } catch {
        $runnerLaunchFailed = $true
    }
} finally {
    Pop-Location
}

$results = @(Get-ChildItem -LiteralPath ([IO.Path]::GetFullPath($EvidenceRoot)) -Filter 'field-result.json' -File -Recurse | Where-Object {
    $_.Directory.Name.EndsWith('-' + $attemptId, [StringComparison]::Ordinal)
})
if ($results.Count -ne 1) {
    if ($runnerLaunchFailed) {
        Close-AttemptCategorically -Reason 'RUNNER_LAUNCH_FAILED'
    } elseif ($results.Count -eq 0) {
        Close-AttemptCategorically -Reason 'RUNNER_RESULT_MISSING'
    } else {
        Close-AttemptCategorically -Reason 'RUNNER_RESULT_AMBIGUOUS'
    }
    throw 'PHASE17_CAMPAIGN_EXACT_RESULT_MISSING'
}
$result = $results[0].FullName
$resultDocument = $null
try {
    $resultDocument = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
} catch {
    Close-AttemptCategorically -Reason 'RUNNER_RESULT_INVALID'
    throw 'PHASE17_CAMPAIGN_RESULT_INVALID'
}
if (([string]$resultDocument.attempt.attemptId -cne $attemptId) -or ([string]$resultDocument.campaign.mode -cne $Mode)) {
    Close-AttemptCategorically -Reason 'RUNNER_RESULT_INVALID'
    throw 'PHASE17_CAMPAIGN_RESULT_IDENTITY_REJECTED'
}

Invoke-Checked -FilePath $phase17qual -Arguments @(
    'attempt', 'finish', '-attempt', $begin, '-candidate', $manifest, '-result', $result,
    '-policy', $policy, '-ledger', $Ledger, '-private-key', $PrivateKey, '-out', $terminal
) -Failure 'PHASE17_CAMPAIGN_ATTEMPT_FINISH_FAILED'

if (($runnerExit -ne 0) -or ([string]$resultDocument.outcome -cne 'PASS')) {
    throw 'PHASE17_CAMPAIGN_TERMINAL_FAILURE'
}
Write-Output ('PHASE17_QUALIFIED_CAMPAIGN_PASS ' + $Mode + ' ' + $attemptId)
