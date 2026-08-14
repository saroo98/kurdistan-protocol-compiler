# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

[CmdletBinding()]
param(
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
$repoRoot = [IO.Path]::GetFullPath((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$candidateScript = Join-Path ([IO.Path]::GetFullPath($CandidateRoot)) 'candidate-A\QHS\scripts\run-qualified-campaign.ps1'
if (-not (Test-Path -LiteralPath $candidateScript -PathType Leaf)) {
    throw 'PHASE17_QUALIFIED_CAMPAIGN_WRAPPER_MISSING'
}

$arguments = @{
    RepositoryRoot = $repoRoot
    CandidateRoot = $CandidateRoot
    RCLock = $RCLock
    Environment = $Environment
    Ledger = $Ledger
    PrivateKey = $PrivateKey
    TrustedPublicKey = $TrustedPublicKey
    AttemptRoot = $AttemptRoot
    EvidenceRoot = $EvidenceRoot
    Mode = $Mode
    PrivateEnvironment = $PrivateEnvironment
    EnvironmentSalt = $EnvironmentSalt
    SoakReady = $SoakReady
    PriorStressResult = $PriorStressResult
}
& $candidateScript @arguments
