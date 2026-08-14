// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"kurdistan/internal/phase17evidence"
	"kurdistan/internal/phase17qualification"
)

func buildTerminalEvidenceV3(
	qualified qualifiedRun,
	androidAPI int,
	androidABI string,
	ipv6 bool,
	durationMS uint64,
	tracker resourceTracker,
	outcome functionalOutcome,
	runErr error,
) (phase17evidence.OwnedVPSEvidenceV3, error) {
	if runErr == nil {
		return buildPassingEvidenceV3(
			qualified, androidAPI, androidABI, ipv6, durationMS, tracker, outcome, outcome.scanners, outcome.boundary,
		)
	}
	terminalOutcome, failingCheck := classifyFieldFailure(runErr, outcome)
	checks := make([]phase17evidence.FieldCheckV3, 0, len(phase17qualification.RequiredChecks()))
	for _, name := range phase17qualification.RequiredChecks() {
		result := "NOT_RUN"
		if name == failingCheck && terminalOutcome != "INCONCLUSIVE" {
			result = "FAIL"
		}
		checks = append(checks, phase17evidence.FieldCheckV3{Name: name, Result: result})
	}
	if androidAPI == 0 {
		androidAPI = qualified.environment.AndroidAPI
	}
	if androidABI == "" {
		androidABI = qualified.environment.AndroidABI
	}
	campaign := phase17evidence.FieldCampaignV3{
		Mode: qualified.campaign.Mode, RestartReconnectCycles: outcome.campaign.RestartReconnectCycles,
		ProfileRotationCycles: outcome.campaign.ProfileRotationCycles,
		Impairments:           append([]string{}, outcome.campaign.Impairments...),
		SoakDurationMS:        outcome.campaign.SoakDurationMS, SoakCycles: outcome.campaign.SoakCycles,
	}
	if qualified.campaign.MinimumDurationMS > 0 {
		campaign.CadenceMS = qualified.campaign.CadenceMS
	}
	scanners := normalizeTerminalScanners(outcome.scanners)
	boundary := outcome.boundary
	if boundary.Result == "" {
		boundary.Result = "NOT_RUN"
	}
	privacy := aggregateTerminalPrivacy(scanners)
	value := phase17evidence.OwnedVPSEvidenceV3{
		Schema: phase17evidence.OwnedVPSRawSchemaV3, Outcome: terminalOutcome,
		Subject: phase17evidence.FieldSubjectV3{
			Repository: qualified.candidate.Repository, CommitSHA: qualified.candidate.CommitSHA, TreeSHA: qualified.candidate.TreeSHA,
			CandidateID: qualified.candidate.Roots.CandidateID, SourceSHA256: qualified.candidate.Roots.SourceSHA256,
			ProductSHA256: qualified.candidate.Roots.ProductSHA256, HarnessSHA256: qualified.candidate.Roots.HarnessSHA256,
			WorkloadSHA256: qualified.candidate.Roots.WorkloadSHA256, VerifierSHA256: qualified.candidate.Roots.VerifierSHA256,
			ComparisonSHA256: qualified.candidate.ComparisonSHA256, PolicySHA256: qualified.policyDigest,
			PackageSHA256: qualified.packageDigest, AppAPKSHA256: qualified.appDigest, TestAPKSHA256: qualified.testDigest,
		},
		Attempt: phase17evidence.FieldAttemptV3{
			AttemptID: qualified.attempt.AttemptID, RCLockedSHA256: qualified.rcLockedDigest,
			AuthorizationSHA256: qualified.attempt.AuthorizationSHA256, EnvironmentSHA256: qualified.environmentDigest,
			PreflightSHA256:         qualified.attempt.PreflightSHA256,
			PriorStressResultSHA256: qualified.priorStressDigest, SoakReadySHA256: qualified.soakReadyDigest,
		},
		Environment: phase17evidence.FieldEnvironmentV3{
			HostOS: qualified.environment.HostOS, HostArch: qualified.environment.HostArch,
			AndroidClass: qualified.environment.AndroidClass, AndroidAPI: androidAPI, AndroidABI: androidABI,
			VPSOS: qualified.environment.VPSOS, VPSArch: qualified.environment.VPSArch,
			ProviderClass: qualified.environment.ProviderClass, IPv4: true, IPv6: ipv6,
		},
		Checks: checks,
		Metrics: phase17evidence.FieldMetricsV3{
			DurationMS: durationMS, PeakRSSBytes: tracker.peakRSS, PeakFileDescriptors: tracker.peakFDs,
			PeakSwapBytes: tracker.peakSwap, OOMKills: tracker.peakOOMKills, Reconnects: outcome.reconnects,
		},
		Privacy: privacy, Scanners: scanners, Boundary: boundary, Campaign: campaign,
	}
	if _, err := phase17evidence.MarshalOwnedVPSRawV3(value); err != nil {
		return phase17evidence.OwnedVPSEvidenceV3{}, err
	}
	return value, nil
}

func classifyFieldFailure(runErr error, outcome functionalOutcome) (string, string) {
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		return "INCONCLUSIVE", "preflight"
	}
	if errors.Is(runErr, errCampaignClockGap) || errors.Is(runErr, errCampaignClockReversed) ||
		errors.Is(runErr, errAndroidEnvironmentUnavailable) || errors.Is(runErr, errVPSEnvironmentUnavailable) {
		return "ABORT_ENVIRONMENT", "preflight"
	}
	var actionFailure *fieldActionFailure
	if errors.As(runErr, &actionFailure) {
		if actionFailure.category == "BOUNDARY_LEAK" {
			return "FAIL_PRIVACY", "routeDnsLeak"
		}
		if strings.HasPrefix(actionFailure.category, "INSTRUMENTATION_") {
			return "FAIL_HARNESS", "androidCrashFree"
		}
		if strings.Contains(actionFailure.category, "DNS") {
			return "FAIL_PRODUCT", "dnsHealthy"
		}
		return "FAIL_PRODUCT", "connect"
	}
	if errors.Is(runErr, errFieldCleanup) {
		return "FAIL_HARNESS", "preflight"
	}
	if errors.Is(runErr, errFieldEvidenceInvalid) {
		return "FAIL_HARNESS", "androidCrashFree"
	}
	message := strings.ToLower(runErr.Error())
	if strings.Contains(message, "boundary monitor found") || strings.Contains(message, "private probe endpoint") ||
		strings.Contains(message, "privacy log scan found") {
		return "FAIL_PRIVACY", map[bool]string{true: "routeDnsLeak", false: "privacy"}[strings.Contains(message, "boundary")]
	}
	if strings.Contains(message, "privacy scanners did not independently pass") {
		for _, scanner := range outcome.scanners {
			if scanner.Result == "FAIL" && scanner.Privacy != (phase17evidence.FieldPrivacyV3{}) {
				return "FAIL_PRIVACY", "privacy"
			}
		}
		return "FAIL_HARNESS", "privacy"
	}
	if strings.Contains(message, "scanner process") || strings.Contains(message, "scanner receipt") ||
		strings.Contains(message, "scanner parity") || strings.Contains(message, "boundary monitor process") ||
		strings.Contains(message, "boundary monitor receipt") || strings.Contains(message, "boundary monitor parity") ||
		strings.Contains(message, "campaign monotonic") || strings.Contains(message, "campaign clock") ||
		strings.Contains(message, "instrumentation") || strings.Contains(message, "evidence reset") {
		return "FAIL_HARNESS", "androidCrashFree"
	}
	if strings.Contains(message, "identity") || strings.Contains(message, "locked candidate") ||
		strings.Contains(message, "qualification") || strings.Contains(message, "artifact differs") ||
		strings.Contains(message, "source state") {
		return "INVALID_IDENTITY", "preflight"
	}
	return "FAIL_PRODUCT", "connect"
}

func joinFieldCleanup(target *error, cleanupErr error) {
	if target == nil || cleanupErr == nil {
		return
	}
	failure := fmt.Errorf("%w: %v", errFieldCleanup, cleanupErr)
	if *target == nil {
		*target = failure
		return
	}
	*target = errors.Join(*target, failure)
}

func normalizeTerminalScanners(values []phase17evidence.FieldScannerV3) []phase17evidence.FieldScannerV3 {
	result := []phase17evidence.FieldScannerV3{{Name: "GO_A", Result: "NOT_RUN"}, {Name: "PYTHON_B", Result: "NOT_RUN"}}
	for _, value := range values {
		switch value.Name {
		case "GO_A":
			result[0] = value
		case "PYTHON_B":
			result[1] = value
		}
	}
	return result
}

func aggregateTerminalPrivacy(values []phase17evidence.FieldScannerV3) phase17evidence.FieldPrivacyV3 {
	var result phase17evidence.FieldPrivacyV3
	for _, value := range values {
		result.PayloadRetained = result.PayloadRetained || value.Privacy.PayloadRetained
		result.DestinationRetained = result.DestinationRetained || value.Privacy.DestinationRetained
		result.DNSNameRetained = result.DNSNameRetained || value.Privacy.DNSNameRetained
		result.CredentialRetained = result.CredentialRetained || value.Privacy.CredentialRetained
		result.KeyRetained = result.KeyRetained || value.Privacy.KeyRetained
		result.ProfileRetained = result.ProfileRetained || value.Privacy.ProfileRetained
		result.RawLogRetained = result.RawLogRetained || value.Privacy.RawLogRetained
	}
	return result
}

func buildPassingEvidenceV3(
	qualified qualifiedRun,
	androidAPI int,
	androidABI string,
	ipv6 bool,
	durationMS uint64,
	tracker resourceTracker,
	outcome functionalOutcome,
	scanners []phase17evidence.FieldScannerV3,
	boundary phase17evidence.FieldBoundaryV3,
) (phase17evidence.OwnedVPSEvidenceV3, error) {
	if qualified.environment.HostOS != runtime.GOOS || qualified.environment.HostArch != runtime.GOARCH ||
		qualified.environment.AndroidAPI != androidAPI || qualified.environment.AndroidABI != androidABI ||
		qualified.campaign.Mode != outcome.campaign.Mode || durationMS == 0 {
		return phase17evidence.OwnedVPSEvidenceV3{}, errors.New("qualified field environment or campaign drifted")
	}
	checks := make([]phase17evidence.FieldCheckV3, 0, len(phase17qualification.RequiredChecks()))
	for _, name := range phase17qualification.RequiredChecks() {
		checks = append(checks, phase17evidence.FieldCheckV3{Name: name, Result: "PASS"})
	}
	value := phase17evidence.OwnedVPSEvidenceV3{
		Schema:  phase17evidence.OwnedVPSRawSchemaV3,
		Outcome: "PASS",
		Subject: phase17evidence.FieldSubjectV3{
			Repository: qualified.candidate.Repository, CommitSHA: qualified.candidate.CommitSHA, TreeSHA: qualified.candidate.TreeSHA,
			CandidateID: qualified.candidate.Roots.CandidateID, SourceSHA256: qualified.candidate.Roots.SourceSHA256,
			ProductSHA256: qualified.candidate.Roots.ProductSHA256, HarnessSHA256: qualified.candidate.Roots.HarnessSHA256,
			WorkloadSHA256: qualified.candidate.Roots.WorkloadSHA256, VerifierSHA256: qualified.candidate.Roots.VerifierSHA256,
			ComparisonSHA256: qualified.candidate.ComparisonSHA256, PolicySHA256: qualified.policyDigest,
			PackageSHA256: qualified.packageDigest, AppAPKSHA256: qualified.appDigest, TestAPKSHA256: qualified.testDigest,
		},
		Attempt: phase17evidence.FieldAttemptV3{
			AttemptID: qualified.attempt.AttemptID, RCLockedSHA256: qualified.rcLockedDigest,
			AuthorizationSHA256: qualified.attempt.AuthorizationSHA256, EnvironmentSHA256: qualified.environmentDigest,
			PreflightSHA256:         qualified.attempt.PreflightSHA256,
			PriorStressResultSHA256: qualified.priorStressDigest, SoakReadySHA256: qualified.soakReadyDigest,
		},
		Environment: phase17evidence.FieldEnvironmentV3{
			HostOS: qualified.environment.HostOS, HostArch: qualified.environment.HostArch,
			AndroidClass: qualified.environment.AndroidClass, AndroidAPI: androidAPI, AndroidABI: androidABI,
			VPSOS: qualified.environment.VPSOS, VPSArch: qualified.environment.VPSArch,
			ProviderClass: qualified.environment.ProviderClass, IPv4: true, IPv6: ipv6,
		},
		Checks: checks,
		Metrics: phase17evidence.FieldMetricsV3{
			DurationMS: durationMS, PeakRSSBytes: tracker.peakRSS, PeakFileDescriptors: tracker.peakFDs,
			PeakSwapBytes: tracker.peakSwap, OOMKills: tracker.peakOOMKills, Reconnects: outcome.reconnects,
			TerminalGaps: 0,
		},
		Privacy:  phase17evidence.FieldPrivacyV3{},
		Scanners: append([]phase17evidence.FieldScannerV3(nil), scanners...),
		Boundary: boundary,
		Campaign: phase17evidence.FieldCampaignV3{
			Mode: qualified.campaign.Mode, RestartReconnectCycles: outcome.campaign.RestartReconnectCycles,
			ProfileRotationCycles: outcome.campaign.ProfileRotationCycles,
			Impairments:           append([]string{}, outcome.campaign.Impairments...),
			SoakDurationMS:        outcome.campaign.SoakDurationMS, CadenceMS: qualified.campaign.CadenceMS,
			SoakCycles: outcome.campaign.SoakCycles,
		},
	}
	if _, err := phase17evidence.MarshalOwnedVPSRawV3(value); err != nil {
		return phase17evidence.OwnedVPSEvidenceV3{}, err
	}
	return value, nil
}
