// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import (
	"context"

	"kurdistan/internal/localproxyingress"
)

const (
	ScenarioFixedTargetDescriptor      = "fixed_target_descriptor"
	ScenarioFixedStreamMapping         = "fixed_stream_mapping"
	ScenarioFixedLifecyclePattern      = "fixed_lifecycle_pattern"
	ScenarioBackpressureIgnored        = "backpressure_ignored"
	ScenarioResetLeaksAcrossRequests   = "reset_leaks_across_requests"
	ScenarioTargetErrorLeaksDescriptor = "target_error_leaks_descriptor"
	ScenarioInvalidTargetsAccepted     = "invalid_targets_accepted"
	ScenarioQueueUnbounded             = "queue_unbounded"
	ScenarioPayloadLoggedControl       = "payload_logged_control"
	ScenarioSecretLoggedControl        = "secret_logged_control"
)

func QuickScenarios() []string {
	return []string{ScenarioFixedTargetDescriptor, ScenarioBackpressureIgnored, ScenarioInvalidTargetsAccepted}
}

func FullScenarios() []string {
	return []string{
		ScenarioFixedTargetDescriptor,
		ScenarioFixedStreamMapping,
		ScenarioFixedLifecyclePattern,
		ScenarioBackpressureIgnored,
		ScenarioResetLeaksAcrossRequests,
		ScenarioTargetErrorLeaksDescriptor,
		ScenarioInvalidTargetsAccepted,
		ScenarioQueueUnbounded,
		ScenarioPayloadLoggedControl,
		ScenarioSecretLoggedControl,
	}
}

type ScenarioRun struct {
	Scenario        string                                     `json:"scenario"`
	Summary         localproxyingress.LocalProxyIngressSummary `json:"summary"`
	Features        FeatureVector                              `json:"features"`
	Collapse        CollapseReport                             `json:"collapse"`
	ExpectedFailure bool                                       `json:"expected_failure"`
	Conclusion      string                                     `json:"conclusion"`
}

func RunScenario(ctx context.Context, scenario string) ScenarioRun {
	base := localproxyingress.ScenarioSingleConnectEcho
	switch scenario {
	case ScenarioBackpressureIgnored:
		base = localproxyingress.ScenarioBackpressurePressure
	case ScenarioResetLeaksAcrossRequests:
		base = localproxyingress.ScenarioResetMidRequest
	case ScenarioTargetErrorLeaksDescriptor:
		base = localproxyingress.ScenarioTargetErrorAfterOpen
	case ScenarioInvalidTargetsAccepted:
		base = localproxyingress.ScenarioInvalidTargetRejection
	case ScenarioQueueUnbounded:
		base = localproxyingress.ScenarioQueueOverflowRejection
	}
	summary, err := localproxyingress.RunScenario(ctx, base, localproxyingress.DefaultConfig())
	if err != nil {
		summary = localproxyingress.LocalProxyIngressSummary{Version: string(localproxyingress.Version), Scenario: base, ContractID: localproxyingress.DefaultConfig().ContractID, PayloadLogged: true}
	}
	if scenario == ScenarioPayloadLoggedControl {
		summary.PayloadLogged = true
	}
	if scenario == ScenarioSecretLoggedControl {
		summary.SecretLogged = true
	}
	if scenario == ScenarioBackpressureIgnored {
		summary.BackpressureEvents = 0
	}
	if scenario == ScenarioInvalidTargetsAccepted {
		summary.AcceptedRequests = 1
		summary.RejectedRequests = 0
	}
	features := ExtractFeatures(summary)
	collapse := ScanCollapse([]FeatureVector{features}, scenario)
	conclusion := "passed"
	if len(collapse.SuspiciousMetrics) > 0 || summary.PayloadLogged || summary.SecretLogged {
		conclusion = "failed"
	}
	return ScenarioRun{Scenario: scenario, Summary: summary, Features: features, Collapse: collapse, ExpectedFailure: true, Conclusion: conclusion}
}
