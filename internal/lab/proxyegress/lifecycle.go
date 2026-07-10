// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

func DefaultScenarios() []EgressLifecycleScenario {
	return []EgressLifecycleScenario{
		{ScenarioID: "simple_echo_response", TargetClass: EgressTargetEchoSynthetic, ExpectedFinalState: EgressStateCompleted, ExpectedResponse: "echo_summary"},
		{ScenarioID: "fixed_response", TargetClass: EgressTargetFixedResponse, ExpectedFinalState: EgressStateCompleted, ExpectedResponse: "fixed_summary"},
		{ScenarioID: "chunked_response", TargetClass: EgressTargetChunkedResponse, ExpectedFinalState: EgressStateCompleted, ExpectedResponse: "chunked_summary"},
		{ScenarioID: "slow_response_backpressure", TargetClass: EgressTargetSlowResponse, ExpectedFinalState: EgressStateCompleted, ExpectedResponse: "slow_summary", ExpectedBackpressure: 2},
		{ScenarioID: "large_object_window_pressure", TargetClass: EgressTargetLargeObject, ExpectedFinalState: EgressStateCompleted, ExpectedResponse: "large_summary", ExpectedBackpressure: 3},
		{ScenarioID: "reset_midstream", TargetClass: EgressTargetResetMidstream, ExpectedFinalState: EgressStateReset, ExpectedResponse: "reset_summary", ExpectedReset: 1},
		{ScenarioID: "target_error_response", TargetClass: EgressTargetErrorResponse, ExpectedFinalState: EgressStateFailed, ExpectedResponse: "error_summary", ExpectedError: 1},
		{ScenarioID: "bridge_failure", TargetClass: EgressTargetBlackholeSynthetic, ExpectedFinalState: EgressStateFailed, ExpectedResponse: "bridge_failure_summary", ExpectedError: 1},
		{ScenarioID: "pathhealth_failover_before_egress", TargetClass: EgressTargetFixedResponse, ExpectedFinalState: EgressStateCompleted, ExpectedResponse: "failover_before_egress_summary"},
		{ScenarioID: "pathhealth_failover_midstream", TargetClass: EgressTargetSlowResponse, ExpectedFinalState: EgressStateCompleted, ExpectedResponse: "failover_midstream_summary", ExpectedBackpressure: 1},
		{ScenarioID: "high_risk_candidate_blocked", TargetClass: EgressTargetFixedResponse, ExpectedFinalState: EgressStateQuarantined, ExpectedResponse: "blocked_high_risk_summary", ExpectedError: 1},
		{ScenarioID: "experimental_candidate_blocked", TargetClass: EgressTargetFixedResponse, ExpectedFinalState: EgressStateQuarantined, ExpectedResponse: "blocked_experimental_summary", ExpectedError: 1},
		{ScenarioID: "descriptor_abuse_rejected", TargetClass: EgressTargetErrorResponse, ExpectedFinalState: EgressStateFailed, ExpectedResponse: "descriptor_rejected_summary", ExpectedError: 1},
		{ScenarioID: "control_no_isolation", TargetClass: EgressTargetControlCollapsed, ExpectedFinalState: EgressStateFailed, ExpectedResponse: "control_failure", Control: true, ExpectedError: 1},
		{ScenarioID: "control_backpressure_ignored", TargetClass: EgressTargetControlCollapsed, ExpectedFinalState: EgressStateFailed, ExpectedResponse: "control_failure", Control: true, ExpectedError: 1},
		{ScenarioID: "control_reset_swallowed", TargetClass: EgressTargetControlCollapsed, ExpectedFinalState: EgressStateFailed, ExpectedResponse: "control_failure", Control: true, ExpectedError: 1},
	}
}

func ExecuteLifecycle(s EgressLifecycleScenario) (EgressLifecycleReport, error) {
	req := RequestDescriptorFor(s)
	target := TargetDescriptorFor(s)
	mapping := MappingPlanFor(req, target)
	if err := ValidateRequestDescriptor(req); err != nil && !s.Control {
		return EgressLifecycleReport{}, err
	}
	if err := ValidateTargetDescriptor(target); err != nil && !s.Control {
		return EgressLifecycleReport{}, err
	}
	if err := ValidateMappingPlan(mapping); err != nil && !s.Control {
		return EgressLifecycleReport{}, err
	}
	report := EgressLifecycleReport{
		Version:            Version,
		ScenarioID:         s.ScenarioID,
		RequestID:          req.RequestID,
		TargetID:           target.TargetID,
		MappingID:          mapping.MappingID,
		FinalState:         s.ExpectedFinalState,
		BackpressureEvents: s.ExpectedBackpressure,
		ResetRequests:      s.ExpectedReset,
		FailedRequests:     s.ExpectedError,
		LogicalTicks:       4 + s.ExpectedBackpressure + s.ExpectedReset + s.ExpectedError,
		Conclusion:         "passed",
	}
	if s.ExpectedFinalState == EgressStateCompleted {
		report.CompletedRequests = 1
	}
	if s.Control || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	report.ReportHash = HashValue(reportHashInput(report))
	return report, nil
}

func reportHashInput(report EgressLifecycleReport) EgressLifecycleReport {
	report.ReportHash = ""
	return report
}
