// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

import "kurdistan/internal/proxyingress"

const Version = "proxyingress-review-v1"

const (
	DecisionGo                     = "go_for_deterministic_prototype"
	DecisionBlockedMissingContract = "blocked_missing_contract"
	DecisionBlockedMissingSecurity = "blocked_missing_security_precondition"
	DecisionBlockedTraceHygiene    = "blocked_trace_hygiene"
	DecisionBlockedRuntimeMapping  = "blocked_runtime_mapping"
	DecisionBlockedGeneratedParity = "blocked_generated_parity"
	RecommendedNextMilestone       = "M25 deterministic local proxy ingress prototype"
)

type ProxyIngressDesignReview struct {
	Version                  string                `json:"version"`
	ReviewID                 string                `json:"review_id"`
	ContractID               string                `json:"contract_id"`
	ChecklistItems           []ReviewChecklistItem `json:"checklist_items"`
	FailureModes             []FailureModeReview   `json:"failure_modes"`
	MissingPreconditions     []string              `json:"missing_preconditions,omitempty"`
	BlockingIssues           []string              `json:"blocking_issues,omitempty"`
	NonBlockingIssues        []string              `json:"non_blocking_issues,omitempty"`
	GoNoGoDecision           string                `json:"go_no_go_decision"`
	RecommendedNextMilestone string                `json:"recommended_next_milestone"`
	ReviewHash               string                `json:"review_hash"`
	PayloadLogged            bool                  `json:"payload_logged"`
	SecretLogged             bool                  `json:"secret_logged"`
}

type ReviewChecklistItem struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
	Blocking bool   `json:"blocking"`
}

type FailureModeReview struct {
	FailureMode     string `json:"failure_mode"`
	ExpectedOutcome string `json:"expected_outcome"`
	CoveredByTest   bool   `json:"covered_by_test"`
	CoveredByGate   bool   `json:"covered_by_gate"`
	Blocking        bool   `json:"blocking"`
	RequiredTest    string `json:"required_test"`
	RequiredGate    string `json:"required_gate"`
	SafeErrorClass  string `json:"safe_error_class"`
	TraceHygiene    string `json:"trace_hygiene"`
	PayloadLogged   bool   `json:"payload_logged"`
	SecretLogged    bool   `json:"secret_logged"`
}

func RunReview(contract proxyingress.ProxyIngressContract, requests []proxyingress.SyntheticProxyRequest, plans []proxyingress.RuntimeStreamMappingPlan, lifecycle []proxyingress.IngressLifecycleEvent, failureModes []FailureModeReview) (ProxyIngressDesignReview, error) {
	items := DefaultChecklist()
	blockers := []string{}
	decision := DecisionGo
	if err := proxyingress.ValidateContract(contract); err != nil {
		items = failItem(items, "contract_completeness", err.Error())
		blockers = append(blockers, "contract_completeness")
		decision = DecisionBlockedMissingContract
	}
	if err := proxyingress.ValidateRequests(requests, contract); err != nil {
		items = failItem(items, "target_descriptor_safety", err.Error())
		blockers = append(blockers, "target_descriptor_safety")
	}
	mapping := proxyingress.MapCapabilities(contract, proxyingress.DefaultAvailableCapabilities())
	if mapping.Conclusion != "passed" {
		items = failItem(items, "capability_mapping", "missing capability")
		blockers = append(blockers, "capability_mapping")
	}
	if len(plans) != len(requests) || len(plans) == 0 {
		items = failItem(items, "runtime_mapping", "mapping count mismatch")
		blockers = append(blockers, "runtime_mapping")
		decision = DecisionBlockedRuntimeMapping
	}
	if !hasCapability(contract.RequiredCapabilities, "secure_context_required") || !hasCapability(contract.RequiredCapabilities, "replay_rejection_required") {
		items = failItem(items, "security_preconditions", "security precondition missing")
		blockers = append(blockers, "security_preconditions")
		decision = DecisionBlockedMissingSecurity
	}
	if !hasCapability(contract.RequiredCapabilities, "trace_hygiene_required") {
		items = failItem(items, "trace_hygiene", "trace hygiene missing")
		blockers = append(blockers, "trace_hygiene")
		decision = DecisionBlockedTraceHygiene
	}
	if len(lifecycle) == 0 {
		items = failItem(items, "failure_modes", "lifecycle matrix missing")
		blockers = append(blockers, "failure_modes")
	}
	if err := ValidateFailureModeMatrix(failureModes); err != nil {
		items = failItem(items, "failure_modes", err.Error())
		blockers = append(blockers, "failure_modes")
	}
	if len(blockers) > 0 && decision == DecisionGo {
		decision = DecisionBlockedRuntimeMapping
	}
	review := ProxyIngressDesignReview{
		Version:                  Version,
		ReviewID:                 "proxyingress_design_review_v1",
		ContractID:               contract.ContractID,
		ChecklistItems:           items,
		FailureModes:             failureModes,
		BlockingIssues:           blockers,
		GoNoGoDecision:           decision,
		RecommendedNextMilestone: RecommendedNextMilestone,
	}
	review.ReviewHash = HashValue(reviewHashInput(review))
	return review, ValidateReview(review)
}

func hasCapability(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
