// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

import "kurdistan/internal/proxyingress"

type ProxyIngressMisuseReport struct {
	ContractID        string   `json:"contract_id"`
	RequestCount      int      `json:"request_count"`
	TargetCount       int      `json:"target_count"`
	LifecycleEvents   int      `json:"lifecycle_events"`
	BlockingIssues    int      `json:"blocking_issues"`
	UnsafeTargets     int      `json:"unsafe_targets"`
	UnboundedLimits   int      `json:"unbounded_limits"`
	MappingFailures   int      `json:"mapping_failures"`
	HygieneFailures   int      `json:"hygiene_failures"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
	Conclusion        string   `json:"conclusion"`
}

func ScanMisuse(contract proxyingress.ProxyIngressContract, requests []proxyingress.SyntheticProxyRequest, plans []proxyingress.RuntimeStreamMappingPlan, lifecycle []proxyingress.IngressLifecycleEvent, review ProxyIngressDesignReview) ProxyIngressMisuseReport {
	report := ProxyIngressMisuseReport{
		ContractID:      contract.ContractID,
		RequestCount:    len(requests),
		TargetCount:     len(requests),
		LifecycleEvents: len(lifecycle),
		Conclusion:      "passed",
	}
	if err := proxyingress.ValidateContract(contract); err != nil {
		report.BlockingIssues++
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "contract_invalid")
	}
	for _, request := range requests {
		if err := proxyingress.ValidateTargetDescriptor(request.Target, contract.Limits); err != nil {
			report.UnsafeTargets++
		}
		if request.PayloadLogged || request.SecretLogged {
			report.HygieneFailures++
		}
	}
	if len(plans) != len(requests) {
		report.MappingFailures++
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "mapping_count_mismatch")
	}
	if allSameStreamClass(plans) && len(plans) > 1 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "all_requests_same_mapping")
	}
	if len(lifecycle) == 0 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "lifecycle_missing")
	}
	if review.GoNoGoDecision == DecisionGo && len(review.BlockingIssues) > 0 {
		report.BlockingIssues++
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "review_go_despite_blocker")
	}
	report.PayloadLogged = contract.PayloadLogged || review.PayloadLogged
	report.SecretLogged = contract.SecretLogged || review.SecretLogged
	if report.BlockingIssues > 0 || report.UnsafeTargets > 0 || report.UnboundedLimits > 0 || report.MappingFailures > 0 || report.HygieneFailures > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func allSameStreamClass(plans []proxyingress.RuntimeStreamMappingPlan) bool {
	if len(plans) == 0 {
		return false
	}
	first := plans[0].StreamClass
	for _, plan := range plans[1:] {
		if plan.StreamClass != first {
			return false
		}
	}
	return true
}
