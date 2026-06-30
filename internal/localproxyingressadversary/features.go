// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import "kurdistan/internal/localproxyingress"

type FeatureVector struct {
	Scenario            string            `json:"scenario"`
	RequestCount        int               `json:"request_count"`
	AcceptedRequests    int               `json:"accepted_requests"`
	RejectedRequests    int               `json:"rejected_requests"`
	StreamMappings      int               `json:"stream_mappings"`
	BackpressureEvents  int               `json:"backpressure_events"`
	ResetEvents         int               `json:"reset_events"`
	TargetErrorEvents   int               `json:"target_error_events"`
	LifecycleViolations int               `json:"lifecycle_violations"`
	SummaryHash         string            `json:"summary_hash"`
	Buckets             map[string]string `json:"buckets"`
	PayloadLogged       bool              `json:"payload_logged"`
	SecretLogged        bool              `json:"secret_logged"`
}

func ExtractFeatures(summary localproxyingress.LocalProxyIngressSummary) FeatureVector {
	return FeatureVector{
		Scenario:            summary.Scenario,
		RequestCount:        summary.RequestCount,
		AcceptedRequests:    summary.AcceptedRequests,
		RejectedRequests:    summary.RejectedRequests,
		StreamMappings:      summary.StreamMappings,
		BackpressureEvents:  summary.BackpressureEvents,
		ResetEvents:         summary.ResetEvents,
		TargetErrorEvents:   summary.TargetErrorEvents,
		LifecycleViolations: summary.LifecycleViolations,
		SummaryHash:         summary.SummaryHash,
		Buckets:             map[string]string{"request_count": bucket(summary.RequestCount), "backpressure": bucket(summary.BackpressureEvents)},
		PayloadLogged:       summary.PayloadLogged,
		SecretLogged:        summary.SecretLogged,
	}
}

func bucket(n int) string {
	switch {
	case n == 0:
		return "zero"
	case n <= 2:
		return "small"
	case n <= 8:
		return "medium"
	default:
		return "large"
	}
}
