// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

type BackpressureReport struct {
	Scenario              string `json:"scenario"`
	RequestCount          int    `json:"request_count"`
	PressureEvents        int    `json:"pressure_events"`
	QueueLimitHits        int    `json:"queue_limit_hits"`
	RequestLimitHits      int    `json:"request_limit_hits"`
	RuntimePressureMapped int    `json:"runtime_pressure_mapped"`
	DroppedEvents         int    `json:"dropped_events"`
	RejectedRequests      int    `json:"rejected_requests"`
	PayloadLogged         bool   `json:"payload_logged"`
	SecretLogged          bool   `json:"secret_logged"`
	Conclusion            string `json:"conclusion"`
}

func BackpressureFromSummary(summary LocalProxyIngressSummary, stats IngressQueueStats) BackpressureReport {
	conclusion := "passed"
	if summary.PayloadLogged || summary.SecretLogged {
		conclusion = "failed"
	}
	return BackpressureReport{
		Scenario:              summary.Scenario,
		RequestCount:          summary.RequestCount,
		PressureEvents:        summary.BackpressureEvents,
		QueueLimitHits:        stats.OverflowRejected,
		RuntimePressureMapped: summary.BackpressureEvents,
		DroppedEvents:         stats.EventsDropped,
		RejectedRequests:      summary.RejectedRequests,
		PayloadLogged:         summary.PayloadLogged,
		SecretLogged:          summary.SecretLogged,
		Conclusion:            conclusion,
	}
}
