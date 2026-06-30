// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

type ErrorResetReport struct {
	Scenario          string `json:"scenario"`
	RequestCount      int    `json:"request_count"`
	ResetEvents       int    `json:"reset_events"`
	TargetErrorEvents int    `json:"target_error_events"`
	IsolationPassed   bool   `json:"isolation_passed"`
	PayloadLogged     bool   `json:"payload_logged"`
	SecretLogged      bool   `json:"secret_logged"`
	Conclusion        string `json:"conclusion"`
}

func ErrorResetFromSummary(summary LocalProxyIngressSummary) ErrorResetReport {
	isolated := summary.ResetEvents+summary.TargetErrorEvents <= summary.RequestCount
	conclusion := "passed"
	if !isolated || summary.PayloadLogged || summary.SecretLogged {
		conclusion = "failed"
	}
	return ErrorResetReport{
		Scenario:          summary.Scenario,
		RequestCount:      summary.RequestCount,
		ResetEvents:       summary.ResetEvents,
		TargetErrorEvents: summary.TargetErrorEvents,
		IsolationPassed:   isolated,
		PayloadLogged:     summary.PayloadLogged,
		SecretLogged:      summary.SecretLogged,
		Conclusion:        conclusion,
	}
}
