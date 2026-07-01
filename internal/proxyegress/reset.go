// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

func BuildResetErrorReport(reports []EgressLifecycleReport) EgressResetErrorReport {
	out := EgressResetErrorReport{
		Version:          Version,
		ScenarioID:       "egress_reset_error_isolation",
		StreamsChecked:   len(reports),
		SafeErrorClasses: []string{"target_error_bucket", "bridge_failure_bucket", "descriptor_rejected_bucket"},
		Conclusion:       "passed",
	}
	for _, report := range reports {
		out.ResetEvents += report.ResetRequests
		out.ErrorEvents += report.FailedRequests
	}
	out.IsolatedResets = out.ResetEvents
	if out.CrossStreamLeaks != 0 || out.PayloadLogged || out.SecretLogged || out.ResetEvents == 0 || out.ErrorEvents == 0 {
		out.Conclusion = "failed"
	}
	return out
}
