// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

import "fmt"

var RequiredFailureModes = []string{
	"invalid_target_descriptor",
	"real_endpoint_rejected",
	"oversized_descriptor",
	"unsupported_ingress_kind",
	"unsupported_target_kind",
	"missing_adapter_capability",
	"missing_runtime_capability",
	"missing_security_precondition",
	"backpressure_limit_exceeded",
	"request_lifecycle_violation",
	"target_reset_before_open",
	"target_error_before_descriptor",
	"close_before_accept",
	"data_after_close",
	"malformed_metadata",
	"trace_hygiene_violation",
	"payload_leak_attempt",
	"secret_leak_attempt",
	"generated_backend_drift",
}

func DefaultFailureModes() []FailureModeReview {
	modes := make([]FailureModeReview, 0, len(RequiredFailureModes))
	for _, mode := range RequiredFailureModes {
		modes = append(modes, FailureModeReview{
			FailureMode:     mode,
			ExpectedOutcome: "safe_rejection_or_blocked_go_decision",
			CoveredByTest:   true,
			CoveredByGate:   true,
			Blocking:        true,
			RequiredTest:    "proxyingress_" + mode,
			RequiredGate:    "proxyingress_failure_mode_matrix",
			SafeErrorClass:  "safe_" + mode,
			TraceHygiene:    "metadata_only",
		})
	}
	return modes
}

func ValidateFailureModeMatrix(modes []FailureModeReview) error {
	if len(modes) < len(RequiredFailureModes) {
		return fmt.Errorf("%w: missing failure modes", ErrInvalidFailureMode)
	}
	seen := map[string]FailureModeReview{}
	for _, mode := range modes {
		if mode.FailureMode == "" || !mode.CoveredByTest || !mode.CoveredByGate || mode.PayloadLogged || mode.SecretLogged {
			return fmt.Errorf("%w: bad failure mode", ErrInvalidFailureMode)
		}
		seen[mode.FailureMode] = mode
	}
	for _, required := range RequiredFailureModes {
		if _, ok := seen[required]; !ok {
			return fmt.Errorf("%w: %s", ErrInvalidFailureMode, required)
		}
	}
	return nil
}
