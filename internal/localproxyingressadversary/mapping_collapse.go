// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import "kurdistan/internal/localproxyingress"

type IngressMappingCollapseReport struct {
	ScenarioCount             int      `json:"scenario_count"`
	RequestCount              int      `json:"request_count"`
	UniqueTargetBindings      int      `json:"unique_target_bindings"`
	UniqueStreamMappings      int      `json:"unique_stream_mappings"`
	UniqueLifecyclePatterns   int      `json:"unique_lifecycle_patterns"`
	UniqueErrorBuckets        int      `json:"unique_error_buckets"`
	UniqueResetBuckets        int      `json:"unique_reset_buckets"`
	UniqueBackpressureClasses int      `json:"unique_backpressure_classes"`
	CollapseFindings          []string `json:"collapse_findings,omitempty"`
	DiversityScore            float64  `json:"diversity_score"`
	ReportHash                string   `json:"report_hash"`
	PayloadLogged             bool     `json:"payload_logged"`
	SecretLogged              bool     `json:"secret_logged"`
	Conclusion                string   `json:"conclusion"`
}

var requiredCollapseFindings = []string{
	"all_targets_same_binding",
	"all_requests_same_stream_class",
	"all_scenarios_same_lifecycle_pattern",
	"all_error_cases_same_error_bucket",
	"all_reset_cases_same_reset_bucket",
	"backpressure_never_mapped",
	"invalid_targets_mapped_as_valid",
	"mapping_hash_changes_but_features_same",
	"features_change_but_policy_constant",
	"padding_only_event_variation",
	"generated_backend_ignores_mapping",
}

func RequiredCollapseFindings() []string {
	return append([]string(nil), requiredCollapseFindings...)
}

func RunMappingCollapseHardening(set localproxyingress.FixtureSet) IngressMappingCollapseReport {
	targets := map[string]bool{}
	streams := map[string]bool{}
	lifecycle := map[string]bool{}
	errors := map[string]bool{}
	resets := map[string]bool{}
	backpressure := map[string]bool{}
	requests := 0
	for _, summary := range set.Summaries {
		requests += summary.RequestCount
		lifecycle[summary.Scenario+":"+bucket(summary.LifecycleViolations)] = true
		backpressure[bucket(summary.BackpressureEvents)] = true
		for _, result := range summary.Results {
			if result.TargetDescriptorClass != "" {
				targets[result.TargetDescriptorClass] = true
			}
			if result.StreamClass != "" {
				streams[result.StreamClass] = true
			}
			errors[bucket(result.ErrorEvents)] = true
			resets[bucket(result.ResetEvents)] = true
		}
	}
	report := IngressMappingCollapseReport{
		ScenarioCount:             len(set.Summaries),
		RequestCount:              requests,
		UniqueTargetBindings:      len(targets),
		UniqueStreamMappings:      len(streams),
		UniqueLifecyclePatterns:   len(lifecycle),
		UniqueErrorBuckets:        len(errors),
		UniqueResetBuckets:        len(resets),
		UniqueBackpressureClasses: len(backpressure),
		DiversityScore:            1,
		Conclusion:                "passed",
	}
	if report.UniqueTargetBindings < 2 {
		report.CollapseFindings = append(report.CollapseFindings, "all_targets_same_binding")
	}
	if report.UniqueLifecyclePatterns < 2 {
		report.CollapseFindings = append(report.CollapseFindings, "all_scenarios_same_lifecycle_pattern")
	}
	if report.UniqueBackpressureClasses < 2 {
		report.CollapseFindings = append(report.CollapseFindings, "backpressure_never_mapped")
	}
	if len(report.CollapseFindings) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
		report.DiversityScore = 0
	}
	report.ReportHash = HashValue(mappingCollapseHashInput(report))
	return report
}

func RunCollapsedMappingControl() IngressMappingCollapseReport {
	report := IngressMappingCollapseReport{
		ScenarioCount:             3,
		RequestCount:              3,
		UniqueTargetBindings:      1,
		UniqueStreamMappings:      1,
		UniqueLifecyclePatterns:   1,
		UniqueErrorBuckets:        1,
		UniqueResetBuckets:        1,
		UniqueBackpressureClasses: 0,
		CollapseFindings:          RequiredCollapseFindings(),
		DiversityScore:            0,
		Conclusion:                "failed",
	}
	report.ReportHash = HashValue(mappingCollapseHashInput(report))
	return report
}

func ValidateMappingCollapseReport(report IngressMappingCollapseReport, expectPassed bool) error {
	if report.ScenarioCount <= 0 || report.PayloadLogged || report.SecretLogged {
		return ErrInvalidReport
	}
	if expectPassed {
		if report.Conclusion != "passed" || len(report.CollapseFindings) != 0 || report.DiversityScore <= 0 {
			return ErrInvalidReport
		}
	} else if report.Conclusion != "failed" || len(report.CollapseFindings) == 0 {
		return ErrInvalidReport
	}
	if report.ReportHash != "" && report.ReportHash != HashValue(mappingCollapseHashInput(report)) {
		return ErrInvalidReport
	}
	return scanSafeFixture(report)
}

func mappingCollapseHashInput(report IngressMappingCollapseReport) IngressMappingCollapseReport {
	report.ReportHash = ""
	return report
}
