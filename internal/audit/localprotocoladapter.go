// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/localprotocoladapter"
	"kurdistan/internal/mutant"
)

type LocalProtocolAdapterAuditSummary struct {
	Version      string                                       `json:"version"`
	RequestCount int                                          `json:"request_count"`
	Comparison   localprotocoladapter.FixtureComparisonReport `json:"comparison"`
	Conclusion   string                                       `json:"conclusion"`
}

func RunLocalProtocolAdapterAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := localprotocoladapter.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := localProtocolAdapterComparison(filepath.Join(root, "testdata", "localprotocoladapter", "localprotocoladapter-report-golden.json"), set)
	gates := LocalProtocolAdapterGates(set, comparison)
	summary := LocalProtocolAdapterAuditSummary{
		Version:      localprotocoladapter.Version,
		RequestCount: len(set.Requests),
		Comparison:   comparison,
		Conclusion:   "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "localprotocoladapter-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		TraceCount:       0,
		Gates:            gates,
		TraceScanSummary: summary,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
		summary.Conclusion = "failed"
		report.TraceScanSummary = summary
	}
	return report, nil
}

func LocalProtocolAdapterGates(set localprotocoladapter.LocalProtocolFixtureSet, comparison localprotocoladapter.FixtureComparisonReport) []GateResult {
	return []GateResult{
		LocalProtocolAdapterConfigValidationGate(set),
		LocalProtocolAdapterConnectLikeGate(set),
		LocalProtocolAdapterSocks5LikeGate(set),
		LocalProtocolAdapterTargetRedactionGate(set),
		LocalProtocolAdapterStateMachineGate(set),
		LocalProtocolAdapterConcreteIntegrationGate(set),
		LocalProtocolAdapterPipelineMappingGate(set),
		LocalProtocolAdapterResourceLimitGate(set),
		LocalProtocolAdapterErrorRedactionGate(set),
		LocalProtocolAdapterMisuseGate(set),
		LocalProtocolAdapterGeneratedBackendParityGate(set),
		LocalProtocolAdapterTraceHygieneGate(set),
		LocalProtocolAdapterMutantDetectionGate(),
		LocalProtocolAdapterFixtureDriftGate(comparison),
	}
}

func LocalProtocolAdapterConfigValidationGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	if err := localprotocoladapter.ValidateConfig(set.Config); err != nil {
		failures = append(failures, err.Error())
	}
	if set.ConfigReport.Conclusion != "passed" || set.ConfigReport.OutboundDialRejected == 0 || set.ConfigReport.DNSResolutionRejected == 0 || set.ConfigReport.PayloadForwardingRejected == 0 {
		failures = append(failures, "parser config control coverage incomplete")
	}
	return gate("localprotocoladapter_config_validation", len(failures) == 0, "required", fmt.Sprintf("%d configs checked", set.ConfigReport.ConfigsChecked), nil, failures)
}

func LocalProtocolAdapterConnectLikeGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	if set.ConnectReport.Conclusion != "passed" || set.ConnectReport.RequestsParsed == 0 || set.ConnectReport.HeaderSmugglingRejected == 0 || set.ConnectReport.AbsoluteURLRejected == 0 {
		failures = append(failures, "CONNECT-like metadata parser coverage incomplete")
	}
	return gate("localprotocoladapter_connect_like_parser", len(failures) == 0, "required", fmt.Sprintf("%d CONNECT-like parser runs", set.ConnectReport.ParserRuns), nil, failures)
}

func LocalProtocolAdapterSocks5LikeGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	if set.Socks5Report.Conclusion != "passed" || set.Socks5Report.RequestsParsed == 0 || set.Socks5Report.UnsupportedAuthRejected == 0 || set.Socks5Report.UnsupportedCommandRejected == 0 {
		failures = append(failures, "SOCKS5-like metadata parser coverage incomplete")
	}
	return gate("localprotocoladapter_socks5_like_parser", len(failures) == 0, "required", fmt.Sprintf("%d SOCKS5-like parser runs", set.Socks5Report.ParserRuns), nil, failures)
}

func LocalProtocolAdapterTargetRedactionGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	if set.RedactionReport.Conclusion != "passed" || set.RedactionReport.ExactTargetLeaks != 0 || set.RedactionReport.ExactPortLeaks != 0 {
		failures = append(failures, "target redaction report failed")
	}
	for _, req := range set.Requests {
		if req.ExactTargetPersisted || req.ExactPortPersisted {
			failures = append(failures, "exact target or port persisted")
		}
	}
	return gate("localprotocoladapter_target_redaction", len(failures) == 0, "required", fmt.Sprintf("%d targets redacted", set.RedactionReport.TargetsRedacted), nil, failures)
}

func LocalProtocolAdapterStateMachineGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	if set.StateReport.Conclusion != "passed" || set.StateReport.Closed == 0 || set.StateReport.ReportHash == "" {
		failures = append(failures, "parser state machine report failed")
	}
	return gate("localprotocoladapter_state_machine", len(failures) == 0, "required", fmt.Sprintf("%d parser transitions checked", len(set.StateReport.Transitions)), nil, failures)
}

func LocalProtocolAdapterConcreteIntegrationGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	if set.Report.ConnectionsChecked == 0 || set.Report.OutboundDialEvents != 0 || set.Report.DNSResolutionEvents != 0 {
		failures = append(failures, "concrete adapter integration used forbidden behavior")
	}
	return gate("localprotocoladapter_concrete_adapter_integration", len(failures) == 0, "required", fmt.Sprintf("%d local connection descriptors checked", set.Report.ConnectionsChecked), nil, failures)
}

func LocalProtocolAdapterPipelineMappingGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	if set.Report.PipelineMappings == 0 {
		failures = append(failures, "no safe localpipeline mappings produced")
	}
	for _, req := range set.Requests {
		if req.ParserState == localprotocoladapter.ParserStateMapped && !strings.Contains(req.PipelineMappingClass, "localpipeline") {
			failures = append(failures, "mapped request lacks localpipeline class")
		}
	}
	return gate("localprotocoladapter_localpipeline_mapping", len(failures) == 0, "required", fmt.Sprintf("%d localpipeline mappings", set.Report.PipelineMappings), nil, failures)
}

func LocalProtocolAdapterResourceLimitGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	if set.Config.MaxHeaderBytes <= 0 || set.Config.MaxBufferedBytes <= 0 || set.Report.ResourceLimitEvents == 0 {
		failures = append(failures, "resource limits not exercised")
	}
	return gate("localprotocoladapter_resource_limits", len(failures) == 0, "required", fmt.Sprintf("%d resource limit controls", set.Report.ResourceLimitEvents), nil, failures)
}

func LocalProtocolAdapterErrorRedactionGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	for _, req := range set.Requests {
		if strings.Contains(req.RejectedReasonClass, ".") || strings.Contains(req.RejectedReasonClass, ":") || strings.Contains(req.RejectedReasonClass, "CONNECT ") {
			failures = append(failures, "raw parser error material leaked")
		}
	}
	return gate("localprotocoladapter_error_redaction", len(failures) == 0, "required", "parser errors are stable classes", nil, failures)
}

func LocalProtocolAdapterMisuseGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := append([]string{}, set.Misuse.Findings...)
	if set.Misuse.Conclusion != "passed" || set.Misuse.UnsafeDetected < 8 || set.Misuse.LeakControlsDetected < 4 {
		failures = append(failures, "misuse controls incomplete")
	}
	return gate("localprotocoladapter_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d unsafe controls detected", set.Misuse.UnsafeDetected), nil, failures)
}

func LocalProtocolAdapterGeneratedBackendParityGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := append([]string{}, set.Parity.UnexpectedDifferences...)
	if set.Parity.Conclusion != "passed" {
		failures = append(failures, "generated/interpreted localprotocoladapter parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"localprotocoladapter_generated.go", "localprotocoladapter_test.go", "localprotocoladapter_parity_test.go", "localprotocoladapter_hygiene_test.go", "LocalProtocolAdapterSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated localprotocoladapter marker "+marker)
				}
			}
		}
	}
	return gate("localprotocoladapter_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d requests compared", set.Parity.ComparedRequests), nil, failures)
}

func LocalProtocolAdapterTraceHygieneGate(set localprotocoladapter.LocalProtocolFixtureSet) GateResult {
	failures := []string{}
	if err := localprotocoladapter.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	for _, unsafe := range []map[string]string{{"raw_payload": "x"}, {"dns_query": "x"}, {"credential": "x"}, {"destination_address": "x"}} {
		if err := localprotocoladapter.ScanForLeak(unsafe); err == nil {
			failures = append(failures, "unsafe local protocol metadata accepted")
		}
	}
	return gate("localprotocoladapter_trace_hygiene", len(failures) == 0, "required", "local protocol fixtures contain safe metadata only", nil, failures)
}

func LocalProtocolAdapterMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeLocalProtocolAdapterAllowsOutboundDial,
		mutant.ModeLocalProtocolAdapterAllowsDNSResolution,
		mutant.ModeLocalProtocolAdapterAllowsPayloadForwarding,
		mutant.ModeLocalProtocolAdapterPersistsTarget,
		mutant.ModeLocalProtocolAdapterAcceptsCredentials,
		mutant.ModeLocalProtocolAdapterAcceptsUDPAssociate,
		mutant.ModeLocalProtocolAdapterHeaderSmuggling,
		mutant.ModeLocalProtocolAdapterGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("localprotocoladapter_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d localprotocoladapter mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func LocalProtocolAdapterFixtureDriftGate(report localprotocoladapter.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("localprotocoladapter_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func localProtocolAdapterComparison(path string, current localprotocoladapter.LocalProtocolFixtureSet) localprotocoladapter.FixtureComparisonReport {
	oldSet, err := localprotocoladapter.LoadFixtureSet(path)
	if err != nil {
		return localprotocoladapter.FixtureComparisonReport{Version: localprotocoladapter.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return localprotocoladapter.CompareFixtureSets(oldSet, current)
}
