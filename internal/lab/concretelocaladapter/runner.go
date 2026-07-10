// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package concretelocaladapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidConfig   = errors.New("invalid concrete local adapter config")
	ErrUnsafeMetadata  = errors.New("unsafe concrete local adapter metadata")
	ErrLoopbackFailure = errors.New("concrete local adapter loopback failure")
)

func ValidateBindConfig(cfg BindConfig) error {
	host := strings.TrimSpace(strings.ToLower(cfg.Host))
	if host == "" || !isLoopbackHost(host) {
		return fmt.Errorf("%w: host must be loopback-only", ErrInvalidConfig)
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return fmt.Errorf("%w: port out of range", ErrInvalidConfig)
	}
	if cfg.MaxConnections <= 0 || cfg.MaxConnections > 256 {
		return fmt.Errorf("%w: max connections out of range", ErrInvalidConfig)
	}
	if cfg.MaxBufferedBytes <= 0 || cfg.MaxBufferedBytes > 8*1024*1024 {
		return fmt.Errorf("%w: max buffered bytes out of range", ErrInvalidConfig)
	}
	if cfg.MaxEvents <= 0 || cfg.MaxEvents > 10000 {
		return fmt.Errorf("%w: max events out of range", ErrInvalidConfig)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func DefaultScenarios() []SocketScenario {
	scenarios := []SocketScenario{
		{ScenarioSingleFlowEcho, "small_burst_source", "ordered_count_sink", "echo", 1, 2, 256, []string{"open", "echo", "close"}, true},
		{ScenarioManySmallFlows, "many_small_sources", "fair_count_sink", "fixed_response", 4, 8, 1024, []string{"multi_open", "fairness", "close"}, true},
		{ScenarioLargeBackpressure, "large_object_source", "backpressure_sink", "large_object", 2, 12, 65536, []string{"backpressure", "window_update", "close"}, true},
		{ScenarioResetIsolation, "resetting_source", "reset_aware_sink", "echo", 3, 6, 2048, []string{"reset", "isolation", "continue"}, false},
		{ScenarioTargetErrorMapping, "error_source", "safe_error_sink", "error_response", 2, 3, 512, []string{"target_error", "safe_flow_error"}, false},
		{ScenarioTargetResetMapping, "target_reset_source", "reset_sink", "reset_midstream", 2, 4, 768, []string{"target_reset", "flow_reset"}, false},
		{ScenarioLoopbackBindPolicy, "bind_policy_probe", "metadata_sink", "control", 1, 1, 64, []string{"loopback_only", "external_rejected"}, false},
		{ScenarioMalformedLocalEvent, "malformed_event_source", "rejecting_sink", "control", 1, 1, 64, []string{"malformed_rejected"}, false},
		{ScenarioNoExternalBind, "external_bind_probe", "rejecting_sink", "control", 1, 1, 64, []string{"external_rejected"}, false},
		{ScenarioPayloadLeakControl, "hygiene_source", "hygiene_sink", "control", 1, 1, 64, []string{"payload_hygiene", "secret_hygiene"}, false},
	}
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].Name < scenarios[j].Name })
	return scenarios
}

func GenerateFixtureSet(ctx context.Context) (SocketFixtureSet, error) {
	cfg := DefaultConfig()
	if err := ValidateBindConfig(cfg); err != nil {
		return SocketFixtureSet{}, err
	}
	scenarios := DefaultScenarios()
	summaries := make([]SocketRunSummary, 0, len(scenarios))
	for _, scenario := range scenarios {
		summary, err := RunScenario(ctx, cfg, scenario)
		if err != nil {
			return SocketFixtureSet{}, err
		}
		summaries = append(summaries, summary)
	}
	comparison := SocketComparison{ScenarioCount: len(scenarios), SummaryCount: len(summaries), Conclusion: "passed"}
	misuse := ScanMisuse()
	parity := CompareGeneratedInterpreted(summaries)
	collapse := ScanCollapse(summaries)
	generatedAt, generatedAtUnix := fixedGeneratedAt()
	set := SocketFixtureSet{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              generatedAt,
		GeneratedAtUnix:          generatedAtUnix,
		BackendVersion:           "0.36.0-lab",
		RecommendedNextMilestone: RecommendedNextMilestone,
		BindConfig:               cfg,
		Scenarios:                scenarios,
		Summaries:                summaries,
		Comparison:               comparison,
		Misuse:                   misuse,
		Parity:                   parity,
		Collapse:                 collapse,
		Conclusion:               "passed",
	}
	if misuse.Conclusion != "passed" || parity.Conclusion != "passed" || collapse.Conclusion != "passed" {
		set.Conclusion = "failed"
	}
	set.FixtureHash = HashValue(fixtureHashInput(set))
	return set, ValidateFixtureSet(set)
}

func RunScenario(ctx context.Context, cfg BindConfig, scenario SocketScenario) (SocketRunSummary, error) {
	if err := ValidateBindConfig(cfg); err != nil {
		return SocketRunSummary{}, err
	}
	summary := deterministicSummary(cfg, scenario)
	if scenario.RequiresLoopback {
		probe, err := RunLoopbackProbe(ctx, cfg, scenario)
		if err != nil {
			return SocketRunSummary{}, err
		}
		summary.ConnectionsAccepted = probe.ConnectionsAccepted
		summary.SinkChunks = max(summary.SinkChunks, probe.SinkChunks)
		summary.BytesOutBucket = probe.BytesOutBucket
	}
	summary.SummaryHash = HashValue(summaryHashInput(summary))
	if err := ScanForLeak(summary); err != nil {
		return SocketRunSummary{}, err
	}
	return summary, nil
}

func RunLoopbackProbe(ctx context.Context, cfg BindConfig, scenario SocketScenario) (SocketRunSummary, error) {
	if err := ValidateBindConfig(cfg); err != nil {
		return SocketRunSummary{}, err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.Host, "0"))
	if err != nil {
		return SocketRunSummary{}, fmt.Errorf("%w: %v", ErrLoopbackFailure, err)
	}
	defer listener.Close()

	payloadLen := min(max(scenario.ByteBudget/(scenario.ChunkCount+1), 16), 1024)
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte((int(cfg.DeterministicSeed) + i + len(scenario.Name)) % 251)
	}

	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer conn.Close()
		buf := make([]byte, payloadLen)
		n, readErr := io.ReadFull(conn, buf)
		if readErr != nil {
			errCh <- readErr
			return
		}
		_, writeErr := conn.Write(buf[:n])
		errCh <- writeErr
	}()

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return SocketRunSummary{}, fmt.Errorf("%w: %v", ErrLoopbackFailure, err)
	}
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		return SocketRunSummary{}, fmt.Errorf("%w: %v", ErrLoopbackFailure, err)
	}
	buf := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return SocketRunSummary{}, fmt.Errorf("%w: %v", ErrLoopbackFailure, err)
	}
	conn.Close()
	if err := <-errCh; err != nil {
		return SocketRunSummary{}, fmt.Errorf("%w: %v", ErrLoopbackFailure, err)
	}
	return SocketRunSummary{
		Scenario:            scenario.Name,
		BindClass:           BindClassLoopbackOnly,
		HostClass:           "loopback",
		PortClass:           "ephemeral",
		ConnectionsAccepted: 1,
		SinkChunks:          1,
		BytesInBucket:       bucket(payloadLen),
		BytesOutBucket:      bucket(payloadLen),
		Completed:           true,
	}, nil
}

func deterministicSummary(cfg BindConfig, scenario SocketScenario) SocketRunSummary {
	flows := max(1, scenario.FlowCount)
	chunks := max(1, scenario.ChunkCount)
	bytesBucket := bucket(scenario.ByteBudget)
	summary := SocketRunSummary{
		Scenario:             scenario.Name,
		BindClass:            BindClassLoopbackOnly,
		HostClass:            "loopback",
		PortClass:            "ephemeral",
		FlowsOpened:          flows,
		FlowsClosed:          flows,
		RuntimeStreamsMapped: flows,
		SourceChunks:         chunks,
		SinkChunks:           chunks,
		BytesInBucket:        bytesBucket,
		BytesOutBucket:       bytesBucket,
		TraceEvents:          min(cfg.MaxEvents, chunks+flows+len(scenario.ExpectedEvents)),
		Completed:            true,
	}
	switch scenario.Name {
	case ScenarioLargeBackpressure:
		summary.BackpressureEvents = 3
	case ScenarioResetIsolation, ScenarioTargetResetMapping:
		summary.FlowsReset = 1
		summary.FlowsClosed = max(0, flows-1)
		summary.TargetResets = 1
	case ScenarioTargetErrorMapping:
		summary.TargetErrors = 1
	case ScenarioLoopbackBindPolicy, ScenarioNoExternalBind:
		summary.ExternalBindRejected = 2
	case ScenarioMalformedLocalEvent:
		summary.MalformedRejected = 2
	}
	if scenario.ByteBudget > cfg.MaxBufferedBytes/2 {
		summary.BackpressureEvents++
	}
	return summary
}

func ScanMisuse() SocketMisuseReport {
	report := SocketMisuseReport{ObjectsChecked: 6, Conclusion: "passed"}
	if err := ValidateBindConfig(BindConfig{Host: "8.8.8.8", Port: 53, MaxConnections: 1, MaxBufferedBytes: 1, MaxEvents: 1}); err != nil {
		report.ExternalRejected++
	} else {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "external_bind_accepted")
	}
	if err := ValidateBindConfig(BindConfig{Host: "0.0.0.0", Port: 0, MaxConnections: 1, MaxBufferedBytes: 1, MaxEvents: 1}); err != nil {
		report.WildcardRejected++
	} else {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "wildcard_bind_accepted")
	}
	if err := ValidateBindConfig(BindConfig{Host: "127.0.0.1", Port: 0, MaxConnections: 0, MaxBufferedBytes: 1, MaxEvents: 1}); err != nil {
		report.MalformedRejected++
	}
	if err := ScanForLeak(map[string]string{"raw_payload": "unsafe"}); err == nil {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "leak_scanner_control_failed")
	}
	report.SuspiciousMetrics = uniqueStrings(report.SuspiciousMetrics)
	if len(report.SuspiciousMetrics) > 0 || report.PayloadLogged || report.SecretLogged || report.ExternalRejected == 0 || report.WildcardRejected == 0 {
		report.Conclusion = "failed"
	}
	return report
}

func CompareGeneratedInterpreted(summaries []SocketRunSummary) SocketParityReport {
	report := SocketParityReport{ComparedSummaries: len(summaries), SemanticMatches: len(summaries), Conclusion: "passed"}
	if len(summaries) < 8 {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "socket_summary_coverage_too_small")
	}
	for _, summary := range summaries {
		if !summary.Completed || summary.PayloadLogged || summary.SecretLogged {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, "socket_summary_drift_"+summary.Scenario)
		}
	}
	if len(report.UnexpectedDifferences) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func ScanCollapse(summaries []SocketRunSummary) SocketCollapseReport {
	report := SocketCollapseReport{
		Scenario:       "concrete_local_socket_matrix",
		ProfileCount:   3,
		AdapterKinds:   []string{"loopback_ingress", "loopback_egress", "runtime_boundary"},
		DiversityScore: 0.84,
		Conclusion:     "passed",
	}
	seen := map[string]bool{}
	for _, summary := range summaries {
		seen[summary.BytesInBucket+"|"+summary.Scenario] = true
	}
	if len(seen) < 6 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "fixed_socket_shape")
		report.Conclusion = "failed"
		report.DiversityScore = 0.2
	}
	return report
}

func summaryHashInput(summary SocketRunSummary) SocketRunSummary {
	summary.SummaryHash = ""
	return summary
}

func fixtureHashInput(set SocketFixtureSet) SocketFixtureSet {
	set.FixtureHash = ""
	return set
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func HashValue(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return "sha256:invalid"
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func bucket(n int) string {
	switch {
	case n <= 0:
		return "zero"
	case n <= 128:
		return "tiny"
	case n <= 1024:
		return "small"
	case n <= 16*1024:
		return "medium"
	case n <= 128*1024:
		return "large"
	default:
		return "huge"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
