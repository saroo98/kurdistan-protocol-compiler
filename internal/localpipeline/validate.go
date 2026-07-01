// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localpipeline

import (
	"encoding/json"
	"fmt"
	"strings"
)

func ValidateFixtureSet(set PipelineFixtureSet) error {
	if set.Version != Version {
		return safeError("unknown_schema")
	}
	if set.SchemaName != DefaultPipelineSchemaName || len(set.Scenarios) < 10 || len(set.Runs) < 10 {
		return safeError("incomplete_fixture_set")
	}
	for _, scenario := range set.Scenarios {
		if err := ValidateScenario(scenario); err != nil {
			return err
		}
	}
	for _, run := range set.Runs {
		if err := ValidateRun(run); err != nil && run.Conclusion != "failed" {
			return err
		}
	}
	if set.Boundary.Conclusion != "passed" || set.Collapse.Conclusion != "passed" || set.Misuse.Conclusion != "passed" || set.Parity.Conclusion != "passed" {
		return safeError("report_failed")
	}
	if set.PayloadLogged || set.SecretLogged {
		return safeError("unsafe_trace_flags")
	}
	return ScanForLeak(set)
}

func ValidateScenario(s PipelineScenario) error {
	if s.ScenarioID == "" || s.Kind == "" || s.IngressClass == "" || s.EgressClass == "" || s.BridgeClass == "" || s.RuntimeClass == "" || s.CarrierClass == "" {
		return safeError("missing_scenario_class")
	}
	if s.ExpectedFlows < 0 || s.ExpectedRuntimeStreams < 0 || s.ExpectedBackpressure < 0 || s.ExpectedErrors < 0 || s.ExpectedResets < 0 {
		return safeError("negative_count")
	}
	if s.ExpectedFlows > 16 || s.ExpectedRuntimeStreams > 16 || s.ExpectedBackpressure > 32 {
		return safeError("unsafe_pipeline_limit")
	}
	if s.PayloadLogged || s.SecretLogged {
		return safeError("unsafe_scenario_flags")
	}
	return ScanForLeak(s)
}

func ValidateRun(run PipelineRunSummary) error {
	if run.Version != Version || run.ScenarioID == "" || run.Kind == "" || run.FinalState == "" || run.RunHash == "" {
		return safeError("invalid_run_summary")
	}
	if run.IngressRequests < 0 || run.EgressRequests < 0 || run.RuntimeStreams < 0 || run.CarrierEnvelopes < 0 || run.ByteFrames < 0 {
		return safeError("negative_run_count")
	}
	if run.IngressRequests > 16 || run.RuntimeStreams > 16 || run.CarrierEnvelopes > 64 || run.ByteFrames > 128 {
		return safeError("unsafe_run_limit")
	}
	if run.PayloadLogged || run.SecretLogged {
		return safeError("unsafe_run_flags")
	}
	return ScanForLeak(run)
}

func ScanMisuse(value any) PipelineMisuseReport {
	report := PipelineMisuseReport{Version: Version, ObjectsScanned: 1, Conclusion: "passed"}
	if err := ScanForLeak(value); err != nil {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, err.Error())
	}
	report.SuspiciousMetrics = uniqueSorted(report.SuspiciousMetrics)
	if len(report.SuspiciousMetrics) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	return scanValue(decoded, "")
}

func scanValue(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, val := range typed {
			normalized := strings.ToLower(key)
			if normalized == "payload_logged" || normalized == "secret_logged" {
				if b, ok := val.(bool); ok && b {
					return fmt.Errorf("unsafe true hygiene flag %s", key)
				}
			} else if isForbiddenToken(normalized) {
				return fmt.Errorf("forbidden localpipeline field %s", key)
			}
			if err := scanValue(val, key); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := scanValue(item, path); err != nil {
				return err
			}
		}
	case string:
		normalized := strings.ToLower(typed)
		if strings.HasPrefix(path, "forbidden") || path == "notes" {
			return nil
		}
		if isForbiddenToken(normalized) {
			return fmt.Errorf("forbidden localpipeline value in %s", path)
		}
	}
	return nil
}

func isForbiddenToken(value string) bool {
	for _, token := range []string{
		"raw_payload", "payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext",
		"pcap", "packet_dump", "capture_bytes", "packet_capture", "destination_address", "endpoint",
		"real_host", "proxy_ip", "server_ip", "client_ip", "domain", "sni", "host_header", "url", "uri",
		"ip_address", "dns_query", "resolver", "resolver_ip", "nameserver", "cloud_provider", "aws", "gcp",
		"azure", "region", "instance_id", "credential", "account_id", "phone_number", "sim_id", "imsi",
		"imei", "device_id", "precise_location", "gps", "latitude", "longitude", "secret", "derived_key",
		"client_write_key", "server_write_key", "nonce", "nonce_base", "auth_tag", "proof_material",
		"private_key", "session_secret", "real_relay", "dial_real", "socket_address",
	} {
		if value == token || strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
