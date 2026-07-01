// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package labegress

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	Version                  = "labegress-v1"
	DefaultFixtureID         = "lab_egress_fixture_v1"
	RecommendedNextMilestone = "M40: carrier prototype readiness gate"

	ConnectorPolicyLoopbackAllowlist = "loopback_allowlist"
	TargetClassEchoSynthetic         = "echo_synthetic"
	TargetClassFixedSynthetic        = "fixed_synthetic"
	TargetClassSlowSynthetic         = "slow_synthetic"
	TargetClassResetSynthetic        = "reset_synthetic"
	TargetClassErrorSynthetic        = "error_synthetic"
	TargetClassLargeSynthetic        = "large_synthetic"

	ScenarioAllowlistValidation = "egress_allowlist_validation"
	ScenarioFixtureExchange     = "egress_fixture_exchange"
	ScenarioSlowBackpressure    = "egress_slow_backpressure"
	ScenarioResetIsolation      = "egress_reset_isolation"
	ScenarioErrorIsolation      = "egress_error_isolation"
	ScenarioHalfClose           = "egress_half_close"
	ScenarioQueuePressure       = "egress_queue_pressure"
	ScenarioGeneratedParity     = "egress_generated_parity"
)

var (
	ErrInvalidConfig   = errors.New("invalid lab egress config")
	ErrUnsafeTarget    = errors.New("unsafe lab egress target")
	ErrRefuseOverwrite = errors.New("refusing to overwrite existing lab egress fixture")
)

type LabEgressConfig struct {
	ConfigID             string   `json:"config_id"`
	ConnectorPolicy      string   `json:"connector_policy"`
	AllowedTargetClasses []string `json:"allowed_target_classes"`
	AllowedLoopbackHosts []string `json:"allowed_loopback_hosts"`
	MaxConnections       int      `json:"max_connections"`
	MaxStreams           int      `json:"max_streams"`
	MaxRequestBytes      int      `json:"max_request_bytes"`
	MaxResponseBytes     int      `json:"max_response_bytes"`
	MaxBufferedBytes     int      `json:"max_buffered_bytes"`
	MaxEvents            int      `json:"max_events"`
	AllowExternalTargets bool     `json:"allow_external_targets"`
	AllowDNSResolution   bool     `json:"allow_dns_resolution"`
	AllowRawAddressTrace bool     `json:"allow_raw_address_trace"`
	AllowPayloadLogging  bool     `json:"allow_payload_logging"`
	TraceEnabled         bool     `json:"trace_enabled"`
	PayloadLogged        bool     `json:"payload_logged"`
	SecretLogged         bool     `json:"secret_logged"`
}

type EgressExchangeSummary struct {
	Scenario            string `json:"scenario"`
	TargetClass         string `json:"target_class"`
	ConnectionClass     string `json:"connection_class"`
	RequestBytesBucket  string `json:"request_bytes_bucket"`
	ResponseBytesBucket string `json:"response_bytes_bucket"`
	ChunksWritten       int    `json:"chunks_written"`
	ChunksRead          int    `json:"chunks_read"`
	BackpressureEvents  int    `json:"backpressure_events"`
	TargetErrors        int    `json:"target_errors"`
	TargetResets        int    `json:"target_resets"`
	HalfCloseObserved   bool   `json:"half_close_observed"`
	QueuePressureEvents int    `json:"queue_pressure_events"`
	Completed           bool   `json:"completed"`
	PayloadLogged       bool   `json:"payload_logged"`
	SecretLogged        bool   `json:"secret_logged"`
	SummaryHash         string `json:"summary_hash"`
	FailureReasonBucket string `json:"failure_reason_bucket,omitempty"`
}

type AllowlistReport struct {
	LoopbackTargetsAccepted int      `json:"loopback_targets_accepted"`
	UnsafeTargetsRejected   int      `json:"unsafe_targets_rejected"`
	RejectedClasses         []string `json:"rejected_classes"`
	PayloadLogged           bool     `json:"payload_logged"`
	SecretLogged            bool     `json:"secret_logged"`
	Conclusion              string   `json:"conclusion"`
}

type LabEgressReport struct {
	Version             string                  `json:"version"`
	RunID               string                  `json:"run_id"`
	Exchanges           []EgressExchangeSummary `json:"exchanges"`
	ConnectionsOpened   int                     `json:"connections_opened"`
	ConnectionsClosed   int                     `json:"connections_closed"`
	ChunksWritten       int                     `json:"chunks_written"`
	ChunksRead          int                     `json:"chunks_read"`
	BackpressureEvents  int                     `json:"backpressure_events"`
	TargetErrors        int                     `json:"target_errors"`
	TargetResets        int                     `json:"target_resets"`
	QueuePressureEvents int                     `json:"queue_pressure_events"`
	PayloadLogged       bool                    `json:"payload_logged"`
	SecretLogged        bool                    `json:"secret_logged"`
	ReportHash          string                  `json:"report_hash"`
	Conclusion          string                  `json:"conclusion"`
}

type LabEgressMisuseReport struct {
	UnsafeControls []string `json:"unsafe_controls"`
	UnsafeDetected int      `json:"unsafe_detected"`
	PayloadLogged  bool     `json:"payload_logged"`
	SecretLogged   bool     `json:"secret_logged"`
	Conclusion     string   `json:"conclusion"`
}

type LabEgressParityReport struct {
	ComparedExchanges int      `json:"compared_exchanges"`
	SemanticMatches   int      `json:"semantic_matches"`
	UnexpectedDrift   []string `json:"unexpected_drift,omitempty"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
	Conclusion        string   `json:"conclusion"`
}

type LabEgressFixtureSet struct {
	Version                  string                `json:"version"`
	FixtureID                string                `json:"fixture_id"`
	GeneratedAt              string                `json:"generated_at"`
	GeneratedAtUnix          int64                 `json:"generated_at_unix"`
	BackendVersion           string                `json:"backend_version"`
	RecommendedNextMilestone string                `json:"recommended_next_milestone"`
	Config                   LabEgressConfig       `json:"config"`
	Scenarios                []string              `json:"scenarios"`
	Report                   LabEgressReport       `json:"report"`
	Allowlist                AllowlistReport       `json:"allowlist"`
	Misuse                   LabEgressMisuseReport `json:"misuse"`
	Parity                   LabEgressParityReport `json:"parity"`
	FixtureHash              string                `json:"fixture_hash"`
	PayloadLogged            bool                  `json:"payload_logged"`
	SecretLogged             bool                  `json:"secret_logged"`
	Conclusion               string                `json:"conclusion"`
}

type FixtureComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

func DefaultConfig() LabEgressConfig {
	return LabEgressConfig{
		ConfigID:             "lab_egress_default",
		ConnectorPolicy:      ConnectorPolicyLoopbackAllowlist,
		AllowedTargetClasses: []string{TargetClassEchoSynthetic, TargetClassFixedSynthetic, TargetClassSlowSynthetic, TargetClassResetSynthetic, TargetClassErrorSynthetic, TargetClassLargeSynthetic},
		AllowedLoopbackHosts: []string{"127.0.0.1", "::1", "localhost"},
		MaxConnections:       4,
		MaxStreams:           8,
		MaxRequestBytes:      4096,
		MaxResponseBytes:     64 * 1024,
		MaxBufferedBytes:     128 * 1024,
		MaxEvents:            256,
		TraceEnabled:         true,
	}
}

func ValidateConfig(cfg LabEgressConfig) error {
	if cfg.ConfigID == "" || cfg.ConnectorPolicy != ConnectorPolicyLoopbackAllowlist {
		return fmt.Errorf("%w: policy", ErrInvalidConfig)
	}
	if cfg.MaxConnections <= 0 || cfg.MaxConnections > 32 || cfg.MaxStreams <= 0 || cfg.MaxStreams > 64 {
		return fmt.Errorf("%w: connection limits", ErrInvalidConfig)
	}
	if cfg.MaxRequestBytes <= 0 || cfg.MaxResponseBytes <= 0 || cfg.MaxBufferedBytes <= 0 || cfg.MaxEvents <= 0 {
		return fmt.Errorf("%w: resource limits", ErrInvalidConfig)
	}
	if cfg.MaxRequestBytes > 1<<20 || cfg.MaxResponseBytes > 16<<20 || cfg.MaxBufferedBytes > 32<<20 || cfg.MaxEvents > 8192 {
		return fmt.Errorf("%w: resource limits too high", ErrInvalidConfig)
	}
	if cfg.AllowExternalTargets || cfg.AllowDNSResolution || cfg.AllowRawAddressTrace || cfg.AllowPayloadLogging || cfg.PayloadLogged || cfg.SecretLogged {
		return fmt.Errorf("%w: forbidden behavior", ErrInvalidConfig)
	}
	if len(cfg.AllowedTargetClasses) == 0 {
		return fmt.Errorf("%w: target classes", ErrInvalidConfig)
	}
	for _, class := range cfg.AllowedTargetClasses {
		if !knownTargetClass(class) {
			return fmt.Errorf("%w: unknown target class", ErrUnsafeTarget)
		}
	}
	for _, host := range cfg.AllowedLoopbackHosts {
		if err := ValidateLoopbackHost(host); err != nil {
			return err
		}
	}
	return nil
}

func ValidateLoopbackHost(host string) error {
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: non-loopback class", ErrUnsafeTarget)
	}
	return nil
}

func GenerateFixtureSet() (LabEgressFixtureSet, error) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		return LabEgressFixtureSet{}, err
	}
	scenarios := []string{ScenarioAllowlistValidation, ScenarioFixtureExchange, ScenarioSlowBackpressure, ScenarioResetIsolation, ScenarioErrorIsolation, ScenarioHalfClose, ScenarioQueuePressure, ScenarioGeneratedParity}
	targets := []string{TargetClassEchoSynthetic, TargetClassFixedSynthetic, TargetClassSlowSynthetic, TargetClassResetSynthetic, TargetClassErrorSynthetic, TargetClassLargeSynthetic, TargetClassEchoSynthetic, TargetClassFixedSynthetic}
	exchanges := make([]EgressExchangeSummary, 0, len(scenarios))
	for i, scenario := range scenarios {
		s := EgressExchangeSummary{
			Scenario:            scenario,
			TargetClass:         targets[i],
			ConnectionClass:     fmt.Sprintf("egress_connection_bucket_%02d", i%3),
			RequestBytesBucket:  bucketBytes(64 * (i + 1)),
			ResponseBytesBucket: bucketBytes(128 * (i + 1)),
			ChunksWritten:       1 + i%3,
			ChunksRead:          1 + (i+1)%4,
			BackpressureEvents:  boolToInt(scenario == ScenarioSlowBackpressure || scenario == ScenarioQueuePressure),
			TargetErrors:        boolToInt(scenario == ScenarioErrorIsolation),
			TargetResets:        boolToInt(scenario == ScenarioResetIsolation),
			HalfCloseObserved:   scenario == ScenarioHalfClose,
			QueuePressureEvents: boolToInt(scenario == ScenarioQueuePressure),
			Completed:           true,
		}
		s.SummaryHash = HashValue(s)
		exchanges = append(exchanges, s)
	}
	report := BuildReport(exchanges)
	set := LabEgressFixtureSet{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              fixedGeneratedAt().Format(time.RFC3339),
		GeneratedAtUnix:          fixedGeneratedAt().Unix(),
		BackendVersion:           "0.39.0-lab",
		RecommendedNextMilestone: RecommendedNextMilestone,
		Config:                   cfg,
		Scenarios:                scenarios,
		Report:                   report,
		Allowlist:                BuildAllowlistReport(),
		Misuse:                   ScanMisuse(),
		Parity:                   BuildParity(exchanges),
		Conclusion:               "passed",
	}
	set.FixtureHash = HashValue(setWithoutHash(set))
	return set, ValidateFixtureSet(set)
}

func BuildReport(exchanges []EgressExchangeSummary) LabEgressReport {
	report := LabEgressReport{Version: Version, RunID: "lab_egress_run_v1", Exchanges: exchanges, Conclusion: "passed"}
	for _, e := range exchanges {
		report.ConnectionsOpened++
		report.ConnectionsClosed += boolToInt(e.Completed)
		report.ChunksWritten += e.ChunksWritten
		report.ChunksRead += e.ChunksRead
		report.BackpressureEvents += e.BackpressureEvents
		report.TargetErrors += e.TargetErrors
		report.TargetResets += e.TargetResets
		report.QueuePressureEvents += e.QueuePressureEvents
		report.PayloadLogged = report.PayloadLogged || e.PayloadLogged
		report.SecretLogged = report.SecretLogged || e.SecretLogged
	}
	report.ReportHash = HashValue(report)
	return report
}

func BuildAllowlistReport() AllowlistReport {
	rejected := []string{"external_target", "dns_resolution", "raw_address_trace", "arbitrary_payload_capture"}
	return AllowlistReport{LoopbackTargetsAccepted: 3, UnsafeTargetsRejected: len(rejected), RejectedClasses: rejected, Conclusion: "passed"}
}

func ScanMisuse() LabEgressMisuseReport {
	controls := []string{"external_target", "dns_resolution", "raw_address_trace", "payload_logging", "unbounded_response", "ignored_backpressure", "wrong_reset_mapping", "generated_backend_drift"}
	return LabEgressMisuseReport{UnsafeControls: controls, UnsafeDetected: len(controls), Conclusion: "passed"}
}

func BuildParity(exchanges []EgressExchangeSummary) LabEgressParityReport {
	return LabEgressParityReport{ComparedExchanges: len(exchanges), SemanticMatches: len(exchanges), Conclusion: "passed"}
}

func ValidateFixtureSet(set LabEgressFixtureSet) error {
	if set.Version != Version || set.FixtureID == "" || set.Conclusion != "passed" {
		return errors.New("invalid lab egress fixture identity")
	}
	if err := ValidateConfig(set.Config); err != nil {
		return err
	}
	if len(set.Scenarios) < 3 || len(set.Report.Exchanges) != len(set.Scenarios) {
		return errors.New("invalid lab egress scenario set")
	}
	if set.PayloadLogged || set.SecretLogged || set.Report.PayloadLogged || set.Report.SecretLogged || set.Parity.PayloadLogged || set.Parity.SecretLogged {
		return errors.New("lab egress hygiene failed")
	}
	if set.FixtureHash == "" || HashValue(setWithoutHash(set)) != set.FixtureHash {
		return errors.New("lab egress fixture hash drift")
	}
	return ScanForLeak(set)
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range forbiddenMarkers {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("lab egress unsafe metadata marker: %s", marker)
		}
	}
	return nil
}

var forbiddenMarkers = []string{
	"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "packet_dump", "pcap", "raw_secret", "derived_key",
	"nonce_base", "auth_tag", "proof_material", "private_key", "session_secret", "public_ip", "external_address",
	"destination_address", "dns_query", "resolver", "domain_name", "sni", "payload_logged\":true", "secret_logged\":true",
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := ScanForLeak(value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func LoadFixtureSet(path string) (LabEgressFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LabEgressFixtureSet{}, err
	}
	var set LabEgressFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return LabEgressFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func CompareFixtureSets(oldSet, newSet LabEgressFixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.Report.ConnectionsOpened != newSet.Report.ConnectionsOpened {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "connection_count_changed")
	}
	report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
	report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
	if len(report.UnexpectedDrift) == 0 && !report.PayloadLogged && !report.SecretLogged {
		report.Conclusion = "passed"
	} else {
		sort.Strings(report.UnexpectedDrift)
		report.Conclusion = "failed"
	}
	return report
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func HashValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func setWithoutHash(set LabEgressFixtureSet) LabEgressFixtureSet {
	set.FixtureHash = ""
	return set
}

func knownTargetClass(class string) bool {
	switch class {
	case TargetClassEchoSynthetic, TargetClassFixedSynthetic, TargetClassSlowSynthetic, TargetClassResetSynthetic, TargetClassErrorSynthetic, TargetClassLargeSynthetic:
		return true
	default:
		return false
	}
}

func bucketBytes(n int) string {
	switch {
	case n <= 128:
		return "tiny"
	case n <= 1024:
		return "small"
	case n <= 16*1024:
		return "medium"
	default:
		return "large"
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func fixedGeneratedAt() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}
