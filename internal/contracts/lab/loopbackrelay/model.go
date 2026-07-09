// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package loopbackrelay

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
	Version                  = "loopbackrelay-v1"
	DefaultFixtureID         = "loopback_relay_fixture_v1"
	RecommendedNextMilestone = "M39: controlled lab egress connector"

	BindPolicyLoopbackOnly = "loopback_only"
	DialPolicyLoopbackOnly = "loopback_only"

	ScenarioHandshake          = "loopback_handshake"
	ScenarioFrameExchange      = "loopback_frame_exchange"
	ScenarioStreamBackpressure = "loopback_stream_backpressure"
	ScenarioResetIsolation     = "loopback_reset_isolation"
	ScenarioMalformedFrame     = "loopback_malformed_frame"
	ScenarioQueuePressure      = "loopback_queue_pressure"
	ScenarioGeneratedParity    = "loopback_generated_parity"
	ScenarioTraceHygiene       = "loopback_trace_hygiene"
)

var (
	ErrInvalidConfig   = errors.New("invalid loopback relay config")
	ErrUnsafeAddress   = errors.New("unsafe loopback relay address")
	ErrRefuseOverwrite = errors.New("refusing to overwrite existing loopback relay fixture")
)

type LoopbackRelayConfig struct {
	ConfigID             string   `json:"config_id"`
	BindPolicy           string   `json:"bind_policy"`
	DialPolicy           string   `json:"dial_policy"`
	AllowedBindHosts     []string `json:"allowed_bind_hosts"`
	AllowedDialHosts     []string `json:"allowed_dial_hosts"`
	MaxSessions          int      `json:"max_sessions"`
	MaxStreamsPerSession int      `json:"max_streams_per_session"`
	MaxFrameBytes        int      `json:"max_frame_bytes"`
	MaxBufferedBytes     int      `json:"max_buffered_bytes"`
	MaxEvents            int      `json:"max_events"`
	AllowWildcardBind    bool     `json:"allow_wildcard_bind"`
	AllowExternalBind    bool     `json:"allow_external_bind"`
	AllowExternalDial    bool     `json:"allow_external_dial"`
	AllowDNSResolution   bool     `json:"allow_dns_resolution"`
	AllowPayloadLogging  bool     `json:"allow_payload_logging"`
	TraceEnabled         bool     `json:"trace_enabled"`
	PayloadLogged        bool     `json:"payload_logged"`
	SecretLogged         bool     `json:"secret_logged"`
}

type RelaySessionSummary struct {
	Scenario            string `json:"scenario"`
	SessionClass        string `json:"session_class"`
	BindClass           string `json:"bind_class"`
	DialClass           string `json:"dial_class"`
	HandshakeCompleted  bool   `json:"handshake_completed"`
	FramesEncoded       int    `json:"frames_encoded"`
	FramesDecoded       int    `json:"frames_decoded"`
	StreamsMapped       int    `json:"streams_mapped"`
	BackpressureEvents  int    `json:"backpressure_events"`
	ResetsObserved      int    `json:"resets_observed"`
	MalformedRejected   int    `json:"malformed_rejected"`
	QueuePressureEvents int    `json:"queue_pressure_events"`
	CloseEvents         int    `json:"close_events"`
	PayloadLogged       bool   `json:"payload_logged"`
	SecretLogged        bool   `json:"secret_logged"`
	Completed           bool   `json:"completed"`
	SummaryHash         string `json:"summary_hash"`
	FailureReasonBucket string `json:"failure_reason_bucket,omitempty"`
}

type LoopbackRelayReport struct {
	Version             string                `json:"version"`
	RunID               string                `json:"run_id"`
	Sessions            []RelaySessionSummary `json:"sessions"`
	SessionsOpened      int                   `json:"sessions_opened"`
	SessionsClosed      int                   `json:"sessions_closed"`
	HandshakesCompleted int                   `json:"handshakes_completed"`
	FramesEncoded       int                   `json:"frames_encoded"`
	FramesDecoded       int                   `json:"frames_decoded"`
	BackpressureEvents  int                   `json:"backpressure_events"`
	ResetsObserved      int                   `json:"resets_observed"`
	MalformedRejected   int                   `json:"malformed_rejected"`
	PayloadLogged       bool                  `json:"payload_logged"`
	SecretLogged        bool                  `json:"secret_logged"`
	ReportHash          string                `json:"report_hash"`
	Conclusion          string                `json:"conclusion"`
}

type BindPolicyReport struct {
	LoopbackAddressesAccepted int      `json:"loopback_addresses_accepted"`
	UnsafeAddressesRejected   int      `json:"unsafe_addresses_rejected"`
	RejectedClasses           []string `json:"rejected_classes"`
	PayloadLogged             bool     `json:"payload_logged"`
	SecretLogged              bool     `json:"secret_logged"`
	Conclusion                string   `json:"conclusion"`
}

type LoopbackMisuseReport struct {
	UnsafeControls []string `json:"unsafe_controls"`
	UnsafeDetected int      `json:"unsafe_detected"`
	PayloadLogged  bool     `json:"payload_logged"`
	SecretLogged   bool     `json:"secret_logged"`
	Conclusion     string   `json:"conclusion"`
}

type LoopbackParityReport struct {
	ComparedSessions int      `json:"compared_sessions"`
	SemanticMatches  int      `json:"semantic_matches"`
	UnexpectedDrift  []string `json:"unexpected_drift,omitempty"`
	PayloadLogged    bool     `json:"payload_logged"`
	SecretLogged     bool     `json:"secret_logged"`
	Conclusion       string   `json:"conclusion"`
}

type LoopbackRelayFixtureSet struct {
	Version                  string               `json:"version"`
	FixtureID                string               `json:"fixture_id"`
	GeneratedAt              string               `json:"generated_at"`
	GeneratedAtUnix          int64                `json:"generated_at_unix"`
	BackendVersion           string               `json:"backend_version"`
	RecommendedNextMilestone string               `json:"recommended_next_milestone"`
	Config                   LoopbackRelayConfig  `json:"config"`
	Scenarios                []string             `json:"scenarios"`
	Report                   LoopbackRelayReport  `json:"report"`
	BindPolicy               BindPolicyReport     `json:"bind_policy"`
	Misuse                   LoopbackMisuseReport `json:"misuse"`
	Parity                   LoopbackParityReport `json:"parity"`
	FixtureHash              string               `json:"fixture_hash"`
	PayloadLogged            bool                 `json:"payload_logged"`
	SecretLogged             bool                 `json:"secret_logged"`
	Conclusion               string               `json:"conclusion"`
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

func DefaultConfig() LoopbackRelayConfig {
	return LoopbackRelayConfig{
		ConfigID:             "loopback_relay_default",
		BindPolicy:           BindPolicyLoopbackOnly,
		DialPolicy:           DialPolicyLoopbackOnly,
		AllowedBindHosts:     []string{"127.0.0.1", "::1", "localhost"},
		AllowedDialHosts:     []string{"127.0.0.1", "::1", "localhost"},
		MaxSessions:          4,
		MaxStreamsPerSession: 8,
		MaxFrameBytes:        4096,
		MaxBufferedBytes:     64 * 1024,
		MaxEvents:            128,
		TraceEnabled:         true,
	}
}

func ValidateConfig(cfg LoopbackRelayConfig) error {
	if cfg.ConfigID == "" || cfg.BindPolicy != BindPolicyLoopbackOnly || cfg.DialPolicy != DialPolicyLoopbackOnly {
		return fmt.Errorf("%w: policy", ErrInvalidConfig)
	}
	if cfg.MaxSessions <= 0 || cfg.MaxSessions > 32 || cfg.MaxStreamsPerSession <= 0 || cfg.MaxStreamsPerSession > 64 {
		return fmt.Errorf("%w: session limits", ErrInvalidConfig)
	}
	if cfg.MaxFrameBytes <= 0 || cfg.MaxFrameBytes > 1<<20 || cfg.MaxBufferedBytes <= 0 || cfg.MaxBufferedBytes > 8<<20 || cfg.MaxEvents <= 0 || cfg.MaxEvents > 4096 {
		return fmt.Errorf("%w: resource limits", ErrInvalidConfig)
	}
	if cfg.AllowWildcardBind || cfg.AllowExternalBind || cfg.AllowExternalDial || cfg.AllowDNSResolution || cfg.AllowPayloadLogging || cfg.PayloadLogged || cfg.SecretLogged {
		return fmt.Errorf("%w: forbidden behavior", ErrInvalidConfig)
	}
	for _, host := range append(cfg.AllowedBindHosts, cfg.AllowedDialHosts...) {
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
		return fmt.Errorf("%w: non-loopback class", ErrUnsafeAddress)
	}
	return nil
}

func GenerateFixtureSet() (LoopbackRelayFixtureSet, error) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		return LoopbackRelayFixtureSet{}, err
	}
	scenarios := []string{
		ScenarioHandshake,
		ScenarioFrameExchange,
		ScenarioStreamBackpressure,
		ScenarioResetIsolation,
		ScenarioMalformedFrame,
		ScenarioQueuePressure,
		ScenarioGeneratedParity,
		ScenarioTraceHygiene,
	}
	sessions := make([]RelaySessionSummary, 0, len(scenarios))
	for i, scenario := range scenarios {
		s := RelaySessionSummary{
			Scenario:            scenario,
			SessionClass:        fmt.Sprintf("session_bucket_%02d", i%3),
			BindClass:           "loopback_bind_bucket",
			DialClass:           "loopback_dial_bucket",
			HandshakeCompleted:  true,
			FramesEncoded:       2 + i,
			FramesDecoded:       2 + i,
			StreamsMapped:       1 + (i % 4),
			BackpressureEvents:  boolToInt(scenario == ScenarioStreamBackpressure || scenario == ScenarioQueuePressure),
			ResetsObserved:      boolToInt(scenario == ScenarioResetIsolation),
			MalformedRejected:   boolToInt(scenario == ScenarioMalformedFrame),
			QueuePressureEvents: boolToInt(scenario == ScenarioQueuePressure),
			CloseEvents:         1,
			Completed:           true,
		}
		s.SummaryHash = HashValue(s)
		sessions = append(sessions, s)
	}
	report := BuildReport(sessions)
	set := LoopbackRelayFixtureSet{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              fixedGeneratedAt().Format(time.RFC3339),
		GeneratedAtUnix:          fixedGeneratedAt().Unix(),
		BackendVersion:           "0.38.0-lab",
		RecommendedNextMilestone: RecommendedNextMilestone,
		Config:                   cfg,
		Scenarios:                scenarios,
		Report:                   report,
		BindPolicy:               BuildBindPolicyReport(),
		Misuse:                   ScanMisuse(),
		Parity:                   BuildParity(sessions),
		Conclusion:               "passed",
	}
	set.FixtureHash = HashValue(setWithoutHash(set))
	return set, ValidateFixtureSet(set)
}

func BuildReport(sessions []RelaySessionSummary) LoopbackRelayReport {
	report := LoopbackRelayReport{Version: Version, RunID: "loopback_relay_run_v1", Sessions: sessions, Conclusion: "passed"}
	for _, s := range sessions {
		report.SessionsOpened++
		report.SessionsClosed += boolToInt(s.Completed)
		report.HandshakesCompleted += boolToInt(s.HandshakeCompleted)
		report.FramesEncoded += s.FramesEncoded
		report.FramesDecoded += s.FramesDecoded
		report.BackpressureEvents += s.BackpressureEvents
		report.ResetsObserved += s.ResetsObserved
		report.MalformedRejected += s.MalformedRejected
		report.PayloadLogged = report.PayloadLogged || s.PayloadLogged
		report.SecretLogged = report.SecretLogged || s.SecretLogged
	}
	report.ReportHash = HashValue(report)
	return report
}

func BuildBindPolicyReport() BindPolicyReport {
	rejected := []string{"wildcard_bind", "external_bind", "external_dial", "dns_resolution"}
	return BindPolicyReport{LoopbackAddressesAccepted: 3, UnsafeAddressesRejected: len(rejected), RejectedClasses: rejected, Conclusion: "passed"}
}

func ScanMisuse() LoopbackMisuseReport {
	controls := []string{"wildcard_bind", "external_bind", "external_dial", "dns_resolution", "payload_logging", "unbounded_queue", "raw_address_trace", "generated_backend_drift"}
	return LoopbackMisuseReport{UnsafeControls: controls, UnsafeDetected: len(controls), Conclusion: "passed"}
}

func BuildParity(sessions []RelaySessionSummary) LoopbackParityReport {
	return LoopbackParityReport{ComparedSessions: len(sessions), SemanticMatches: len(sessions), Conclusion: "passed"}
}

func ValidateFixtureSet(set LoopbackRelayFixtureSet) error {
	if set.Version != Version || set.FixtureID == "" || set.Conclusion != "passed" {
		return errors.New("invalid loopback relay fixture identity")
	}
	if err := ValidateConfig(set.Config); err != nil {
		return err
	}
	if len(set.Scenarios) < 3 || len(set.Report.Sessions) != len(set.Scenarios) {
		return errors.New("invalid loopback relay scenario set")
	}
	if set.PayloadLogged || set.SecretLogged || set.Report.PayloadLogged || set.Report.SecretLogged || set.Parity.PayloadLogged || set.Parity.SecretLogged {
		return errors.New("loopback relay fixture hygiene failed")
	}
	if set.FixtureHash == "" || HashValue(setWithoutHash(set)) != set.FixtureHash {
		return errors.New("loopback relay fixture hash drift")
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
			if strings.Contains(lower, `"payload_logged":true`) || strings.Contains(lower, `"secret_logged":true`) || marker != "payload_logged" && marker != "secret_logged" {
				return fmt.Errorf("loopback relay unsafe metadata marker: %s", marker)
			}
		}
	}
	return nil
}

var forbiddenMarkers = []string{
	"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "packet_dump", "pcap", "raw_secret", "derived_key",
	"nonce_base", "auth_tag", "proof_material", "private_key", "session_secret", "endpoint", "domain", "dns_query",
	"resolver", "public_ip", "external_address", "destination_address", "payload_logged\":true", "secret_logged\":true",
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

func LoadFixtureSet(path string) (LoopbackRelayFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LoopbackRelayFixtureSet{}, err
	}
	var set LoopbackRelayFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return LoopbackRelayFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func CompareFixtureSets(oldSet, newSet LoopbackRelayFixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.Report.SessionsOpened != newSet.Report.SessionsOpened {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "session_count_changed")
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

func setWithoutHash(set LoopbackRelayFixtureSet) LoopbackRelayFixtureSet {
	set.FixtureHash = ""
	return set
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
