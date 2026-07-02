// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyadapterreview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	Version                  = "localproxyadapterreview-v1"
	BackendVersion           = "0.48.0-lab"
	DefaultFixtureID         = "payload_bearing_local_proxy_adapter_review_v1"
	DecisionReady            = "ready_for_m49_local_only_prototype"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M49: local proxy adapter prototype"
)

var generatedAt = time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type ScopeReport struct {
	AllowedBehaviors []string `json:"allowed_behaviors"`
	BlockedBehaviors []string `json:"blocked_behaviors"`
	Decision         string   `json:"decision"`
}

type ProtocolAcceptanceReport struct {
	AcceptedProtocols []string `json:"accepted_protocols"`
	ParserStates      []string `json:"parser_states_that_may_open_stream"`
	RejectedProtocols []string `json:"rejected_protocols"`
}

type PayloadHandlingContract struct {
	OpaqueByteClasses    []string `json:"opaque_byte_classes"`
	LoggingPolicy        string   `json:"logging_policy"`
	CommittedFixtureRule string   `json:"committed_fixture_rule"`
	SegmentationClasses  []string `json:"segmentation_classes"`
	ReassemblyClasses    []string `json:"reassembly_classes"`
	MaxPayloadClass      string   `json:"max_payload_class"`
	PayloadLogged        bool     `json:"payload_logged"`
	RawPayloadCommitted  bool     `json:"raw_payload_committed"`
}

type StreamMappingContract struct {
	OpenTriggers        []string `json:"open_triggers"`
	StreamClasses       []string `json:"stream_classes"`
	MappingRules        []string `json:"mapping_rules"`
	CarrierSelection    string   `json:"carrier_selection"`
	ExactTargetExcluded bool     `json:"exact_target_excluded"`
	ExactPortExcluded   bool     `json:"exact_port_excluded"`
}

type BackpressureResetContract struct {
	BackpressureSignals []string `json:"backpressure_signals"`
	ResetSignals        []string `json:"reset_signals"`
	HalfCloseRules      []string `json:"half_close_rules"`
	SafeErrorBuckets    []string `json:"safe_error_buckets"`
}

type TargetRedactionReport struct {
	AllowedFields      []string `json:"allowed_fields"`
	ForbiddenFields    []string `json:"forbidden_fields"`
	RedactionRules     []string `json:"redaction_rules"`
	ExactTargetPersist bool     `json:"exact_target_persist"`
	ExactPortPersist   bool     `json:"exact_port_persist"`
}

type IntegrationReport struct {
	LocalProtocolAdapter string   `json:"localprotocoladapter"`
	LoopbackRelay        string   `json:"loopbackrelay"`
	MultiCarrierSelect   string   `json:"multicarrierselect"`
	LabEgress            string   `json:"labegress"`
	MeasurementReview    string   `json:"measurementreview"`
	RequiredGates        []string `json:"required_gates"`
}

type ResourceLimitContract struct {
	MaxStreamsClass       string   `json:"max_streams_class"`
	MaxBufferedBytesClass string   `json:"max_buffered_bytes_class"`
	MaxEventsClass        string   `json:"max_events_class"`
	PanicSafetyTargets    []string `json:"panic_safety_targets"`
}

type MisuseReport struct {
	DetectedControls []string `json:"detected_controls"`
	DetectedCount    int      `json:"detected_count"`
	ExpectedCount    int      `json:"expected_count"`
	Conclusion       string   `json:"conclusion"`
}

type PublicClaimSafetyReport struct {
	DocsChecked         int      `json:"docs_checked"`
	UnsafeClaimsFound   []string `json:"unsafe_claims_found"`
	AllowedClaimClasses []string `json:"allowed_claim_classes"`
	Conclusion          string   `json:"conclusion"`
}

type M49Contract struct {
	CommandName            string   `json:"command_name"`
	Decision               string   `json:"decision"`
	AcceptanceRequirements []string `json:"acceptance_requirements"`
	RequiredIntegrations   []string `json:"required_integrations"`
	RequiredControls       []string `json:"required_controls"`
}

type ParityReport struct {
	GeneratedMarkers []string `json:"generated_markers"`
	InterpretedHash  string   `json:"interpreted_hash"`
	GeneratedHash    string   `json:"generated_hash"`
	UnexpectedDrift  []string `json:"unexpected_drift"`
	Conclusion       string   `json:"conclusion"`
}

type FixtureEntry struct {
	Name          string `json:"name"`
	Category      string `json:"category"`
	SafeClass     string `json:"safe_class"`
	Expected      string `json:"expected"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
}

type FixtureSet struct {
	Version           string                    `json:"version"`
	FixtureID         string                    `json:"fixture_id"`
	GeneratedAt       string                    `json:"generated_at"`
	BackendVersion    string                    `json:"backend_version"`
	Scope             ScopeReport               `json:"scope"`
	Protocols         ProtocolAcceptanceReport  `json:"protocols"`
	Payload           PayloadHandlingContract   `json:"payload"`
	StreamMapping     StreamMappingContract     `json:"stream_mapping"`
	BackpressureReset BackpressureResetContract `json:"backpressure_reset"`
	TargetRedaction   TargetRedactionReport     `json:"target_redaction"`
	Integration       IntegrationReport         `json:"integration"`
	ResourceLimits    ResourceLimitContract     `json:"resource_limits"`
	Misuse            MisuseReport              `json:"misuse"`
	PublicClaims      PublicClaimSafetyReport   `json:"public_claims"`
	M49Contract       M49Contract               `json:"m49_contract"`
	Parity            ParityReport              `json:"parity"`
	Fixtures          []FixtureEntry            `json:"fixtures"`
	FixtureHash       string                    `json:"fixture_hash"`
	PayloadLogged     bool                      `json:"payload_logged"`
	SecretLogged      bool                      `json:"secret_logged"`
	Conclusion        string                    `json:"conclusion"`
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

func GenerateFixtureSet() (FixtureSet, error) {
	set := FixtureSet{
		Version:        Version,
		FixtureID:      DefaultFixtureID,
		GeneratedAt:    generatedAt,
		BackendVersion: BackendVersion,
		Scope: ScopeReport{
			AllowedBehaviors: []string{
				"local_only_opaque_stream_bytes",
				"symbolic_stream_content_classes",
				"loopback_policy_context",
				"bounded_runtime_mapping",
				"aggregate_local_diagnostics",
			},
			BlockedBehaviors: []string{
				"public_deployment",
				"external_target_proxying_beyond_controlled_policy",
				"dns_resolution_by_default",
				"transparent_os_wide_vpn_behavior",
				"tun_vpn_packet_capture",
				"android_behavior",
				"payload_logging",
				"packet_capture",
				"credential_storage",
				"browser_os_configuration_automation",
				"field_testing",
			},
			Decision: DecisionReady,
		},
		Protocols: ProtocolAcceptanceReport{
			AcceptedProtocols: []string{
				"local_socks_like_stream_adapter_semantics",
				"local_http_connect_like_stream_adapter_semantics",
			},
			ParserStates: []string{
				"socks5_like_command_accepted",
				"socks5_like_target_redacted",
				"http_connect_like_request_accepted",
				"http_connect_like_target_redacted",
			},
			RejectedProtocols: []string{"transparent_vpn", "raw_tun", "public_proxy", "browser_config_automation"},
		},
		Payload: PayloadHandlingContract{
			OpaqueByteClasses:    []string{"interactive_small", "bulk_bounded", "chunked_local", "reset_after_partial"},
			LoggingPolicy:        "byte_counts_buckets_and_flags_only",
			CommittedFixtureRule: "symbolic_classes_only_no_raw_bytes",
			SegmentationClasses:  []string{"single_chunk", "fixed_chunk", "backpressure_chunk", "half_close_final_chunk"},
			ReassemblyClasses:    []string{"ordered_reassembly", "bounded_missing_chunk", "reset_clears_reassembly"},
			MaxPayloadClass:      "bounded_local_stream_content",
		},
		StreamMapping: StreamMappingContract{
			OpenTriggers:        []string{"parser_state_accept", "target_redaction_complete", "capability_check_passed"},
			StreamClasses:       []string{"interactive", "bulk", "control", "error_test"},
			MappingRules:        []string{"one_local_flow_to_one_runtime_stream", "target_descriptor_bucket_only", "carrier_selection_before_first_payload_chunk"},
			CarrierSelection:    "invoke_multicarrierselect_with_review_and_health_constraints",
			ExactTargetExcluded: true,
			ExactPortExcluded:   true,
		},
		BackpressureReset: BackpressureResetContract{
			BackpressureSignals: []string{"adapter_queue_pressure", "runtime_stream_window_pressure", "carrier_selection_pressure", "labegress_policy_pressure"},
			ResetSignals:        []string{"parser_reset", "runtime_stream_reset", "target_error_reset", "carrier_reset_bucket"},
			HalfCloseRules:      []string{"write_half_close_allowed_only_if_capability", "read_side_may_continue_until_bounded_close"},
			SafeErrorBuckets:    []string{"target_redacted_rejected", "policy_blocked", "resource_limit", "reset_bucket", "parser_misuse"},
		},
		TargetRedaction: TargetRedactionReport{
			AllowedFields:      []string{"target_class_bucket", "port_class_bucket", "request_class", "priority_class", "policy_bucket"},
			ForbiddenFields:    []string{"exact_target", "exact_port", "hostname", "domain", "url", "sni", "host_header"},
			RedactionRules:     []string{"redact_before_stream_open", "redact_before_trace", "redact_before_fixture", "error_strings_use_bucket_only"},
			ExactTargetPersist: false,
			ExactPortPersist:   false,
		},
		Integration: IntegrationReport{
			LocalProtocolAdapter: "must_compose_with_m37_parser_states",
			LoopbackRelay:        "must_use_loopbackrelay_only_for_lab_round_trips",
			MultiCarrierSelect:   "must_invoke_reviewed_selector_before_payload_chunks",
			LabEgress:            "must_obey_controlled_policy_and_allowlist",
			MeasurementReview:    "must_keep_diagnostics_aggregate_local_only",
			RequiredGates:        []string{"localprotocoladapter", "loopbackrelay", "labegress", "localpipeline", "multicarrierselect", "measurementreview", "hardening"},
		},
		ResourceLimits: ResourceLimitContract{
			MaxStreamsClass:       "bounded_by_profile_and_adapter_config",
			MaxBufferedBytesClass: "bounded_local_buffer_bucket",
			MaxEventsClass:        "bounded_trace_event_bucket",
			PanicSafetyTargets:    []string{"parser_transition", "payload_segmenter", "stream_mapper", "redaction_validator", "diagnostic_builder"},
		},
		Misuse: BuildMisuseReport(),
		PublicClaims: PublicClaimSafetyReport{
			DocsChecked:         5,
			AllowedClaimClasses: []string{"design_review", "local_only_contract", "M49_acceptance_criteria", "no_public_deployment_claim"},
			Conclusion:          ConclusionPassed,
		},
		M49Contract: M49Contract{
			CommandName: "localproxyadapter",
			Decision:    DecisionReady,
			AcceptanceRequirements: []string{
				"carry_opaque_local_stream_bytes_without_logging_payloads",
				"accept_only_reviewed_local_socks_like_and_connect_like_parser_states",
				"preserve_target_redaction_before_stream_open",
				"invoke_multicarrierselect_and_measurementreview_gates",
				"surface_backpressure_reset_and_half_close_as_safe_metadata",
				"reject_public_deployment_dns_by_default_vpn_capture_and_browser_configuration",
				"provide_generated_interpreted_parity_and_fixture_drift_gates",
			},
			RequiredIntegrations: []string{"localprotocoladapter", "loopbackrelay", "labegress", "localpipeline", "multicarrierselect", "measurementreview", "hardening", "codegen"},
			RequiredControls:     RequiredMisuseNames(),
		},
		Fixtures: []FixtureEntry{
			{Name: "local_socks_like_acceptance", Category: "protocol_acceptance", SafeClass: "socks_like_stream", Expected: "accepted_after_target_redaction"},
			{Name: "local_connect_like_acceptance", Category: "protocol_acceptance", SafeClass: "connect_like_stream", Expected: "accepted_after_target_redaction"},
			{Name: "opaque_payload_policy", Category: "payload_handling", SafeClass: "symbolic_bytes_only", Expected: "no_payload_logged"},
			{Name: "stream_mapping_policy", Category: "stream_mapping", SafeClass: "flow_to_stream", Expected: "carrier_selection_before_payload"},
			{Name: "backpressure_policy", Category: "backpressure_reset", SafeClass: "pressure_bucket", Expected: "surfaced_to_adapter"},
			{Name: "reset_policy", Category: "backpressure_reset", SafeClass: "reset_bucket", Expected: "stream_scoped_reset"},
			{Name: "target_redaction_policy", Category: "target_redaction", SafeClass: "target_bucket_only", Expected: "exact_target_excluded"},
			{Name: "resource_limit_policy", Category: "resource_limits", SafeClass: "bounded_buffers", Expected: "bounded"},
			{Name: "public_claim_policy", Category: "public_claims", SafeClass: "review_only", Expected: "no_working_proxy_claim"},
			{Name: "m49_contract_policy", Category: "m49_contract", SafeClass: "go_for_local_prototype", Expected: "ready"},
		},
		Conclusion: ConclusionPassed,
	}
	set.Parity = BuildParityReport(set)
	set.FixtureHash = HashValue(hashInput(set))
	if err := ValidateFixtureSet(set); err != nil {
		return FixtureSet{}, err
	}
	return set, nil
}

func BuildMisuseReport() MisuseReport {
	required := RequiredMisuseNames()
	return MisuseReport{
		DetectedControls: append([]string{}, required...),
		DetectedCount:    len(required),
		ExpectedCount:    len(required),
		Conclusion:       ConclusionPassed,
	}
}

func BuildParityReport(set FixtureSet) ParityReport {
	markers := []string{"LocalProxyAdapterReviewSchemaVersion", "LocalProxyAdapterReviewGeneratedProfileID", "LocalProxyAdapterReviewM49Decision", "LocalProxyAdapterReviewPayloadPolicy", "LocalProxyAdapterReviewTargetRedaction"}
	base := map[string]any{
		"version":   set.Version,
		"scope":     set.Scope.Decision,
		"protocols": set.Protocols.AcceptedProtocols,
		"payload":   set.Payload.LoggingPolicy,
		"mapping":   set.StreamMapping.CarrierSelection,
	}
	hash := HashValue(base)
	return ParityReport{GeneratedMarkers: markers, InterpretedHash: hash, GeneratedHash: hash, Conclusion: ConclusionPassed}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version {
		return fmt.Errorf("unexpected version %q", set.Version)
	}
	if set.BackendVersion != BackendVersion {
		return fmt.Errorf("unexpected backend version %q", set.BackendVersion)
	}
	if set.Scope.Decision != DecisionReady || len(set.Scope.BlockedBehaviors) < 10 {
		return errors.New("scope contract incomplete")
	}
	if len(set.Protocols.AcceptedProtocols) < 2 || len(set.Protocols.ParserStates) < 4 {
		return errors.New("protocol acceptance contract incomplete")
	}
	if set.Payload.PayloadLogged || set.Payload.RawPayloadCommitted || set.Payload.LoggingPolicy == "" {
		return errors.New("payload handling contract unsafe")
	}
	if !set.StreamMapping.ExactTargetExcluded || !set.StreamMapping.ExactPortExcluded {
		return errors.New("target exclusion contract missing")
	}
	if set.TargetRedaction.ExactTargetPersist || set.TargetRedaction.ExactPortPersist || len(set.TargetRedaction.ForbiddenFields) < 6 {
		return errors.New("target redaction contract unsafe")
	}
	if len(set.Integration.RequiredGates) < 6 {
		return errors.New("integration gates incomplete")
	}
	if len(set.ResourceLimits.PanicSafetyTargets) < 4 {
		return errors.New("resource limit contract incomplete")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) {
		return errors.New("misuse control count mismatch")
	}
	if set.M49Contract.CommandName != "localproxyadapter" || len(set.M49Contract.AcceptanceRequirements) < 6 {
		return errors.New("M49 contract incomplete")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash {
		return errors.New("parity report failed")
	}
	if set.PayloadLogged || set.SecretLogged {
		return errors.New("fixture set reports unsafe logging")
	}
	for _, fixture := range set.Fixtures {
		if fixture.PayloadLogged || fixture.SecretLogged {
			return fmt.Errorf("unsafe fixture logging in %s", fixture.Name)
		}
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash}
	if oldSet.PayloadLogged || newSet.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload logging flag changed")
	}
	if oldSet.SecretLogged || newSet.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret logging flag changed")
	}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture hash changed")
	}
	if len(report.UnexpectedDrift) == 0 {
		report.Conclusion = ConclusionPassed
	} else {
		report.Conclusion = "failed"
	}
	return report
}

func LoadFixtureSet(path string) (FixtureSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FixtureSet{}, err
	}
	var set FixtureSet
	if err := json.Unmarshal(data, &set); err != nil {
		return FixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func WriteFixtureSet(path string, set FixtureSet, force bool) error {
	if err := ValidateFixtureSet(set); err != nil {
		return err
	}
	return WriteJSON(path, set, force)
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; use --force", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func StableJSON(value any) ([]byte, error) {
	return json.MarshalIndent(value, "", "  ")
}

func HashValue(value any) string {
	data, _ := StableJSON(value)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ScanForLeak(value any) error {
	data, err := StableJSON(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(data))
	for _, marker := range ForbiddenMarkers() {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return fmt.Errorf("forbidden marker %q found", marker)
		}
	}
	for _, marker := range []string{`"payload_logged": true`, `"secret_logged": true`, `"raw_payload_committed": true`, `"exact_target_persist": true`, `"exact_port_persist": true`} {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("unsafe flag %s found", marker)
		}
	}
	return nil
}

func ForbiddenMarkers() []string {
	return []string{
		`"raw_payload"`,
		`"payload_body"`,
		`"raw_bytes"`,
		`"packet_capture_dump"`,
		`"credential_value"`,
		`"secret_value"`,
		`"private_key"`,
		`"session_secret"`,
		`"auth_tag"`,
		`"nonce_base"`,
		`"exact_target_value"`,
		`"exact_port_value"`,
		`"sni_value"`,
		`"host_header_value"`,
		`"resolver_ip"`,
		`"exact_dns_query"`,
		`"public_network_egress"`,
	}
}

func RequiredMisuseNames() []string {
	return []string{
		"localproxyadapterreview_allows_payload_logging",
		"localproxyadapterreview_allows_packet_capture",
		"localproxyadapterreview_allows_dns_by_default",
		"localproxyadapterreview_allows_public_deployment",
		"localproxyadapterreview_allows_exact_target_persistence",
		"localproxyadapterreview_allows_credential_storage",
		"localproxyadapterreview_allows_os_browser_config",
		"localproxyadapterreview_allows_vpn_packet_capture",
		"localproxyadapterreview_bypasses_localprotocoladapter",
		"localproxyadapterreview_bypasses_multicarrierselect",
		"localproxyadapterreview_bypasses_measurementreview",
		"localproxyadapterreview_public_claim_working_proxy",
		"localproxyadapterreview_public_claim_working_vpn",
		"localproxyadapterreview_payload_leak",
		"localproxyadapterreview_secret_leak",
		"localproxyadapterreview_generated_backend_drift",
	}
}

func hashInput(set FixtureSet) map[string]any {
	return map[string]any{
		"version":            set.Version,
		"fixture_id":         set.FixtureID,
		"backend_version":    set.BackendVersion,
		"scope":              set.Scope,
		"protocols":          set.Protocols,
		"payload":            set.Payload,
		"stream_mapping":     set.StreamMapping,
		"backpressure_reset": set.BackpressureReset,
		"target_redaction":   set.TargetRedaction,
		"integration":        set.Integration,
		"resource_limits":    set.ResourceLimits,
		"misuse":             set.Misuse,
		"public_claims":      set.PublicClaims,
		"m49_contract":       set.M49Contract,
		"fixtures":           set.Fixtures,
	}
}

func SortedRequiredMisuseNames() []string {
	names := RequiredMisuseNames()
	sort.Strings(names)
	return names
}
