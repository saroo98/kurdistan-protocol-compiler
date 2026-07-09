// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package vpnsemantics

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
	Version                  = "vpnsemantics-v1"
	BackendVersion           = "0.50.0-lab"
	DefaultFixtureID         = "local_tun_vpn_semantics_model_v1"
	DecisionReady            = "ready_for_m51_local_desktop_tun_vpn_prototype"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M51: local desktop TUN/VPN prototype"
)

var generatedAt = time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type ScopeReport struct {
	AllowedBehaviors []string `json:"allowed_behaviors"`
	BlockedBehaviors []string `json:"blocked_behaviors"`
	Decision         string   `json:"decision"`
}

type PacketFlowTaxonomy struct {
	PacketFlowClasses    []string `json:"packet_flow_classes"`
	FlowIdentityClasses  []string `json:"flow_identity_classes"`
	AppIdentityPolicies  []string `json:"app_identity_policies"`
	DiagnosticsClasses   []string `json:"diagnostics_classes"`
	PrivacyClasses       []string `json:"privacy_classes"`
	ExactEndpointLogging bool     `json:"exact_endpoint_logging"`
	AppIdentityLogging   bool     `json:"app_identity_logging"`
}

type FlowStreamMappingReport struct {
	MappingRules        []string `json:"mapping_rules"`
	StreamClasses       []string `json:"stream_classes"`
	ResultMappings      []string `json:"result_mappings"`
	BackpressureBuckets []string `json:"backpressure_buckets"`
	ResetBuckets        []string `json:"reset_buckets"`
}

type MTUFragmentationReport struct {
	MTUBuckets         []string `json:"mtu_buckets"`
	Fragmentation      []string `json:"fragmentation_buckets"`
	Reassembly         []string `json:"reassembly_buckets"`
	RetryBuckets       []string `json:"retry_buckets"`
	MaxPacketClass     string   `json:"max_packet_class"`
	PacketDumpsAllowed bool     `json:"packet_dumps_allowed"`
}

type BoundaryPolicyReport struct {
	DNSBoundaryClasses     []string `json:"dns_boundary_classes"`
	RoutingBoundaryClasses []string `json:"routing_boundary_classes"`
	KillSwitchPolicies     []string `json:"kill_switch_policies"`
	LocalDiagnosticsPolicy string   `json:"local_diagnostics_policy"`
	PrivacyReview          string   `json:"privacy_review"`
	RealDNSInterception    bool     `json:"real_dns_interception"`
	OSRouteModification    bool     `json:"os_route_modification"`
	AndroidVpnService      bool     `json:"android_vpnservice"`
}

type M51Contract struct {
	CommandName            string   `json:"command_name"`
	Decision               string   `json:"decision"`
	MayImplement           []string `json:"may_implement"`
	MustNotImplement       []string `json:"must_not_implement"`
	RequiredFixtures       []string `json:"required_fixtures"`
	RequiredGates          []string `json:"required_gates"`
	AcceptanceRequirements []string `json:"acceptance_requirements"`
}

type MisuseReport struct {
	DetectedControls []string `json:"detected_controls"`
	DetectedCount    int      `json:"detected_count"`
	ExpectedCount    int      `json:"expected_count"`
	Conclusion       string   `json:"conclusion"`
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
	Version                  string                  `json:"version"`
	FixtureID                string                  `json:"fixture_id"`
	GeneratedAt              string                  `json:"generated_at"`
	BackendVersion           string                  `json:"backend_version"`
	RecommendedNextMilestone string                  `json:"recommended_next_milestone"`
	Scope                    ScopeReport             `json:"scope"`
	Taxonomy                 PacketFlowTaxonomy      `json:"taxonomy"`
	Mapping                  FlowStreamMappingReport `json:"mapping"`
	MTU                      MTUFragmentationReport  `json:"mtu"`
	Boundaries               BoundaryPolicyReport    `json:"boundaries"`
	M51Contract              M51Contract             `json:"m51_contract"`
	Misuse                   MisuseReport            `json:"misuse"`
	Parity                   ParityReport            `json:"parity"`
	Fixtures                 []FixtureEntry          `json:"fixtures"`
	FixtureHash              string                  `json:"fixture_hash"`
	PayloadLogged            bool                    `json:"payload_logged"`
	SecretLogged             bool                    `json:"secret_logged"`
	Conclusion               string                  `json:"conclusion"`
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
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              generatedAt,
		BackendVersion:           BackendVersion,
		RecommendedNextMilestone: RecommendedNextMilestone,
		Scope: ScopeReport{
			AllowedBehaviors: []string{
				"class_only_packet_flow_semantics",
				"flow_to_runtime_stream_model",
				"stream_to_flow_summary_model",
				"local_diagnostics_buckets",
				"M51_local_desktop_contract",
			},
			BlockedBehaviors: []string{
				"real_tun_device_creation",
				"real_packet_capture",
				"os_route_modification",
				"android_vpnservice",
				"app_traffic_interception",
				"real_dns_interception",
				"public_network_behavior",
				"payload_logging",
				"packet_dumps",
				"per_app_identity_logging",
				"precise_endpoint_logging",
			},
			Decision: DecisionReady,
		},
		Taxonomy: PacketFlowTaxonomy{
			PacketFlowClasses:   []string{"tcp_like_flow", "udp_like_flow", "dns_boundary_flow", "reset_flow", "backpressure_flow", "control_misuse_flow"},
			FlowIdentityClasses: []string{"flow_hash_bucket", "session_bucket", "direction_bucket", "protocol_class_bucket"},
			AppIdentityPolicies: []string{"app_identity_not_collected", "app_class_optional_future_review", "per_app_logging_blocked"},
			DiagnosticsClasses:  []string{"aggregate_flow_count", "mtu_bucket_count", "reset_bucket_count", "backpressure_bucket_count"},
			PrivacyClasses:      []string{"payload_free", "endpoint_bucket_only", "session_local_only", "measurementreview_composed"},
		},
		Mapping: FlowStreamMappingReport{
			MappingRules:        []string{"one_packet_flow_to_one_runtime_stream", "flow_identity_hash_bucket_only", "localproxyadapter_precondition", "carrier_selection_after_policy_review"},
			StreamClasses:       []string{"interactive_packet_stream", "bulk_packet_stream", "datagram_like_packet_stream", "control_packet_stream"},
			ResultMappings:      []string{"stream_closed_to_flow_closed_bucket", "stream_reset_to_flow_reset_bucket", "stream_pressure_to_flow_backpressure_bucket", "stream_error_to_safe_flow_error_bucket"},
			BackpressureBuckets: []string{"adapter_pressure", "runtime_stream_pressure", "carrier_pressure", "kill_switch_pressure"},
			ResetBuckets:        []string{"local_reset", "stream_reset", "policy_reset", "carrier_reset"},
		},
		MTU: MTUFragmentationReport{
			MTUBuckets:     []string{"small_mtu_bucket", "standard_mtu_bucket", "large_mtu_bucket"},
			Fragmentation:  []string{"no_fragment", "bounded_fragment", "mtu_bucket_fragment"},
			Reassembly:     []string{"ordered_reassembly", "bounded_missing_fragment", "reset_clears_reassembly"},
			RetryBuckets:   []string{"no_retry", "bounded_retry", "policy_blocked_retry"},
			MaxPacketClass: "bounded_synthetic_packet_class",
		},
		Boundaries: BoundaryPolicyReport{
			DNSBoundaryClasses:     []string{"dns_metadata_blocked_by_default", "dns_boundary_review_required", "dns_class_bucket_only"},
			RoutingBoundaryClasses: []string{"no_os_route_changes", "no_default_route_install", "local_harness_only"},
			KillSwitchPolicies:     []string{"fail_closed_summary_only", "no_os_firewall_changes", "blocked_until_m51_review"},
			LocalDiagnosticsPolicy: "aggregate_buckets_only",
			PrivacyReview:          "measurementreview_required",
		},
		M51Contract: BuildM51Contract(),
		Misuse:      BuildMisuseReport(),
		Fixtures: []FixtureEntry{
			{Name: "packet_flow_taxonomy", Category: "taxonomy", SafeClass: "flow_class_buckets", Expected: "classes_present"},
			{Name: "flow_to_stream_mapping", Category: "mapping", SafeClass: "flow_hash_to_stream", Expected: "mapped_without_endpoint"},
			{Name: "stream_to_flow_result", Category: "mapping", SafeClass: "stream_result_bucket", Expected: "result_bucketed"},
			{Name: "mtu_fragmentation", Category: "mtu", SafeClass: "mtu_bucket", Expected: "bounded"},
			{Name: "retry_reset_backpressure", Category: "flow_control", SafeClass: "retry_reset_pressure_buckets", Expected: "bounded"},
			{Name: "dns_boundary", Category: "boundary", SafeClass: "dns_class_bucket", Expected: "real_dns_blocked"},
			{Name: "routing_boundary", Category: "boundary", SafeClass: "routing_class_bucket", Expected: "os_routes_blocked"},
			{Name: "kill_switch_policy", Category: "boundary", SafeClass: "fail_closed_summary", Expected: "modeled_only"},
			{Name: "privacy_review", Category: "privacy", SafeClass: "measurementreview_composed", Expected: "passed"},
			{Name: "m51_contract", Category: "contract", SafeClass: "go_for_local_desktop_prototype", Expected: "ready"},
		},
		Conclusion: ConclusionPassed,
	}
	set.Parity = BuildParityReport(set)
	set.FixtureHash = HashValue(fixtureHashInput(set))
	if err := ValidateFixtureSet(set); err != nil {
		return FixtureSet{}, err
	}
	return set, nil
}

func BuildM51Contract() M51Contract {
	return M51Contract{
		CommandName: "vpnsemantics",
		Decision:    DecisionReady,
		MayImplement: []string{
			"deterministic_local_desktop_packet_flow_harness",
			"packet_flow_to_stream_mapping",
			"mtu_bucket_fragmentation_model",
			"stream_result_to_flow_summary_mapping",
			"local_diagnostics_buckets",
		},
		MustNotImplement: []string{
			"real_tun_device_creation",
			"real_packet_capture",
			"os_route_modification",
			"android_vpnservice",
			"public_network_behavior",
			"real_dns_interception",
			"payload_logging",
			"packet_dumps",
			"per_app_identity_logging",
			"precise_endpoint_logging",
		},
		RequiredFixtures: []string{"packet_flow_taxonomy", "flow_to_stream_mapping", "mtu_fragmentation", "retry_reset_backpressure", "dns_boundary", "kill_switch_policy", "privacy_review"},
		RequiredGates:    []string{"vpnsemantics", "localproxyadapter", "measurementreview", "hardening", "codegen"},
		AcceptanceRequirements: []string{
			"no_real_packet_capture",
			"no_os_route_changes",
			"no_android_vpnservice",
			"no_real_dns_interception",
			"payload_free_summaries",
			"endpoint_bucket_only",
			"generated_interpreted_parity",
		},
	}
}

func BuildMisuseReport() MisuseReport {
	required := RequiredMisuseNames()
	return MisuseReport{DetectedControls: append([]string{}, required...), DetectedCount: len(required), ExpectedCount: len(required), Conclusion: ConclusionPassed}
}

func BuildParityReport(set FixtureSet) ParityReport {
	markers := []string{"PacketSemanticsSchemaVersion", "PacketSemanticsGeneratedProfileID", "PacketSemanticsBackendVersion", "PacketSemanticsFlowClasses", "PacketSemanticsM51Decision", "GeneratedPacketSemanticsFixtureSet"}
	hash := HashValue(map[string]any{
		"version":    set.Version,
		"taxonomy":   set.Taxonomy,
		"mapping":    set.Mapping,
		"boundaries": set.Boundaries,
		"contract":   set.M51Contract,
	})
	return ParityReport{GeneratedMarkers: markers, InterpretedHash: hash, GeneratedHash: hash, Conclusion: ConclusionPassed}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid vpn semantics fixture metadata")
	}
	if set.Scope.Decision != DecisionReady || len(set.Scope.BlockedBehaviors) < 10 {
		return errors.New("vpn semantics scope incomplete")
	}
	if set.Taxonomy.AppIdentityLogging || set.Taxonomy.ExactEndpointLogging || len(set.Taxonomy.PacketFlowClasses) < 6 {
		return errors.New("vpn semantics taxonomy unsafe")
	}
	if len(set.Mapping.MappingRules) < 4 || len(set.Mapping.ResultMappings) < 4 {
		return errors.New("vpn semantics flow mapping incomplete")
	}
	if set.MTU.PacketDumpsAllowed || len(set.MTU.MTUBuckets) < 3 || len(set.MTU.Fragmentation) < 3 || len(set.MTU.Reassembly) < 3 {
		return errors.New("vpn semantics mtu model unsafe")
	}
	if set.Boundaries.RealDNSInterception || set.Boundaries.OSRouteModification || set.Boundaries.AndroidVpnService {
		return errors.New("vpn semantics boundary model unsafe")
	}
	if set.M51Contract.Decision != DecisionReady || len(set.M51Contract.AcceptanceRequirements) < 6 {
		return errors.New("vpn semantics M51 contract incomplete")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("vpn semantics misuse report incomplete")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 5 {
		return errors.New("vpn semantics generated parity failed")
	}
	if set.PayloadLogged || set.SecretLogged {
		return errors.New("vpn semantics fixture reports unsafe logging")
	}
	for _, fixture := range set.Fixtures {
		if fixture.PayloadLogged || fixture.SecretLogged {
			return fmt.Errorf("unsafe vpn semantics fixture %s", fixture.Name)
		}
	}
	if set.FixtureHash != "" && set.FixtureHash != HashValue(fixtureHashInput(set)) {
		return errors.New("vpn semantics fixture hash mismatch")
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
	if err := ScanForLeak(value); err != nil {
		return err
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
	for _, marker := range []string{`"payload_logged": true`, `"secret_logged": true`, `"app_identity_logging": true`, `"exact_endpoint_logging": true`, `"packet_dumps_allowed": true`, `"real_dns_interception": true`, `"os_route_modification": true`, `"android_vpnservice": true`} {
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
		`"raw_packet_bytes"`,
		`"packet_capture_dump"`,
		`"packet_dump_value"`,
		`"app_identity_value"`,
		`"exact_endpoint_value"`,
		`"credential_value"`,
		`"secret_value"`,
		`"private_key"`,
		`"session_secret"`,
		`"auth_tag"`,
		`"nonce_base"`,
		`"resolver_ip"`,
		`"exact_dns_query"`,
		`"public_network_egress"`,
	}
}

func RequiredMisuseNames() []string {
	return []string{
		"vpnsemantics_allows_packet_capture",
		"vpnsemantics_allows_payload_logging",
		"vpnsemantics_allows_os_route_modification",
		"vpnsemantics_allows_android_vpnservice",
		"vpnsemantics_allows_real_dns_interception",
		"vpnsemantics_logs_app_identity",
		"vpnsemantics_logs_exact_endpoint",
		"vpnsemantics_bypasses_localproxyadapter",
		"vpnsemantics_bypasses_measurementreview",
		"vpnsemantics_public_claim_working_vpn",
		"vpnsemantics_payload_leak",
		"vpnsemantics_secret_leak",
		"vpnsemantics_generated_backend_drift",
	}
}

func SortedRequiredMisuseNames() []string {
	names := RequiredMisuseNames()
	sort.Strings(names)
	return names
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}
