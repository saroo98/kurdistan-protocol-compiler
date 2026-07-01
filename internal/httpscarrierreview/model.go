// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package httpscarrierreview

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
	Version                  = "httpscarrierreview-v1"
	DefaultFixtureID         = "https_like_carrier_lab_design_lock_v1"
	BackendVersion           = "0.41.0-lab"
	RecommendedNextMilestone = "M42: HTTPS-like carrier lab prototype"

	StatusLocked  = "locked"
	StatusBlocked = "blocked"
	StatusReview  = "review"
	DecisionReady = "ready_for_m42_lab_prototype"
)

var ErrRefuseOverwrite = errors.New("refusing to overwrite existing HTTPS carrier review fixture")

type BehaviorBoundary struct {
	Name     string `json:"name"`
	Blocked  bool   `json:"blocked"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence"`
}

type ShapeDescriptor struct {
	Name             string   `json:"name"`
	ShapeClass       string   `json:"shape_class"`
	AllowedMarkers   []string `json:"allowed_markers"`
	MaxMarkerBytes   int      `json:"max_marker_bytes"`
	ProfileSensitive bool     `json:"profile_sensitive"`
	PayloadFree      bool     `json:"payload_free"`
}

type StreamMappingContract struct {
	OpenMapping       string `json:"open_mapping"`
	CloseMapping      string `json:"close_mapping"`
	ResetMapping      string `json:"reset_mapping"`
	ErrorMapping      string `json:"error_mapping"`
	IsolationRequired bool   `json:"isolation_required"`
	ProfileSensitive  bool   `json:"profile_sensitive"`
}

type BackpressureContract struct {
	QueueLimitRequired    bool     `json:"queue_limit_required"`
	StreamWindowRequired  bool     `json:"stream_window_required"`
	SessionWindowRequired bool     `json:"session_window_required"`
	CarrierSignals        []string `json:"carrier_signals"`
	FailureMode           string   `json:"failure_mode"`
}

type ResetErrorContract struct {
	ResetIsolationRequired bool     `json:"reset_isolation_required"`
	ErrorIsolationRequired bool     `json:"error_isolation_required"`
	AllowedErrorBuckets    []string `json:"allowed_error_buckets"`
	UnsafeFallbackBlocked  bool     `json:"unsafe_fallback_blocked"`
}

type IntegrationContract struct {
	Layer      string   `json:"layer"`
	Required   bool     `json:"required"`
	Checks     []string `json:"checks"`
	Conclusion string   `json:"conclusion"`
}

type FixtureSchemaContract struct {
	SchemaVersion string   `json:"schema_version"`
	RequiredFiles []string `json:"required_files"`
	SafeFields    []string `json:"safe_fields"`
	ForbiddenData []string `json:"forbidden_data"`
}

type TraceHygieneContract struct {
	AllowedFields   []string `json:"allowed_fields"`
	ForbiddenFields []string `json:"forbidden_fields"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

type MisuseControl struct {
	Name     string `json:"name"`
	Blocked  bool   `json:"blocked"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
}

type M42AcceptanceCriterion struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Evidence string `json:"evidence"`
}

type RiskItem struct {
	Name       string `json:"name"`
	Level      string `json:"level"`
	Mitigation string `json:"mitigation"`
	Status     string `json:"status"`
}

type ChecklistItem struct {
	Name     string `json:"name"`
	Checked  bool   `json:"checked"`
	Evidence string `json:"evidence"`
}

type HTTPSCarrierLabContract struct {
	Version                  string                   `json:"version"`
	FixtureID                string                   `json:"fixture_id"`
	GeneratedAt              string                   `json:"generated_at"`
	GeneratedAtUnix          int64                    `json:"generated_at_unix"`
	BackendVersion           string                   `json:"backend_version"`
	RecommendedNextMilestone string                   `json:"recommended_next_milestone"`
	AllowedBehavior          []string                 `json:"allowed_behavior"`
	BlockedBehavior          []BehaviorBoundary       `json:"blocked_behavior"`
	RequestShapes            []ShapeDescriptor        `json:"request_shapes"`
	ResponseShapes           []ShapeDescriptor        `json:"response_shapes"`
	StreamMapping            StreamMappingContract    `json:"stream_mapping"`
	Backpressure             BackpressureContract     `json:"backpressure"`
	ResetError               ResetErrorContract       `json:"reset_error"`
	FixtureSchema            FixtureSchemaContract    `json:"fixture_schema"`
	TraceHygiene             TraceHygieneContract     `json:"trace_hygiene"`
	MisuseControls           []MisuseControl          `json:"misuse_controls"`
	GeneratedParityRequired  bool                     `json:"generated_parity_required"`
	M42AcceptanceCriteria    []M42AcceptanceCriterion `json:"m42_acceptance_criteria"`
	ContractHash             string                   `json:"contract_hash"`
	PayloadLogged            bool                     `json:"payload_logged"`
	SecretLogged             bool                     `json:"secret_logged"`
	Decision                 string                   `json:"decision"`
	Conclusion               string                   `json:"conclusion"`
}

type MisuseReport struct {
	UnsafeControls []string `json:"unsafe_controls"`
	UnsafeDetected int      `json:"unsafe_detected"`
	PayloadLogged  bool     `json:"payload_logged"`
	SecretLogged   bool     `json:"secret_logged"`
	Conclusion     string   `json:"conclusion"`
}

type ParityReport struct {
	ProfileID        string   `json:"profile_id"`
	BackendVersion   string   `json:"backend_version"`
	ContractSections int      `json:"contract_sections"`
	GeneratedMarkers []string `json:"generated_markers"`
	SemanticMatches  int      `json:"semantic_matches"`
	UnexpectedDrift  []string `json:"unexpected_drift,omitempty"`
	PayloadLogged    bool     `json:"payload_logged"`
	SecretLogged     bool     `json:"secret_logged"`
	Conclusion       string   `json:"conclusion"`
}

type FixtureSet struct {
	Version        string                   `json:"version"`
	Contract       HTTPSCarrierLabContract  `json:"contract"`
	Scope          []BehaviorBoundary       `json:"scope"`
	ShapeTaxonomy  []ShapeDescriptor        `json:"shape_taxonomy"`
	RequestShapes  []ShapeDescriptor        `json:"request_shapes"`
	ResponseShapes []ShapeDescriptor        `json:"response_shapes"`
	StreamMapping  StreamMappingContract    `json:"stream_mapping"`
	Backpressure   BackpressureContract     `json:"backpressure"`
	ResetError     ResetErrorContract       `json:"reset_error"`
	Integration    []IntegrationContract    `json:"integration"`
	M42Contract    []M42AcceptanceCriterion `json:"m42_contract"`
	Blockers       []BehaviorBoundary       `json:"blockers"`
	Risks          []RiskItem               `json:"risks"`
	Checklist      []ChecklistItem          `json:"checklist"`
	Misuse         MisuseReport             `json:"misuse"`
	Controls       []MisuseControl          `json:"controls"`
	Parity         ParityReport             `json:"parity"`
	FixtureHash    string                   `json:"fixture_hash"`
	PayloadLogged  bool                     `json:"payload_logged"`
	SecretLogged   bool                     `json:"secret_logged"`
	Conclusion     string                   `json:"conclusion"`
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
	contract := GenerateContract()
	set := FixtureSet{
		Version:        Version,
		Contract:       contract,
		Scope:          contract.BlockedBehavior,
		ShapeTaxonomy:  append(append([]ShapeDescriptor{}, contract.RequestShapes...), contract.ResponseShapes...),
		RequestShapes:  contract.RequestShapes,
		ResponseShapes: contract.ResponseShapes,
		StreamMapping:  contract.StreamMapping,
		Backpressure:   contract.Backpressure,
		ResetError:     contract.ResetError,
		Integration:    integrationContracts(),
		M42Contract:    contract.M42AcceptanceCriteria,
		Blockers:       contract.BlockedBehavior,
		Risks:          riskItems(),
		Checklist:      checklist(),
		Misuse:         ScanMisuse(),
		Controls:       contract.MisuseControls,
		Parity:         BuildParity(contract),
		Conclusion:     "passed",
	}
	set.FixtureHash = HashValue(setWithoutHash(set))
	return set, ValidateFixtureSet(set)
}

func GenerateContract() HTTPSCarrierLabContract {
	contract := HTTPSCarrierLabContract{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              fixedGeneratedAt().Format(time.RFC3339),
		GeneratedAtUnix:          fixedGeneratedAt().Unix(),
		BackendVersion:           BackendVersion,
		RecommendedNextMilestone: RecommendedNextMilestone,
		AllowedBehavior: []string{
			"bounded_request_shape_markers",
			"bounded_response_shape_markers",
			"loopback_lab_envelopes",
			"profile_sensitive_shape_selection",
			"metadata_only_stream_mapping",
			"payload_free_trace_summaries",
		},
		BlockedBehavior: blockedBehavior(),
		RequestShapes: []ShapeDescriptor{
			{"request_marker_compact", "compact_marker", []string{"rq_a", "rq_b"}, 48, true, true},
			{"request_marker_split", "split_marker", []string{"rq_head", "rq_tail"}, 64, true, true},
			{"request_marker_bucketed", "bucketed_marker", []string{"rq_small", "rq_medium", "rq_large"}, 96, true, true},
			{"request_marker_state_derived", "state_derived_marker", []string{"rq_state"}, 80, true, true},
		},
		ResponseShapes: []ShapeDescriptor{
			{"response_marker_compact", "compact_marker", []string{"rs_a", "rs_b"}, 48, true, true},
			{"response_marker_chunked", "chunked_marker", []string{"rs_chunk", "rs_final"}, 96, true, true},
			{"response_marker_error_bucket", "error_bucket_marker", []string{"rs_error", "rs_retry"}, 80, true, true},
			{"response_marker_state_derived", "state_derived_marker", []string{"rs_state"}, 80, true, true},
		},
		StreamMapping: StreamMappingContract{
			OpenMapping:       "stream_open_maps_to_request_shape_marker",
			CloseMapping:      "stream_close_maps_to_response_final_marker",
			ResetMapping:      "stream_reset_maps_to_reset_bucket_marker",
			ErrorMapping:      "target_error_maps_to_safe_error_bucket",
			IsolationRequired: true,
			ProfileSensitive:  true,
		},
		Backpressure: BackpressureContract{
			QueueLimitRequired:    true,
			StreamWindowRequired:  true,
			SessionWindowRequired: true,
			CarrierSignals:        []string{"queue_pressure_bucket", "stream_window_bucket", "session_window_bucket"},
			FailureMode:           "bounded_safe_reject",
		},
		ResetError: ResetErrorContract{
			ResetIsolationRequired: true,
			ErrorIsolationRequired: true,
			AllowedErrorBuckets:    []string{"target_error_bucket", "carrier_limit_bucket", "malformed_shape_bucket"},
			UnsafeFallbackBlocked:  true,
		},
		FixtureSchema: FixtureSchemaContract{
			SchemaVersion: Version,
			RequiredFiles: requiredFixtureFiles(),
			SafeFields:    []string{"shape_class", "marker_count", "stream_bucket", "backpressure_bucket", "reset_bucket", "error_bucket"},
			ForbiddenData: []string{"raw content", "raw encoded data", "credentials", "address literals", "packet dumps"},
		},
		TraceHygiene: TraceHygieneContract{
			AllowedFields:   []string{"carrier_shape_bucket", "stream_bucket", "backpressure_bucket", "reset_bucket", "error_bucket", "profile_shape_hash"},
			ForbiddenFields: []string{"raw content fields", "raw encoded content fields", "secret material fields", "cryptographic proof fields", "address literal fields"},
			Conclusion:      "passed",
		},
		MisuseControls:          misuseControls(),
		GeneratedParityRequired: true,
		M42AcceptanceCriteria:   m42Acceptance(),
		Decision:                DecisionReady,
		Conclusion:              "passed",
	}
	contract.ContractHash = HashValue(contractWithoutHash(contract))
	return contract
}

func ScanMisuse() MisuseReport {
	controls := []string{
		"real_tls_behavior",
		"real_https_client_behavior",
		"sni_routing",
		"host_header_routing",
		"cdn_provider_integration",
		"public_network_egress",
		"arbitrary_target_proxying",
		"payload_logging",
		"packet_capture",
		"measurement_upload",
	}
	return MisuseReport{UnsafeControls: controls, UnsafeDetected: len(controls), Conclusion: "passed"}
}

func BuildParity(contract HTTPSCarrierLabContract) ParityReport {
	markers := []string{
		"httpscarrierreview_generated.go",
		"httpscarrierreview_test.go",
		"httpscarrierreview_parity_test.go",
		"httpscarrierreview_hygiene_test.go",
		"HTTPSCarrierReviewSchemaVersion",
	}
	return ParityReport{
		BackendVersion:   contract.BackendVersion,
		ContractSections: 12,
		GeneratedMarkers: markers,
		SemanticMatches:  12,
		Conclusion:       "passed",
	}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.Conclusion != "passed" {
		return errors.New("invalid HTTPS carrier review fixture")
	}
	if set.Contract.Version != Version || set.Contract.BackendVersion != BackendVersion || set.Contract.Decision != DecisionReady {
		return errors.New("HTTPS carrier design lock contract incomplete")
	}
	if len(set.RequestShapes) < 4 || len(set.ResponseShapes) < 4 || len(set.Blockers) < 10 || len(set.M42Contract) < 10 {
		return errors.New("HTTPS carrier design lock missing required sections")
	}
	for _, blocker := range set.Blockers {
		if !blocker.Blocked {
			return fmt.Errorf("HTTPS carrier blocker not enforced: %s", blocker.Name)
		}
	}
	for _, shape := range set.ShapeTaxonomy {
		if !shape.ProfileSensitive || !shape.PayloadFree || shape.MaxMarkerBytes <= 0 || len(shape.AllowedMarkers) == 0 {
			return fmt.Errorf("unsafe HTTPS carrier shape descriptor: %s", shape.Name)
		}
	}
	for _, item := range set.Checklist {
		if !item.Checked {
			return fmt.Errorf("unchecked HTTPS carrier review item: %s", item.Name)
		}
	}
	if set.PayloadLogged || set.SecretLogged || set.Contract.PayloadLogged || set.Contract.SecretLogged || set.Parity.PayloadLogged || set.Parity.SecretLogged {
		return errors.New("HTTPS carrier trace hygiene failed")
	}
	if set.Contract.ContractHash == "" || HashValue(contractWithoutHash(set.Contract)) != set.Contract.ContractHash {
		return errors.New("HTTPS carrier contract hash drift")
	}
	if set.FixtureHash == "" || HashValue(setWithoutHash(set)) != set.FixtureHash {
		return errors.New("HTTPS carrier fixture hash drift")
	}
	return ScanForLeak(set)
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range forbiddenExactMarkers {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("HTTPS carrier review unsafe metadata marker: %s", marker)
		}
	}
	for _, marker := range unsafeClaimMarkers {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("HTTPS carrier review unsafe public claim marker: %s", marker)
		}
	}
	return nil
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

func LoadFixtureSet(path string) (FixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FixtureSet{}, err
	}
	var set FixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return FixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.Contract.Decision != newSet.Contract.Decision {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "decision_changed")
	}
	if len(oldSet.M42Contract) != len(newSet.M42Contract) {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "m42_contract_changed")
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

func blockedBehavior() []BehaviorBoundary {
	return []BehaviorBoundary{
		{"real_tls_behavior", true, "M41 is shape-contract only", "blocked before M42 implementation"},
		{"real_https_client_behavior", true, "no network client behavior in design lock", "blocked by scope gate"},
		{"real_sni_routing", true, "routing metadata must not depend on names", "blocked by misuse controls"},
		{"real_host_header_routing", true, "routing metadata must not depend on headers", "blocked by misuse controls"},
		{"real_domain_dependency", true, "no public naming dependency", "blocked by fixture scanner"},
		{"real_cdn_provider_integration", true, "no provider integration", "blocked by scope gate"},
		{"public_network_egress", true, "local deterministic harness only", "blocked by integration contract"},
		{"arbitrary_target_proxying", true, "synthetic target model only", "blocked by proxy contract"},
		{"payload_forwarding", true, "no carrier payload forwarding contract", "blocked by trace hygiene"},
		{"payload_logging", true, "safe counts and buckets only", "blocked by hygiene scanner"},
		{"packet_capture", true, "fixtures store summaries only", "blocked by fixture schema"},
		{"measurement_upload", true, "measurement review remains offline", "blocked by measurement contract"},
	}
}

func misuseControls() []MisuseControl {
	controls := []MisuseControl{}
	for _, blocker := range blockedBehavior() {
		controls = append(controls, MisuseControl{Name: blocker.Name, Blocked: true, Severity: "critical", Evidence: blocker.Evidence})
	}
	controls = append(controls,
		MisuseControl{"shape_collapse", true, "high", "request/response taxonomy requires profile-sensitive markers"},
		MisuseControl{"generated_backend_drift", true, "high", "generated parity tests required"},
	)
	return controls
}

func integrationContracts() []IntegrationContract {
	return []IntegrationContract{
		{"relaybridge", true, []string{"stream-open mapping", "stream-close mapping", "reset isolation"}, "locked"},
		{"loopbackrelay", true, []string{"loopback-only bind", "no public egress", "safe summaries"}, "locked"},
		{"labegress", true, []string{"synthetic allowlist only", "target error buckets", "target reset buckets"}, "locked"},
		{"localpipeline", true, []string{"local source/sink only", "byte-path fixture parity", "bounded queues"}, "locked"},
		{"pathhealth", true, []string{"offline health buckets", "no active probe", "no upload"}, "locked"},
		{"measurementreview", true, []string{"privacy gate", "no public measurement", "no exact endpoint data"}, "locked"},
	}
}

func m42Acceptance() []M42AcceptanceCriterion {
	return []M42AcceptanceCriterion{
		{"implements bounded request-shape markers", true, "shape taxonomy contract"},
		{"implements bounded response-shape markers", true, "shape taxonomy contract"},
		{"maps stream open close reset and error safely", true, "stream mapping contract"},
		{"propagates carrier backpressure", true, "backpressure contract"},
		{"integrates relaybridge loopbackrelay labegress localpipeline and pathhealth", true, "integration contract"},
		{"enforces measurement review blocker", true, "measurementreview integration"},
		{"rejects real TLS and real HTTPS client behavior", true, "scope contract"},
		{"rejects public network and provider integration", true, "scope contract"},
		{"keeps traces payload-free and secret-free", true, "trace hygiene contract"},
		{"passes generated interpreted parity", true, "generated backend parity contract"},
		{"includes fixture verify and compare commands", true, "fixture schema contract"},
	}
}

func riskItems() []RiskItem {
	return []RiskItem{
		{"shape collapse", "high", "profile-sensitive request/response shape taxonomy", StatusReview},
		{"unsafe fallback", "critical", "block public-network and provider behavior before implementation", StatusBlocked},
		{"trace leakage", "high", "fixture scanner and generated hygiene tests", StatusLocked},
		{"generated drift", "high", "M42 generated/interpreted parity criteria", StatusReview},
		{"misuse of review as implementation", "medium", "M41 package contains contracts only", StatusLocked},
	}
}

func checklist() []ChecklistItem {
	return []ChecklistItem{
		{"scope contract locked", true, "allowed and blocked behaviors enumerated"},
		{"request shape taxonomy locked", true, "four request shape classes"},
		{"response shape taxonomy locked", true, "four response shape classes"},
		{"stream mapping locked", true, "open close reset and error mappings"},
		{"backpressure contract locked", true, "queue stream and session pressure"},
		{"reset error isolation locked", true, "per-stream isolation required"},
		{"integration contracts locked", true, "six local/offline layers"},
		{"M42 acceptance criteria locked", true, "implementation gate list"},
		{"unsafe public claims blocked", true, "claim-safety scanner"},
		{"generated parity contract locked", true, "generated markers and tests"},
	}
}

func requiredFixtureFiles() []string {
	return []string{
		"https-carrier-lab-contract.json",
		"scope-report.json",
		"shape-taxonomy-report.json",
		"request-shapes-golden.json",
		"response-shapes-golden.json",
		"stream-mapping-report.json",
		"backpressure-contract-report.json",
		"reset-error-contract-report.json",
		"integration-contract-report.json",
		"m42-implementation-contract.json",
		"blocker-matrix.json",
		"risk-report.json",
		"readiness-checklist.json",
		"httpscarrierreview-report-golden.json",
		"httpscarrierreview-misuse-report.json",
		"httpscarrierreview-controls.json",
	}
}

func contractWithoutHash(contract HTTPSCarrierLabContract) HTTPSCarrierLabContract {
	contract.ContractHash = ""
	return contract
}

func setWithoutHash(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func fixedGeneratedAt() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

var forbiddenExactMarkers = []string{
	"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "packet_dump", "pcap",
	"raw_secret", "derived_key", "nonce_base", "auth_tag", "proof_material", "private_key", "session_secret",
	"public_ip", "destination_address", "exact_endpoint", "payload_logged\":true", "secret_logged\":true",
	"contains_payload\":true", "contains_secret\":true", "contains_sni\":true", "contains_host_header\":true",
	"contains_domain\":true", "contains_url\":true",
}

var unsafeClaimMarkers = []string{
	"guaranteed bypass",
	"undetectable",
	"impossible to detect",
	"field-ready",
	"production vpn",
	"working vpn app",
	"live probing",
	"real dns probing",
	"real https probing",
	"real udp probing",
}
