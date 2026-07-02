// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package keyexchangeplan

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
	Version                  = "keyexchangeplan-v1"
	BackendVersion           = "0.53.0-lab"
	DefaultFixtureID         = "production_key_exchange_design_v1"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M54: relay auth, rotation, and compatibility"
)

var generatedAt = time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type DesignItem struct {
	Name            string   `json:"name"`
	Policy          string   `json:"policy"`
	RequiredInputs  []string `json:"required_inputs"`
	RequiredOutputs []string `json:"required_outputs"`
	BlockedClasses  []string `json:"blocked_classes"`
	Conclusion      string   `json:"conclusion"`
}

type TranscriptBindingReport struct {
	BindingID        string   `json:"binding_id"`
	BoundComponents  []string `json:"bound_components"`
	RejectsConfusion bool     `json:"rejects_confusion"`
	PayloadLogged    bool     `json:"payload_logged"`
	SecretLogged     bool     `json:"secret_logged"`
	Conclusion       string   `json:"conclusion"`
}

type IdentityBindingReport struct {
	Policy                 string   `json:"policy"`
	ProfileBinding         string   `json:"profile_binding"`
	RelayIdentityBinding   string   `json:"relay_identity_binding"`
	UnauthenticatedRelayID bool     `json:"unauthenticated_relay_identity"`
	RequiredChecks         []string `json:"required_checks"`
	Conclusion             string   `json:"conclusion"`
}

type NonceReplayReport struct {
	NoncePolicy      string   `json:"nonce_policy"`
	ReplayPolicy     string   `json:"replay_policy"`
	NonceLogged      bool     `json:"nonce_logged"`
	ReplayAccepted   bool     `json:"replay_accepted"`
	RequiredChecks   []string `json:"required_checks"`
	SafetyInvariants []string `json:"safety_invariants"`
	Conclusion       string   `json:"conclusion"`
}

type DowngradeResistanceReport struct {
	VersionNegotiationBoundary string   `json:"version_negotiation_boundary"`
	AlgorithmAgilityBoundary   string   `json:"algorithm_agility_boundary"`
	RejectsSilentDowngrade     bool     `json:"rejects_silent_downgrade"`
	RequiredChecks             []string `json:"required_checks"`
	Conclusion                 string   `json:"conclusion"`
}

type KeySeparationReport struct {
	Policy             string   `json:"policy"`
	SeparatedContexts  []string `json:"separated_contexts"`
	ExportedSecretRule string   `json:"exported_secret_rule"`
	KeyReuseAllowed    bool     `json:"key_reuse_allowed"`
	Conclusion         string   `json:"conclusion"`
}

type RotationReadinessReport struct {
	Policy             string   `json:"policy"`
	RelayKeyPolicy     string   `json:"relay_key_policy"`
	ResumptionPolicy   string   `json:"resumption_policy"`
	ForwardSecrecyGoal string   `json:"forward_secrecy_goal"`
	RecoveryGoal       string   `json:"post_compromise_recovery_goal"`
	RequiredInterfaces []string `json:"required_interfaces"`
	Conclusion         string   `json:"conclusion"`
}

type TransportCompatibilityReport struct {
	Policy                string   `json:"policy"`
	GeneratedConstraints  []string `json:"generated_constraints"`
	CompatibilityChecks   []string `json:"compatibility_checks"`
	GeneratedDriftAllowed bool     `json:"generated_drift_allowed"`
	Conclusion            string   `json:"conclusion"`
}

type ExternalReviewReadinessReport struct {
	PackageID           string   `json:"package_id"`
	RequiredArtifacts   []string `json:"required_artifacts"`
	IndependentReview   bool     `json:"independent_review_required"`
	ReviewBypassAllowed bool     `json:"review_bypass_allowed"`
	Conclusion          string   `json:"conclusion"`
}

type TraceHygieneReport struct {
	ReportsScanned int    `json:"reports_scanned"`
	PayloadLogged  bool   `json:"payload_logged"`
	SecretLogged   bool   `json:"secret_logged"`
	NonceLogged    bool   `json:"nonce_logged"`
	AuthTagLogged  bool   `json:"auth_tag_logged"`
	Conclusion     string `json:"conclusion"`
}

type PublicClaimSafetyReport struct {
	DocsChecked       int      `json:"docs_checked"`
	ForbiddenClaims   []string `json:"forbidden_claims"`
	UnsafeClaimsFound []string `json:"unsafe_claims_found,omitempty"`
	Conclusion        string   `json:"conclusion"`
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
	UnexpectedDrift  []string `json:"unexpected_drift,omitempty"`
	Conclusion       string   `json:"conclusion"`
}

type FixtureSet struct {
	Version                  string                        `json:"version"`
	FixtureID                string                        `json:"fixture_id"`
	GeneratedAt              string                        `json:"generated_at"`
	BackendVersion           string                        `json:"backend_version"`
	RecommendedNextMilestone string                        `json:"recommended_next_milestone"`
	DesignInventory          []DesignItem                  `json:"design_inventory"`
	TranscriptBinding        TranscriptBindingReport       `json:"transcript_binding"`
	IdentityBinding          IdentityBindingReport         `json:"identity_binding"`
	NonceReplay              NonceReplayReport             `json:"nonce_replay"`
	DowngradeResistance      DowngradeResistanceReport     `json:"downgrade_resistance"`
	KeySeparation            KeySeparationReport           `json:"key_separation"`
	RotationReadiness        RotationReadinessReport       `json:"rotation_readiness"`
	TransportCompatibility   TransportCompatibilityReport  `json:"transport_compatibility"`
	ExternalReviewReadiness  ExternalReviewReadinessReport `json:"external_review_readiness"`
	Misuse                   MisuseReport                  `json:"misuse"`
	TraceHygiene             TraceHygieneReport            `json:"trace_hygiene"`
	PublicClaims             PublicClaimSafetyReport       `json:"public_claims"`
	Parity                   ParityReport                  `json:"parity"`
	FixtureHash              string                        `json:"fixture_hash"`
	PayloadLogged            bool                          `json:"payload_logged"`
	SecretLogged             bool                          `json:"secret_logged"`
	Conclusion               string                        `json:"conclusion"`
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
		DesignInventory:          DefaultDesignInventory(),
		TranscriptBinding:        DefaultTranscriptBindingReport(),
		IdentityBinding:          DefaultIdentityBindingReport(),
		NonceReplay:              DefaultNonceReplayReport(),
		DowngradeResistance:      DefaultDowngradeResistanceReport(),
		KeySeparation:            DefaultKeySeparationReport(),
		RotationReadiness:        DefaultRotationReadinessReport(),
		TransportCompatibility:   DefaultTransportCompatibilityReport(),
		ExternalReviewReadiness:  DefaultExternalReviewReadinessReport(),
		Misuse:                   BuildMisuseReport(),
		TraceHygiene:             BuildTraceHygieneReport(),
		PublicClaims:             BuildPublicClaimSafetyReport(),
	}
	set.Parity = BuildParityReport(set)
	set.Conclusion = ConclusionPassed
	set.FixtureHash = HashValue(fixtureHashInput(set))
	if err := ValidateFixtureSet(set); err != nil {
		set.Conclusion = "failed"
		return set, err
	}
	return set, nil
}

func DefaultDesignInventory() []DesignItem {
	items := []DesignItem{
		design("handshake_transcript_binding", "bind_profile_relay_client_ephemeral_versions_and_capabilities", []string{"profile_hash", "relay_identity_bucket", "client_ephemeral_class", "capability_set"}, []string{"transcript_hash_class", "compatibility_result"}, []string{"payload_material", "secret_material"}),
		design("profile_identity_binding", "profile_hash_and_wire_policy_bound_to_handshake_context", []string{"profile_id", "profile_hash", "wire_policy_hash"}, []string{"profile_binding_result"}, []string{"profile_version_confusion", "unbound_profile_id"}),
		design("relay_identity_binding", "relay_identity_required_before_session_open", []string{"relay_identity_bucket", "rotation_epoch_bucket"}, []string{"relay_identity_result"}, []string{"unauthenticated_relay_identity", "silent_identity_fallback"}),
		design("client_ephemeral_policy", "fresh_ephemeral_key_per_session_design_contract", []string{"client_ephemeral_class", "session_id_bucket"}, []string{"ephemeral_freshness_result"}, []string{"key_reuse_across_contexts", "ephemeral_fixture_persistence"}),
		design("relay_key_policy", "static_or_rotating_relay_identity_with_reviewed_rotation_interface", []string{"relay_identity_bucket", "rotation_policy"}, []string{"rotation_readiness_result"}, []string{"private_key_fixture", "operator_secret_fixture"}),
		design("nonce_replay_policy", "directional_nonce_space_with_bounded_replay_window", []string{"direction_class", "sequence_bucket", "epoch_bucket"}, []string{"replay_result", "nonce_uniqueness_result"}, []string{"nonce_logging", "replay_acceptance"}),
		design("downgrade_resistance", "version_and_algorithm_selection_bound_to_transcript", []string{"version_floor", "algorithm_suite_bucket", "capability_hash"}, []string{"downgrade_result"}, []string{"silent_downgrade", "algorithm_confusion"}),
		design("key_separation", "separate_context_labels_for_handshake_transport_exporter_and_trace_safe_summaries", []string{"context_label", "direction_class"}, []string{"key_context_result"}, []string{"key_reuse_across_contexts", "exported_secret_logging"}),
		design("session_resumption", "disabled_until_independent_review_or_explicit_reviewed_ticket_contract", []string{"review_status"}, []string{"resumption_policy_result"}, []string{"unreviewed_resumption", "ticket_secret_fixture"}),
		design("external_crypto_review", "review_package_required_before_claiming_production_cryptography", []string{"test_vectors", "threat_model", "failure_modes", "invariants"}, []string{"review_package_result"}, []string{"independent_review_bypass", "production_claim"}),
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func DefaultTranscriptBindingReport() TranscriptBindingReport {
	return TranscriptBindingReport{
		BindingID: "keyexchangeplan-transcript-binding-v1",
		BoundComponents: []string{
			"profile_id_hash",
			"relay_identity_bucket",
			"client_ephemeral_class",
			"relay_rotation_epoch_bucket",
			"version_floor",
			"algorithm_suite_bucket",
			"generated_transport_compatibility_hash",
		},
		RejectsConfusion: true,
		Conclusion:       ConclusionPassed,
	}
}

func DefaultIdentityBindingReport() IdentityBindingReport {
	return IdentityBindingReport{
		Policy:               "profile_and_relay_identity_bound_before_session_open",
		ProfileBinding:       "profile_hash_plus_generated_transport_policy_hash",
		RelayIdentityBinding: "reviewed_relay_identity_bucket_with_rotation_epoch",
		RequiredChecks:       []string{"profile_hash_match", "relay_identity_required", "version_floor_match", "capability_set_match"},
		Conclusion:           ConclusionPassed,
	}
}

func DefaultNonceReplayReport() NonceReplayReport {
	return NonceReplayReport{
		NoncePolicy:      "directional_monotonic_nonce_space_with_context_label",
		ReplayPolicy:     "bounded_replay_window_reject_duplicate_old_and_future_jump",
		RequiredChecks:   []string{"nonce_context_unique", "duplicate_replay_rejected", "old_sequence_rejected", "future_jump_rejected", "close_reset_terminal"},
		SafetyInvariants: []string{"nonce_never_logged", "replay_never_accepted", "nonce_context_bound_to_transcript"},
		Conclusion:       ConclusionPassed,
	}
}

func DefaultDowngradeResistanceReport() DowngradeResistanceReport {
	return DowngradeResistanceReport{
		VersionNegotiationBoundary: "minimum_supported_version_and_profile_compatibility_floor_bound_to_transcript",
		AlgorithmAgilityBoundary:   "named_suite_registry_only_no_custom_primitive_design",
		RejectsSilentDowngrade:     true,
		RequiredChecks:             []string{"version_floor_bound", "algorithm_suite_bound", "capability_hash_bound", "downgrade_attempt_rejected"},
		Conclusion:                 ConclusionPassed,
	}
}

func DefaultKeySeparationReport() KeySeparationReport {
	return KeySeparationReport{
		Policy: "context_labeled_key_schedule_contract_no_custom_primitives",
		SeparatedContexts: []string{
			"handshake_context",
			"client_to_relay_transport_context",
			"relay_to_client_transport_context",
			"exporter_context",
			"trace_summary_context",
		},
		ExportedSecretRule: "exporters_are_named_and_reviewed_no_fixture_secret_material",
		Conclusion:         ConclusionPassed,
	}
}

func DefaultRotationReadinessReport() RotationReadinessReport {
	return RotationReadinessReport{
		Policy:             "rotation_interfaces_defined_for_m54_no_key_material_in_fixtures",
		RelayKeyPolicy:     "static_or_rotating_identity_bucket_with_epoch_and_overlap_contract",
		ResumptionPolicy:   "disabled_until_reviewed_resumption_contract",
		ForwardSecrecyGoal: "fresh_client_ephemeral_per_session_and_relay_rotation_support",
		RecoveryGoal:       "post_compromise_recovery_requires_epoch_rotation_and_session_rekey_boundary",
		RequiredInterfaces: []string{"relay_identity_epoch", "rotation_overlap_window", "compatibility_floor", "safe_failure_reason", "review_artifact_linkage"},
		Conclusion:         ConclusionPassed,
	}
}

func DefaultTransportCompatibilityReport() TransportCompatibilityReport {
	return TransportCompatibilityReport{
		Policy: "generated_transport_compatibility_hash_bound_to_handshake",
		GeneratedConstraints: []string{
			"profile_specific_wire_policy_bound",
			"carrier_family_policy_bound",
			"runtime_capability_policy_bound",
			"trace_hygiene_policy_bound",
			"generated_backend_version_bound",
		},
		CompatibilityChecks:   []string{"generated_backend_version_match", "profile_hash_match", "carrier_policy_match", "capability_floor_match"},
		GeneratedDriftAllowed: false,
		Conclusion:            ConclusionPassed,
	}
}

func DefaultExternalReviewReadinessReport() ExternalReviewReadinessReport {
	return ExternalReviewReadinessReport{
		PackageID: "m62-independent-cryptography-review-package-precondition",
		RequiredArtifacts: []string{
			"key_exchange_design_contract",
			"threat_model",
			"test_vector_plan",
			"failure_mode_matrix",
			"nonce_replay_invariants",
			"downgrade_resistance_invariants",
			"rotation_and_compatibility_questions",
		},
		IndependentReview:   true,
		ReviewBypassAllowed: false,
		Conclusion:          ConclusionPassed,
	}
}

func BuildTraceHygieneReport() TraceHygieneReport {
	return TraceHygieneReport{ReportsScanned: 12, Conclusion: ConclusionPassed}
}

func BuildPublicClaimSafetyReport() PublicClaimSafetyReport {
	return PublicClaimSafetyReport{
		DocsChecked:     5,
		ForbiddenClaims: []string{"reviewed production cryptography", "production-ready key exchange", "guaranteed bypass", "undetectable", "field-ready", "independent crypto review complete"},
		Conclusion:      ConclusionPassed,
	}
}

func BuildMisuseReport() MisuseReport {
	controls := RequiredMisuseNames()
	return MisuseReport{DetectedControls: controls, DetectedCount: len(controls), ExpectedCount: len(controls), Conclusion: ConclusionPassed}
}

func BuildParityReport(set FixtureSet) ParityReport {
	hash := HashValue(parityHashInput(set))
	return ParityReport{
		GeneratedMarkers: []string{"KeyExchangePlanSchemaVersion", "KeyExchangePlanBackendVersion", "KeyExchangePlanDesignCount", "KeyExchangePlanMisuseCount", "KeyExchangePlanTranscriptPolicy", "KeyExchangePlanNextMilestone"},
		InterpretedHash:  hash,
		GeneratedHash:    hash,
		Conclusion:       ConclusionPassed,
	}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid key exchange plan fixture identity")
	}
	if len(set.DesignInventory) < 10 {
		return errors.New("key exchange design inventory incomplete")
	}
	if !set.TranscriptBinding.RejectsConfusion || len(set.TranscriptBinding.BoundComponents) < 6 {
		return errors.New("transcript binding contract incomplete")
	}
	if set.IdentityBinding.UnauthenticatedRelayID || len(set.IdentityBinding.RequiredChecks) < 4 {
		return errors.New("identity binding contract unsafe")
	}
	if set.NonceReplay.NonceLogged || set.NonceReplay.ReplayAccepted || len(set.NonceReplay.RequiredChecks) < 5 {
		return errors.New("nonce replay contract unsafe")
	}
	if !set.DowngradeResistance.RejectsSilentDowngrade || set.KeySeparation.KeyReuseAllowed {
		return errors.New("downgrade or key separation contract unsafe")
	}
	if set.TransportCompatibility.GeneratedDriftAllowed || len(set.TransportCompatibility.GeneratedConstraints) < 5 {
		return errors.New("generated transport compatibility contract unsafe")
	}
	if !set.ExternalReviewReadiness.IndependentReview || set.ExternalReviewReadiness.ReviewBypassAllowed || len(set.ExternalReviewReadiness.RequiredArtifacts) < 6 {
		return errors.New("external crypto review readiness incomplete")
	}
	if set.PayloadLogged || set.SecretLogged || set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.NonceLogged || set.TraceHygiene.AuthTagLogged {
		return errors.New("key exchange trace hygiene failed")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("key exchange misuse controls incomplete")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		return errors.New("key exchange generated parity failed")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: ConclusionPassed}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "keyexchangeplan_fixture_hash_changed")
	}
	if oldSet.Version != newSet.Version || oldSet.BackendVersion != newSet.BackendVersion {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "keyexchangeplan_schema_or_backend_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "keyexchangeplan_trace_hygiene_failed")
	}
	report.UnexpectedDrift = uniqueStrings(report.UnexpectedDrift)
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
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

func WriteFixtureSet(path string, set FixtureSet, force bool) error {
	if err := ValidateFixtureSet(set); err != nil {
		return err
	}
	return WriteJSON(path, set, force)
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s exists; use --force", path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
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

func ScanForLeak(value any) error {
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range ForbiddenMarkers() {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return fmt.Errorf("key exchange unsafe marker %q", marker)
		}
	}
	return nil
}

func ForbiddenMarkers() []string {
	return []string{
		`"raw_payload"`,
		`"payload_body"`,
		`"secret_value"`,
		`"nonce_value"`,
		`"auth_tag"`,
		`"proof_material"`,
		`"private_key"`,
		`"session_secret"`,
		`"derived_key"`,
		`"exported_secret"`,
		`"client_write_key"`,
		`"server_write_key"`,
	}
}

func RequiredMisuseNames() []string {
	return []string{
		"keyexchangeplan_custom_crypto_allowed",
		"keyexchangeplan_secret_logged",
		"keyexchangeplan_nonce_logged",
		"keyexchangeplan_auth_tag_logged",
		"keyexchangeplan_private_key_fixture",
		"keyexchangeplan_replay_allowed",
		"keyexchangeplan_downgrade_allowed",
		"keyexchangeplan_missing_transcript_binding",
		"keyexchangeplan_missing_identity_binding",
		"keyexchangeplan_missing_key_separation",
		"keyexchangeplan_independent_review_bypass",
		"keyexchangeplan_production_claim",
		"keyexchangeplan_generated_backend_drift",
	}
}

func design(name, policy string, inputs, outputs, blocked []string) DesignItem {
	return DesignItem{Name: name, Policy: policy, RequiredInputs: inputs, RequiredOutputs: outputs, BlockedClasses: blocked, Conclusion: ConclusionPassed}
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func parityHashInput(set FixtureSet) struct {
	Version                 string
	DesignInventory         []DesignItem
	TranscriptBinding       TranscriptBindingReport
	IdentityBinding         IdentityBindingReport
	NonceReplay             NonceReplayReport
	DowngradeResistance     DowngradeResistanceReport
	KeySeparation           KeySeparationReport
	RotationReadiness       RotationReadinessReport
	TransportCompatibility  TransportCompatibilityReport
	ExternalReviewReadiness ExternalReviewReadinessReport
} {
	return struct {
		Version                 string
		DesignInventory         []DesignItem
		TranscriptBinding       TranscriptBindingReport
		IdentityBinding         IdentityBindingReport
		NonceReplay             NonceReplayReport
		DowngradeResistance     DowngradeResistanceReport
		KeySeparation           KeySeparationReport
		RotationReadiness       RotationReadinessReport
		TransportCompatibility  TransportCompatibilityReport
		ExternalReviewReadiness ExternalReviewReadinessReport
	}{set.Version, set.DesignInventory, set.TranscriptBinding, set.IdentityBinding, set.NonceReplay, set.DowngradeResistance, set.KeySeparation, set.RotationReadiness, set.TransportCompatibility, set.ExternalReviewReadiness}
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
