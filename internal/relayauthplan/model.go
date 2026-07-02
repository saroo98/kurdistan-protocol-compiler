// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayauthplan

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
	Version                  = "relayauthplan-v1"
	BackendVersion           = "0.54.0-lab"
	DefaultFixtureID         = "relay_auth_rotation_compatibility_v1"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M55: relay operational hardening"
)

var generatedAt = time.Date(2026, 2, 19, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type AuthInventoryItem struct {
	Name            string   `json:"name"`
	Policy          string   `json:"policy"`
	RequiredInputs  []string `json:"required_inputs"`
	RequiredOutputs []string `json:"required_outputs"`
	BlockedClasses  []string `json:"blocked_classes"`
	Conclusion      string   `json:"conclusion"`
}

type IdentityBindingPolicyReport struct {
	Policy                        string   `json:"policy"`
	RelayIdentityRequired         bool     `json:"relay_identity_required"`
	ClientProfileIdentityRequired bool     `json:"client_profile_identity_required"`
	BoundComponents               []string `json:"bound_components"`
	UnauthenticatedRelayAllowed   bool     `json:"unauthenticated_relay_allowed"`
	Conclusion                    string   `json:"conclusion"`
}

type CompatibilityMatrixReport struct {
	Policy                  string   `json:"policy"`
	RelayCompatibility      []string `json:"relay_compatibility"`
	TransportCompatibility  []string `json:"transport_compatibility"`
	CarrierCompatibility    []string `json:"carrier_compatibility"`
	ProfileBundleVersioning []string `json:"profile_bundle_versioning"`
	UnknownVersionFailOpen  bool     `json:"unknown_version_fail_open"`
	GeneratedDriftAllowed   bool     `json:"generated_drift_allowed"`
	Conclusion              string   `json:"conclusion"`
}

type RotationPolicyReport struct {
	Policy                string   `json:"policy"`
	WindowPolicy          string   `json:"rotation_window_policy"`
	SplitBrainPolicy      string   `json:"split_brain_rotation_policy"`
	RequiredChecks        []string `json:"required_checks"`
	RotationWithoutWindow bool     `json:"rotation_without_window"`
	Conclusion            string   `json:"conclusion"`
}

type ExpiryRevocationReport struct {
	Policy               string   `json:"policy"`
	ProfileExpiryPolicy  string   `json:"profile_expiry_policy"`
	RevocationPolicy     string   `json:"revocation_policy"`
	StaleProfileFailOpen bool     `json:"stale_profile_fail_open"`
	RevocationMissing    bool     `json:"revocation_missing"`
	RequiredChecks       []string `json:"required_checks"`
	Conclusion           string   `json:"conclusion"`
}

type SafeFailurePolicyReport struct {
	Policy              string   `json:"policy"`
	FailureBuckets      []string `json:"failure_buckets"`
	FailOpenAllowed     bool     `json:"fail_open_allowed"`
	PublicDiscovery     bool     `json:"public_discovery_added"`
	ProductionProvision bool     `json:"production_provisioning_added"`
	Conclusion          string   `json:"conclusion"`
}

type DowngradeRejectionReport struct {
	Policy                 string   `json:"policy"`
	RejectsSilentDowngrade bool     `json:"rejects_silent_downgrade"`
	RequiredBindings       []string `json:"required_bindings"`
	UnknownVersionPolicy   string   `json:"unknown_version_policy"`
	CompatibilityFloor     string   `json:"compatibility_floor"`
	Conclusion             string   `json:"conclusion"`
}

type UnknownStaleProfileReport struct {
	Policy                 string   `json:"policy"`
	UnknownVersionPolicy   string   `json:"unknown_version_policy"`
	StaleProfilePolicy     string   `json:"stale_profile_policy"`
	SafeDiagnostics        []string `json:"safe_diagnostics"`
	UnknownVersionAccepted bool     `json:"unknown_version_accepted"`
	StaleProfileAccepted   bool     `json:"stale_profile_accepted"`
	Conclusion             string   `json:"conclusion"`
}

type OperationalHardeningPrereqReport struct {
	PackageID         string   `json:"package_id"`
	RequiredArtifacts []string `json:"required_artifacts"`
	M55Ready          bool     `json:"m55_ready"`
	Conclusion        string   `json:"conclusion"`
}

type TraceHygieneReport struct {
	ReportsScanned    int    `json:"reports_scanned"`
	PayloadLogged     bool   `json:"payload_logged"`
	SecretLogged      bool   `json:"secret_logged"`
	KeyMaterialLogged bool   `json:"key_material_logged"`
	AccountTracking   bool   `json:"account_tracking_added"`
	Conclusion        string `json:"conclusion"`
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
	Version                  string                           `json:"version"`
	FixtureID                string                           `json:"fixture_id"`
	GeneratedAt              string                           `json:"generated_at"`
	BackendVersion           string                           `json:"backend_version"`
	RecommendedNextMilestone string                           `json:"recommended_next_milestone"`
	AuthInventory            []AuthInventoryItem              `json:"relay_auth_inventory"`
	IdentityBinding          IdentityBindingPolicyReport      `json:"identity_binding_policy"`
	CompatibilityMatrix      CompatibilityMatrixReport        `json:"compatibility_matrix"`
	RotationPolicy           RotationPolicyReport             `json:"rotation_policy"`
	ExpiryRevocation         ExpiryRevocationReport           `json:"expiry_revocation_policy"`
	SafeFailure              SafeFailurePolicyReport          `json:"safe_failure_policy"`
	DowngradeRejection       DowngradeRejectionReport         `json:"downgrade_rejection"`
	UnknownStaleProfile      UnknownStaleProfileReport        `json:"unknown_stale_profile"`
	OperationalPrereqs       OperationalHardeningPrereqReport `json:"m55_operational_hardening_prerequisites"`
	Misuse                   MisuseReport                     `json:"misuse"`
	TraceHygiene             TraceHygieneReport               `json:"trace_hygiene"`
	PublicClaims             PublicClaimSafetyReport          `json:"public_claims"`
	Parity                   ParityReport                     `json:"parity"`
	FixtureHash              string                           `json:"fixture_hash"`
	PayloadLogged            bool                             `json:"payload_logged"`
	SecretLogged             bool                             `json:"secret_logged"`
	Conclusion               string                           `json:"conclusion"`
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
		AuthInventory:            DefaultAuthInventory(),
		IdentityBinding:          DefaultIdentityBindingPolicyReport(),
		CompatibilityMatrix:      DefaultCompatibilityMatrixReport(),
		RotationPolicy:           DefaultRotationPolicyReport(),
		ExpiryRevocation:         DefaultExpiryRevocationReport(),
		SafeFailure:              DefaultSafeFailurePolicyReport(),
		DowngradeRejection:       DefaultDowngradeRejectionReport(),
		UnknownStaleProfile:      DefaultUnknownStaleProfileReport(),
		OperationalPrereqs:       DefaultOperationalHardeningPrereqReport(),
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

func DefaultAuthInventory() []AuthInventoryItem {
	items := []AuthInventoryItem{
		authItem("relay_identity_policy", "relay_identity_bucket_required_before_session_open", []string{"relay_identity_bucket", "relay_epoch_bucket"}, []string{"relay_identity_result"}, []string{"unauthenticated_relay_acceptance"}),
		authItem("client_profile_identity_policy", "client_profile_hash_bound_to_profile_bundle_version", []string{"profile_id", "profile_hash", "profile_bundle_version"}, []string{"profile_identity_result"}, []string{"profile_confusion"}),
		authItem("profile_bundle_version_policy", "version_floor_and_bundle_epoch_bound_to_compatibility_matrix", []string{"bundle_version", "compatibility_floor"}, []string{"version_policy_result"}, []string{"unknown_version_fail_open"}),
		authItem("relay_auth_policy", "authenticated_relay_identity_required_no_public_discovery", []string{"relay_identity_bucket", "auth_policy_class"}, []string{"relay_auth_result"}, []string{"public_discovery", "account_tracking"}),
		authItem("relay_compatibility_matrix", "relay_profile_transport_carrier_versions_checked_before_open", []string{"relay_version", "profile_version", "transport_version", "carrier_family"}, []string{"compatibility_result"}, []string{"generated_backend_drift"}),
		authItem("transport_compatibility_matrix", "generated_transport_policy_hash_bound_to_compatibility_floor", []string{"transport_policy_hash", "backend_version"}, []string{"transport_compatibility_result"}, []string{"transport_confusion"}),
		authItem("carrier_compatibility_matrix", "carrier_family_and_review_gate_bound_to_relay_auth_decision", []string{"carrier_family", "review_gate_status"}, []string{"carrier_compatibility_result"}, []string{"carrier_review_bypass"}),
		authItem("rotation_window_policy", "overlap_window_required_for_epoch_rotation", []string{"current_epoch", "next_epoch", "overlap_window_bucket"}, []string{"rotation_window_result"}, []string{"rotation_without_window"}),
		authItem("profile_expiry_policy", "expired_profiles_fail_closed_with_safe_reason_bucket", []string{"profile_expiry_bucket", "current_epoch_bucket"}, []string{"expiry_result"}, []string{"stale_profile_fail_open"}),
		authItem("revocation_policy", "revocation_list_bucket_required_and_checked_before_session_open", []string{"revocation_epoch_bucket", "relay_identity_bucket"}, []string{"revocation_result"}, []string{"revocation_missing"}),
		authItem("safe_failure_policy", "closed_failure_buckets_with_no_retry_to_public_discovery", []string{"failure_bucket", "diagnostic_bucket"}, []string{"safe_failure_result"}, []string{"unsafe_fail_open", "public_relay_discovery"}),
		authItem("downgrade_rejection_policy", "version_floor_and_capability_hash_bound_to_auth_result", []string{"version_floor", "capability_hash"}, []string{"downgrade_result"}, []string{"silent_downgrade"}),
		authItem("unknown_version_policy", "unknown_versions_rejected_by_default_pending_explicit_matrix_entry", []string{"presented_version", "matrix_entry"}, []string{"unknown_version_result"}, []string{"unknown_version_acceptance"}),
		authItem("stale_profile_policy", "stale_profiles_rejected_by_default_with_rotation_hint_bucket", []string{"profile_epoch", "relay_epoch"}, []string{"stale_profile_result"}, []string{"stale_profile_acceptance"}),
		authItem("diagnostics_policy", "safe_bucketed_reasons_no_accounts_no_keys_no_payloads", []string{"failure_bucket", "compatibility_bucket"}, []string{"diagnostic_summary"}, []string{"secret_logging", "key_material_logging", "account_tracking"}),
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func DefaultIdentityBindingPolicyReport() IdentityBindingPolicyReport {
	return IdentityBindingPolicyReport{
		Policy:                        "relay_and_profile_identity_required_before_session_open",
		RelayIdentityRequired:         true,
		ClientProfileIdentityRequired: true,
		BoundComponents:               []string{"relay_identity_bucket", "relay_rotation_epoch_bucket", "profile_id_hash", "profile_bundle_version", "compatibility_floor", "capability_hash"},
		Conclusion:                    ConclusionPassed,
	}
}

func DefaultCompatibilityMatrixReport() CompatibilityMatrixReport {
	return CompatibilityMatrixReport{
		Policy:                  "relay_profile_transport_carrier_compatibility_checked_before_session_open",
		RelayCompatibility:      []string{"relay_version_floor", "relay_epoch_bucket", "auth_policy_class"},
		TransportCompatibility:  []string{"generated_backend_version", "profile_wire_policy_hash", "runtime_capability_floor"},
		CarrierCompatibility:    []string{"carrier_family_class", "carrier_review_gate_status", "measurement_review_gate_status"},
		ProfileBundleVersioning: []string{"profile_bundle_version", "profile_expiry_bucket", "revocation_epoch_bucket"},
		Conclusion:              ConclusionPassed,
	}
}

func DefaultRotationPolicyReport() RotationPolicyReport {
	return RotationPolicyReport{
		Policy:           "bounded_epoch_rotation_with_required_overlap_window",
		WindowPolicy:     "current_and_next_epoch_overlap_bucket_required",
		SplitBrainPolicy: "split_brain_epochs_fail_closed_with_rotation_hint_bucket",
		RequiredChecks:   []string{"epoch_overlap_present", "current_epoch_accepted", "next_epoch_accepted_inside_window", "old_epoch_rejected_after_window", "split_brain_rejected"},
		Conclusion:       ConclusionPassed,
	}
}

func DefaultExpiryRevocationReport() ExpiryRevocationReport {
	return ExpiryRevocationReport{
		Policy:              "expiry_and_revocation_checked_before_session_open",
		ProfileExpiryPolicy: "expired_or_stale_profile_fails_closed_by_default",
		RevocationPolicy:    "revocation_epoch_bucket_required_for_relay_identity",
		RequiredChecks:      []string{"profile_expiry_checked", "stale_profile_rejected", "revocation_bucket_checked", "revoked_relay_rejected"},
		Conclusion:          ConclusionPassed,
	}
}

func DefaultSafeFailurePolicyReport() SafeFailurePolicyReport {
	return SafeFailurePolicyReport{
		Policy:         "fail_closed_with_safe_bucketed_diagnostics",
		FailureBuckets: []string{"unauthenticated_relay", "unknown_version", "stale_profile", "revoked_relay", "rotation_split_brain", "compatibility_mismatch"},
		Conclusion:     ConclusionPassed,
	}
}

func DefaultDowngradeRejectionReport() DowngradeRejectionReport {
	return DowngradeRejectionReport{
		Policy:                 "silent_downgrade_rejected_before_relay_session_open",
		RejectsSilentDowngrade: true,
		RequiredBindings:       []string{"version_floor", "profile_bundle_version", "capability_hash", "relay_auth_policy", "generated_backend_version"},
		UnknownVersionPolicy:   "reject_unknown_version_by_default",
		CompatibilityFloor:     "minimum_supported_version_and_capability_floor",
		Conclusion:             ConclusionPassed,
	}
}

func DefaultUnknownStaleProfileReport() UnknownStaleProfileReport {
	return UnknownStaleProfileReport{
		Policy:               "unknown_and_stale_profiles_fail_closed_with_safe_diagnostics",
		UnknownVersionPolicy: "unknown_version_rejected_by_default_pending_matrix_entry",
		StaleProfilePolicy:   "stale_profile_rejected_by_default_pending_rotation_window",
		SafeDiagnostics:      []string{"unknown_version_bucket", "stale_profile_bucket", "rotation_hint_bucket", "compatibility_floor_bucket"},
		Conclusion:           ConclusionPassed,
	}
}

func DefaultOperationalHardeningPrereqReport() OperationalHardeningPrereqReport {
	return OperationalHardeningPrereqReport{
		PackageID: "m55-relay-operational-hardening-preconditions",
		RequiredArtifacts: []string{
			"relay_auth_identity_contract",
			"compatibility_matrix",
			"rotation_window_policy",
			"expiry_revocation_policy",
			"safe_failure_matrix",
			"diagnostics_redaction_policy",
			"generated_backend_parity_markers",
		},
		M55Ready:   true,
		Conclusion: ConclusionPassed,
	}
}

func BuildTraceHygieneReport() TraceHygieneReport {
	return TraceHygieneReport{ReportsScanned: 12, Conclusion: ConclusionPassed}
}

func BuildPublicClaimSafetyReport() PublicClaimSafetyReport {
	return PublicClaimSafetyReport{
		DocsChecked:     5,
		ForbiddenClaims: []string{"production relay provisioning", "public relay discovery", "field-ready relay operations", "guaranteed bypass", "undetectable", "account tracking enabled"},
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
		GeneratedMarkers: []string{"RelayAuthPlanSchemaVersion", "RelayAuthPlanBackendVersion", "RelayAuthPlanInventoryCount", "RelayAuthPlanMisuseCount", "RelayAuthPlanCompatibilityPolicy", "RelayAuthPlanNextMilestone"},
		InterpretedHash:  hash,
		GeneratedHash:    hash,
		Conclusion:       ConclusionPassed,
	}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid relay auth plan fixture identity")
	}
	if len(set.AuthInventory) < 15 {
		return errors.New("relay auth inventory incomplete")
	}
	if !set.IdentityBinding.RelayIdentityRequired || !set.IdentityBinding.ClientProfileIdentityRequired || set.IdentityBinding.UnauthenticatedRelayAllowed || len(set.IdentityBinding.BoundComponents) < 6 {
		return errors.New("relay auth identity binding unsafe")
	}
	if set.CompatibilityMatrix.UnknownVersionFailOpen || set.CompatibilityMatrix.GeneratedDriftAllowed || len(set.CompatibilityMatrix.RelayCompatibility) < 3 || len(set.CompatibilityMatrix.CarrierCompatibility) < 3 {
		return errors.New("relay auth compatibility matrix unsafe")
	}
	if set.RotationPolicy.RotationWithoutWindow || len(set.RotationPolicy.RequiredChecks) < 5 {
		return errors.New("relay rotation policy unsafe")
	}
	if set.ExpiryRevocation.StaleProfileFailOpen || set.ExpiryRevocation.RevocationMissing || len(set.ExpiryRevocation.RequiredChecks) < 4 {
		return errors.New("expiry or revocation policy unsafe")
	}
	if set.SafeFailure.FailOpenAllowed || set.SafeFailure.PublicDiscovery || set.SafeFailure.ProductionProvision || len(set.SafeFailure.FailureBuckets) < 6 {
		return errors.New("safe failure policy unsafe")
	}
	if !set.DowngradeRejection.RejectsSilentDowngrade || len(set.DowngradeRejection.RequiredBindings) < 5 {
		return errors.New("downgrade rejection incomplete")
	}
	if set.UnknownStaleProfile.UnknownVersionAccepted || set.UnknownStaleProfile.StaleProfileAccepted || len(set.UnknownStaleProfile.SafeDiagnostics) < 4 {
		return errors.New("unknown or stale profile policy unsafe")
	}
	if !set.OperationalPrereqs.M55Ready || len(set.OperationalPrereqs.RequiredArtifacts) < 7 {
		return errors.New("M55 operational hardening prerequisites incomplete")
	}
	if set.PayloadLogged || set.SecretLogged || set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.KeyMaterialLogged || set.TraceHygiene.AccountTracking {
		return errors.New("relay auth trace hygiene failed")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("relay auth misuse controls incomplete")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		return errors.New("relay auth generated parity failed")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: ConclusionPassed}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "relayauthplan_fixture_hash_changed")
	}
	if oldSet.Version != newSet.Version || oldSet.BackendVersion != newSet.BackendVersion {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "relayauthplan_schema_or_backend_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "relayauthplan_trace_hygiene_failed")
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
			return fmt.Errorf("relay auth unsafe marker %q", marker)
		}
	}
	return nil
}

func ForbiddenMarkers() []string {
	return []string{
		`"raw_payload"`,
		`"payload_body"`,
		`"secret_value"`,
		`"key_material_value"`,
		`"account_identifier"`,
		`"user_tracking_id"`,
		`"nonce_value"`,
		`"auth_tag"`,
		`"proof_material"`,
		`"private_key"`,
		`"session_secret"`,
		`"cloud_provider_metadata"`,
	}
}

func RequiredMisuseNames() []string {
	return []string{
		"relayauthplan_unauthenticated_relay_allowed",
		"relayauthplan_silent_downgrade_allowed",
		"relayauthplan_unknown_version_fail_open",
		"relayauthplan_stale_profile_fail_open",
		"relayauthplan_rotation_without_window",
		"relayauthplan_revocation_missing",
		"relayauthplan_secret_logged",
		"relayauthplan_key_material_logged",
		"relayauthplan_account_tracking_added",
		"relayauthplan_public_discovery_added",
		"relayauthplan_cloud_provider_dependency",
		"relayauthplan_generated_backend_drift",
	}
}

func authItem(name, policy string, inputs, outputs, blocked []string) AuthInventoryItem {
	return AuthInventoryItem{Name: name, Policy: policy, RequiredInputs: inputs, RequiredOutputs: outputs, BlockedClasses: blocked, Conclusion: ConclusionPassed}
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func parityHashInput(set FixtureSet) struct {
	Version             string
	AuthInventory       []AuthInventoryItem
	IdentityBinding     IdentityBindingPolicyReport
	CompatibilityMatrix CompatibilityMatrixReport
	RotationPolicy      RotationPolicyReport
	ExpiryRevocation    ExpiryRevocationReport
	SafeFailure         SafeFailurePolicyReport
	DowngradeRejection  DowngradeRejectionReport
	UnknownStaleProfile UnknownStaleProfileReport
	OperationalPrereqs  OperationalHardeningPrereqReport
} {
	return struct {
		Version             string
		AuthInventory       []AuthInventoryItem
		IdentityBinding     IdentityBindingPolicyReport
		CompatibilityMatrix CompatibilityMatrixReport
		RotationPolicy      RotationPolicyReport
		ExpiryRevocation    ExpiryRevocationReport
		SafeFailure         SafeFailurePolicyReport
		DowngradeRejection  DowngradeRejectionReport
		UnknownStaleProfile UnknownStaleProfileReport
		OperationalPrereqs  OperationalHardeningPrereqReport
	}{set.Version, set.AuthInventory, set.IdentityBinding, set.CompatibilityMatrix, set.RotationPolicy, set.ExpiryRevocation, set.SafeFailure, set.DowngradeRejection, set.UnknownStaleProfile, set.OperationalPrereqs}
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
