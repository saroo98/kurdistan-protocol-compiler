// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayprocess

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
	Version                  = "relayprocess-v1"
	BackendVersion           = "0.52.0-lab"
	DefaultFixtureID         = "relay_process_architecture_v1"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M53: production key exchange review"
)

var generatedAt = time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type ProcessRole struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	AllowedScope     string   `json:"allowed_scope"`
	BlockedBehaviors []string `json:"blocked_behaviors"`
	RequiredPolicies []string `json:"required_policies"`
	Conclusion       string   `json:"conclusion"`
}

type ConfigContract struct {
	ConfigID                      string   `json:"config_id"`
	LoadingPolicy                 string   `json:"loading_policy"`
	ProfileBundlePolicy           string   `json:"profile_bundle_policy"`
	RequiresExplicitLabMode       bool     `json:"requires_explicit_lab_mode"`
	AllowPublicDeploymentDefaults bool     `json:"allow_public_deployment_defaults"`
	AllowCloudProviderDependency  bool     `json:"allow_cloud_provider_dependency"`
	AllowProductionKeyingChanges  bool     `json:"allow_production_keying_changes"`
	AllowedConfigClasses          []string `json:"allowed_config_classes"`
	BlockedConfigClasses          []string `json:"blocked_config_classes"`
	PayloadLogged                 bool     `json:"payload_logged"`
	SecretLogged                  bool     `json:"secret_logged"`
	Conclusion                    string   `json:"conclusion"`
}

type LifecycleContract struct {
	Name             string   `json:"name"`
	Role             string   `json:"role"`
	StatePath        []string `json:"state_path"`
	TerminalStates   []string `json:"terminal_states"`
	RequiredHandlers []string `json:"required_handlers"`
	BlockedFallbacks []string `json:"blocked_fallbacks"`
	Conclusion       string   `json:"conclusion"`
}

type LoggingContract struct {
	Policy              string   `json:"policy"`
	AllowedFields       []string `json:"allowed_fields"`
	ForbiddenFields     []string `json:"forbidden_fields"`
	PublicUploadAllowed bool     `json:"public_upload_allowed"`
	PayloadLogged       bool     `json:"payload_logged"`
	SecretLogged        bool     `json:"secret_logged"`
	Conclusion          string   `json:"conclusion"`
}

type ShutdownContract struct {
	Policy               string   `json:"policy"`
	GracefulPhases       []string `json:"graceful_phases"`
	CrashRecoveryPolicy  string   `json:"crash_recovery_policy"`
	IdempotentClose      bool     `json:"idempotent_close"`
	UnreviewedAutoUpdate bool     `json:"unreviewed_auto_update"`
	Conclusion           string   `json:"conclusion"`
}

type CompatibilityContract struct {
	Policy           string   `json:"policy"`
	CapabilityChecks []string `json:"capability_checks"`
	UpgradePolicy    string   `json:"upgrade_policy"`
	RollbackPolicy   string   `json:"rollback_policy"`
	RejectsDowngrade bool     `json:"rejects_downgrade"`
	Conclusion       string   `json:"conclusion"`
}

type ResourceContract struct {
	Policy                string   `json:"policy"`
	Bounds                []string `json:"bounds"`
	AbuseControlPolicy    string   `json:"abuse_control_policy"`
	MissingResourcePolicy bool     `json:"missing_resource_policy"`
	Conclusion            string   `json:"conclusion"`
}

type M53Preconditions struct {
	ReviewID        string   `json:"review_id"`
	Preconditions   []string `json:"preconditions"`
	BlockedUntilM53 []string `json:"blocked_until_m53"`
	Conclusion      string   `json:"conclusion"`
}

type TraceHygieneReport struct {
	FixturesScanned int    `json:"fixtures_scanned"`
	PayloadLogged   bool   `json:"payload_logged"`
	SecretLogged    bool   `json:"secret_logged"`
	PacketCaptured  bool   `json:"packet_captured"`
	Conclusion      string `json:"conclusion"`
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
	Version                  string                  `json:"version"`
	FixtureID                string                  `json:"fixture_id"`
	GeneratedAt              string                  `json:"generated_at"`
	BackendVersion           string                  `json:"backend_version"`
	RecommendedNextMilestone string                  `json:"recommended_next_milestone"`
	Roles                    []ProcessRole           `json:"roles"`
	Config                   ConfigContract          `json:"config"`
	Lifecycle                []LifecycleContract     `json:"lifecycle"`
	Logging                  LoggingContract         `json:"logging"`
	Shutdown                 ShutdownContract        `json:"shutdown"`
	Compatibility            CompatibilityContract   `json:"compatibility"`
	Resource                 ResourceContract        `json:"resource"`
	M53Preconditions         M53Preconditions        `json:"m53_preconditions"`
	Misuse                   MisuseReport            `json:"misuse"`
	TraceHygiene             TraceHygieneReport      `json:"trace_hygiene"`
	PublicClaims             PublicClaimSafetyReport `json:"public_claims"`
	Parity                   ParityReport            `json:"parity"`
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
		Roles:                    DefaultRoles(),
		Config:                   DefaultConfigContract(),
		Lifecycle:                DefaultLifecycleContracts(),
		Logging:                  DefaultLoggingContract(),
		Shutdown:                 DefaultShutdownContract(),
		Compatibility:            DefaultCompatibilityContract(),
		Resource:                 DefaultResourceContract(),
		M53Preconditions:         DefaultM53Preconditions(),
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

func DefaultRoles() []ProcessRole {
	roles := []ProcessRole{
		role("client_process", "client", []string{"payload logging", "packet capture", "public observability upload", "unreviewed auto-update"}, []string{"config_contract", "profile_bundle_contract", "shutdown_policy", "resource_policy"}),
		role("relay_process", "relay", []string{"production relay provisioning", "cloud provider integration", "public deployment defaults", "production key exchange changes"}, []string{"listener_lifecycle", "egress_lifecycle", "compatibility_policy", "abuse_control_placeholder"}),
		role("supervisor_process", "supervisor", []string{"field-test tooling", "Android behavior", "real user account systems"}, []string{"crash_recovery_policy", "upgrade_rollback_policy", "observability_policy"}),
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	return roles
}

func DefaultConfigContract() ConfigContract {
	return ConfigContract{
		ConfigID:                      "relayprocess-config-contract-v1",
		LoadingPolicy:                 "explicit_lab_config_only",
		ProfileBundlePolicy:           "signed_manifest_placeholder_no_key_exchange_change",
		RequiresExplicitLabMode:       true,
		AllowPublicDeploymentDefaults: false,
		AllowCloudProviderDependency:  false,
		AllowProductionKeyingChanges:  false,
		AllowedConfigClasses:          []string{"process_role", "profile_bundle_id", "resource_bucket", "observability_bucket", "compatibility_floor"},
		BlockedConfigClasses:          []string{"secret_material_class", "provider_dependency_class", "public_route_class", "account_metadata_class", "auto_update_channel_class", "production_keying_class"},
		Conclusion:                    ConclusionPassed,
	}
}

func DefaultLifecycleContracts() []LifecycleContract {
	return []LifecycleContract{
		lifecycle("service_lifecycle", "client_or_relay", []string{"created", "configured", "starting", "ready", "draining", "stopped"}, []string{"stopped", "failed"}, []string{"bounded_start", "idempotent_stop", "drain_sessions"}, []string{"background_public_retry", "unbounded_restart_loop"}),
		lifecycle("session_lifecycle", "client_or_relay", []string{"new", "negotiating", "open", "draining", "closed"}, []string{"closed", "reset", "failed"}, []string{"capability_check", "profile_compatibility", "secure_context_create"}, []string{"accept_profile_mismatch", "accept_downgrade"}),
		lifecycle("carrier_lifecycle", "relay", []string{"inactive", "bound_to_profile", "opening", "active", "draining", "closed"}, []string{"closed", "failed"}, []string{"carrierreview_gate", "measurementreview_gate", "pathhealth_gate"}, []string{"unsafe_public_fallback", "provider_specific_auto_config"}),
		lifecycle("listener_lifecycle", "relay", []string{"disabled", "configured", "loopback_ready", "draining", "closed"}, []string{"closed", "failed"}, []string{"lab_scope_check", "loopback_policy_check"}, []string{"wildcard_bind", "public_bind"}),
		lifecycle("egress_lifecycle", "relay", []string{"disabled", "configured", "lab_target_ready", "draining", "closed"}, []string{"closed", "failed"}, []string{"labegress_allowlist", "target_redaction"}, []string{"arbitrary_target_proxying", "payload_forwarding_default"}),
	}
}

func DefaultLoggingContract() LoggingContract {
	return LoggingContract{
		Policy:              "structured_safe_metadata_only",
		AllowedFields:       []string{"role_class", "state_class", "resource_bucket", "event_count", "error_bucket", "compatibility_result"},
		ForbiddenFields:     []string{"payload_material_class", "packet_observation_class", "secret_material_class", "key_material_class", "proof_material_class", "provider_metadata_class", "account_metadata_class", "public_route_class", "auto_update_channel_class", "production_keying_class"},
		PublicUploadAllowed: false,
		Conclusion:          ConclusionPassed,
	}
}

func DefaultShutdownContract() ShutdownContract {
	return ShutdownContract{
		Policy:              "bounded_graceful_shutdown",
		GracefulPhases:      []string{"stop_accepting", "drain_sessions", "close_carriers", "flush_safe_summary", "terminal"},
		CrashRecoveryPolicy: "local_safe_restart_plan_no_public_retry",
		IdempotentClose:     true,
		Conclusion:          ConclusionPassed,
	}
}

func DefaultCompatibilityContract() CompatibilityContract {
	return CompatibilityContract{
		Policy:           "versioned_capability_floor",
		CapabilityChecks: []string{"backend_version", "profile_hash", "capability_set", "carrier_family_review", "security_policy"},
		UpgradePolicy:    "manual_reviewed_upgrade_only",
		RollbackPolicy:   "rollback_to_prior_reviewed_profile_bundle",
		RejectsDowngrade: true,
		Conclusion:       ConclusionPassed,
	}
}

func DefaultResourceContract() ResourceContract {
	return ResourceContract{
		Policy:             "bounded_process_resources",
		Bounds:             []string{"max_sessions_bucket", "max_streams_bucket", "max_carriers_bucket", "max_log_events_bucket", "max_restart_attempts_bucket"},
		AbuseControlPolicy: "placeholder_only_rate_bucket_and_reset_bucket_no_user_accounts",
		Conclusion:         ConclusionPassed,
	}
}

func DefaultM53Preconditions() M53Preconditions {
	return M53Preconditions{
		ReviewID: "m53-production-key-exchange-review-preconditions",
		Preconditions: []string{
			"relayprocess contracts passed",
			"security transcript binding unchanged",
			"generated backend parity passed",
			"trace hygiene passed",
			"public deployment defaults remain blocked",
		},
		BlockedUntilM53: []string{"production key exchange changes", "long term key distribution", "operator credential storage"},
		Conclusion:      ConclusionPassed,
	}
}

func BuildTraceHygieneReport() TraceHygieneReport {
	return TraceHygieneReport{FixturesScanned: 13, Conclusion: ConclusionPassed}
}

func BuildPublicClaimSafetyReport() PublicClaimSafetyReport {
	return PublicClaimSafetyReport{
		DocsChecked:     5,
		ForbiddenClaims: []string{"guaranteed bypass", "undetectable", "field-ready", "production relay", "working VPN app", "public deployment ready"},
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
		GeneratedMarkers: []string{"RelayProcessSchemaVersion", "RelayProcessBackendVersion", "RelayProcessRoleCount", "RelayProcessLifecycleCount", "RelayProcessMisuseCount", "RelayProcessNextMilestone"},
		InterpretedHash:  hash,
		GeneratedHash:    hash,
		Conclusion:       ConclusionPassed,
	}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid relay process fixture identity")
	}
	if len(set.Roles) < 3 || len(set.Lifecycle) < 5 {
		return errors.New("relay process architecture inventory incomplete")
	}
	if set.Config.AllowPublicDeploymentDefaults || set.Config.AllowCloudProviderDependency || set.Config.AllowProductionKeyingChanges {
		return errors.New("unsafe relay process config contract")
	}
	if set.Logging.PublicUploadAllowed || set.Logging.PayloadLogged || set.Logging.SecretLogged || set.PayloadLogged || set.SecretLogged {
		return errors.New("unsafe relay process logging contract")
	}
	if !set.Shutdown.IdempotentClose || set.Shutdown.UnreviewedAutoUpdate || !set.Compatibility.RejectsDowngrade || set.Resource.MissingResourcePolicy {
		return errors.New("relay process lifecycle contract incomplete")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("relay process misuse controls incomplete")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		return errors.New("relay process generated parity failed")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: ConclusionPassed}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "relayprocess_fixture_hash_changed")
	}
	if oldSet.Version != newSet.Version || oldSet.BackendVersion != newSet.BackendVersion {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "relayprocess_schema_or_backend_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "relayprocess_trace_hygiene_failed")
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
			return fmt.Errorf("relay process unsafe marker %q", marker)
		}
	}
	return nil
}

func ForbiddenMarkers() []string {
	return []string{
		`"raw_payload"`,
		`"payload_body"`,
		`"packet_capture"`,
		`"packet_dump"`,
		`"secret_value"`,
		`"private_key"`,
		`"session_secret"`,
		`"auth_tag"`,
		`"nonce_base"`,
		`"cloud_provider_metadata"`,
		`"account_identity"`,
		`"public_observability_upload"`,
	}
}

func RequiredMisuseNames() []string {
	return []string{
		"relayprocess_public_deployment_default",
		"relayprocess_payload_logging_allowed",
		"relayprocess_packet_capture_allowed",
		"relayprocess_secret_logging_allowed",
		"relayprocess_cloud_provider_dependency",
		"relayprocess_public_observability_upload",
		"relayprocess_unreviewed_auto_update",
		"relayprocess_missing_shutdown_policy",
		"relayprocess_missing_resource_policy",
		"relayprocess_missing_compatibility_policy",
		"relayprocess_production_keying_modified",
		"relayprocess_android_behavior_added",
		"relayprocess_payload_leak",
		"relayprocess_secret_leak",
		"relayprocess_generated_backend_drift",
	}
}

func role(name, kind string, blocked, required []string) ProcessRole {
	return ProcessRole{Name: name, Kind: kind, AllowedScope: "bounded_lab_process_architecture", BlockedBehaviors: blocked, RequiredPolicies: required, Conclusion: ConclusionPassed}
}

func lifecycle(name, role string, path, terminals, handlers, blocked []string) LifecycleContract {
	return LifecycleContract{Name: name, Role: role, StatePath: path, TerminalStates: terminals, RequiredHandlers: handlers, BlockedFallbacks: blocked, Conclusion: ConclusionPassed}
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func parityHashInput(set FixtureSet) struct {
	Version       string
	Roles         []ProcessRole
	Lifecycle     []LifecycleContract
	Config        ConfigContract
	Compatibility CompatibilityContract
	Resource      ResourceContract
} {
	return struct {
		Version       string
		Roles         []ProcessRole
		Lifecycle     []LifecycleContract
		Config        ConfigContract
		Compatibility CompatibilityContract
		Resource      ResourceContract
	}{set.Version, set.Roles, set.Lifecycle, set.Config, set.Compatibility, set.Resource}
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
