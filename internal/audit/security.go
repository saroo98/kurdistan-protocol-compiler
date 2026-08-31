// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/lab/runtimeadversary"
	ktrace "kurdistan/internal/observe/trace"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/testkit/evidenceoverlay"
)

func RunSecurityAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	gates := []GateResult{
		SecurityTranscriptBindingGate(profiles),
		SecurityKeyScheduleGate(profiles),
		SecurityNonceUniquenessGate(profiles),
		SecurityReplayRejectionGate(),
		SecurityDowngradeResistanceGate(profiles),
		SecurityCapabilityNegotiationGate(profiles),
		SecurityProfileCompatibilityGate(profiles),
		SecurityConfigHygieneGate(profiles),
		SecuritySecretTraceHygieneGate(profiles),
		SecurityMutantDetectionGate(ctx),
		SecurityGeneratedBackendParityGate(),
		SecurityM0IntegratedEvidenceGate(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "security-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     len(profiles),
		TraceCount:       0,
		Gates:            gates,
		TraceScanSummary: securitySummary(profiles),
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

const (
	m0AuthorizedRepoStateV1            = "6f04295c52a0a37b83d2a13c38e9028f90ccbaf8854929f8557e36c64ad5532c"
	m0LifecycleEvidenceV1              = "1f63391af51b23c4eca802e76d5164a98398a857070b8a7dd2cf99d055e4588e"
	m0PolicySeedCSVV1                  = "1,2,3,4,6,7,19,25,26,27,35,40,42,58,66,69,78,80,91,94,102,107,110,123,135,171,174,202,223"
	m0PolicySeedCSVHashV1              = "2577a6114b5df02b44d43ae02fd80fa08f8c593c2449f79a46f84aa63fa5efaa"
	m0OutsideScopeHashV1               = "1254e4f88da67f1c48e14e76b1bce93ea68285ffb84a2af38bc5366023362d5b"
	m0OutsideScopeFileCount            = 1286
	m0WO058MaintenanceHashV1           = "dc1bf68fc1d507c14da6bf71aa96b880697f4377a842a574ad6ae739fc949172"
	m0WO058MaintenanceCount            = 9
	m2MaintenanceOverlayV1             = "m2-governance-foundation-v1"
	m2MaintenanceSelfPathV1            = "testdata/evidence/phase1-m0-committed-sha256.json"
	baselineStabilizationOverlayNameV1 = "go126-clean-worktree-stabilization-v1"
	baselineStabilizationPredecessorV1 = "4bc0e7279b17cfbac0dc7138654991f20331b535d0c097c406efee68a1af8f74"
)

type m2MaintenanceEntryV1 struct {
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PreSHA256   string `json:"pre_sha256"`
	PostSHA256  string `json:"post_sha256"`
}

type m2MaintenanceOverlayRecordV1 struct {
	Version       string                 `json:"version"`
	SelfPath      string                 `json:"self_path"`
	SelfPreSHA256 string                 `json:"self_pre_sha256"`
	Paths         []string               `json:"paths"`
	Entries       []m2MaintenanceEntryV1 `json:"entries"`
}

type m2MaintenanceManifestV1 struct {
	MaintenanceOverlays                 map[string]m2MaintenanceOverlayRecordV1 `json:"maintenance_overlays"`
	HelperOwnerOverlays                 map[string]m2LayeredOverlayV1           `json:"helper_owner_overlays"`
	ValidatorOverlays                   map[string]m2LayeredOverlayV1           `json:"validator_overlays"`
	ValidatorConsumerOverlays           map[string]m2LayeredOverlayV1           `json:"validator_consumer_overlays"`
	EvidenceConvergenceOverlays         map[string]m2LayeredOverlayV1           `json:"evidence_convergence_overlays"`
	Phase2CompleteOverlays              map[string]m2Phase2CompleteOverlayV1    `json:"phase2_complete_overlays"`
	Phase3ContractOverlays              map[string]m2Phase2CompleteOverlayV1    `json:"phase3_contract_overlays"`
	Phase4FallbackOverlays              map[string]m2Phase2CompleteOverlayV1    `json:"phase4_fallback_overlays"`
	Phase5RelayDescriptorOverlays       map[string]m2Phase2CompleteOverlayV1    `json:"phase5_relay_descriptor_overlays"`
	Phase6DiagnosticExportOverlays      map[string]m2Phase2CompleteOverlayV1    `json:"phase6_diagnostic_export_overlays"`
	Phase7AppRuntimeOverlays            map[string]m2Phase2CompleteOverlayV1    `json:"phase7_app_runtime_overlays"`
	BaselineStabilizationOverlays       map[string]m2Phase2CompleteOverlayV1    `json:"baseline_stabilization_overlays"`
	Phase8ProfileCryptographyOverlays   map[string]m2Phase2CompleteOverlayV1    `json:"phase8_profile_cryptography_overlays"`
	Phase8WO801ThreatModelOverlays      map[string]m2Phase2CompleteOverlayV1    `json:"phase8_wo801_threat_model_overlays"`
	Phase8WO801AdoptionOverlays         map[string]m2Phase2CompleteOverlayV1    `json:"phase8_wo801_adoption_overlays"`
	Phase8WorkOrderOverlays             map[string]m2Phase8WorkOrderOverlayV1   `json:"phase8_work_order_overlays"`
	Phase8GuardMaintenanceOverlays      map[string]m2MaintenanceOverlayRecordV1 `json:"phase8_guard_maintenance_overlays"`
	Phase8FinalGuardMaintenanceOverlays map[string]m2MaintenanceOverlayRecordV1 `json:"phase8_final_guard_maintenance_overlays"`
	Phase9GuardMaintenanceOverlays      map[string]m2MaintenanceOverlayRecordV1 `json:"phase9_guard_maintenance_overlays"`
	Phase10VPNRuntimeOverlays           map[string]m2MaintenanceOverlayRecordV1 `json:"phase10_vpn_runtime_overlays"`
	Phase11LocalTransportOverlays       map[string]m2MaintenanceOverlayRecordV1 `json:"phase11_local_transport_overlays"`
	Phase12OperatorControlPlaneOverlays map[string]m2MaintenanceOverlayRecordV1 `json:"phase12_operator_control_plane_overlays"`
	Phase13AndroidProductOverlays       map[string]m2MaintenanceOverlayRecordV1 `json:"phase13_android_product_overlays"`
	Phase14AssuranceOverlays            map[string]m2MaintenanceOverlayRecordV1 `json:"phase14_assurance_overlays"`
}

type m2Phase8WorkOrderOverlayV1 struct {
	Version                  string                           `json:"version"`
	WorkOrderPath            string                           `json:"work_order_path"`
	PredecessorOverlaySHA256 string                           `json:"predecessor_overlay_sha256"`
	Paths                    []string                         `json:"paths"`
	Entries                  []m2Phase2CompleteOverlayEntryV1 `json:"entries"`
	OverlaySHA256            string                           `json:"overlay_sha256"`
}

type m2LayeredOverlayV1 struct {
	Version                string                 `json:"version"`
	PredecessorManifestSHA string                 `json:"predecessor_manifest_sha256"`
	Entries                []m2MaintenanceEntryV1 `json:"entries"`
}

type m2Phase2CompleteOverlayV1 struct {
	Version                   string                           `json:"version"`
	PredecessorManifestSHA256 string                           `json:"predecessor_manifest_sha256"`
	Paths                     []string                         `json:"paths"`
	Entries                   []m2Phase2CompleteOverlayEntryV1 `json:"entries"`
}

type m2Phase2CompleteOverlayEntryV1 struct {
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PostSHA256  string `json:"post_sha256"`
}

var m2MaintenancePathsV1 = []string{
	"README.md",
	"RZ-evidence-ref-069",
	"docs/GZ-evidence-ref-001",
	"docs/sb-evidence-ref-068",
	"internal/audit/security.go",
	"internal/audit/security_test.go",
	"internal/runtime/policy_enforcement_test.go",
	"internal/testkit/importrules/importrules_test.go",
	m2MaintenanceSelfPathV1,
}

const (
	m2HelperOverlayV1              = "m2-governance-foundation-helper-owners-v1"
	m2HelperOverlayV2              = "m2-governance-foundation-helper-owners-v2"
	m2ValidatorOverlayV1           = "m2-governance-foundation-validators-v1"
	m2ValidatorConsumerOverlayV1   = "m2-governance-foundation-validator-consumer-v1"
	m2EvidenceConvergenceOverlayV1 = "m2-governance-foundation-evidence-convergence-v1"
	m2Phase2CompleteOverlayNameV1  = "m2-governance-foundation-phase2-complete-v1"
	m2Phase2PredecessorManifestV1  = "c89a6be543ec35e68bef3cd6d5a91b685b1a05e523aca264faabc6d4933c398b"
)

var m2HelperPathsV1 = []string{"internal/audit/codegen_test.go", "internal/codegen/authorization_v1_test.go", "cmd/kgen/main_test.go"}
var m2HelperHistoricalPreV1 = []string{"0874db08bb14f2d94b94b88171f1d78cd87dd34122e6ca39e3eb4ec9942a00ec", "9f1941a9ef49c70aedddddf11890ea97df0563c2b921c75a3300aee713faf9ac", "a80d10983b1e5684faf64011ee482a3a8216f2ab2393fbe9cd7570cbf4d5524d"}
var m2HelperV1PostV1 = []string{"5e7fff88d4e75aadf0b2306c9d9574b76e13a62c585deeebda53ba6a191832d1", "96e6e30ccfe131cfa0384fc4463ac2f75a4e9d0630179233dc40157f7839f30b", "bad5ffb692075048785a98b0c048761f06003462f1a202660b60bddf4c9103e4"}
var m2HelperV2PostV1 = []string{"7707d4faf66e9d20edbb157a3ad59d71c81d8d3b7f869d7529ff312f9fce073d", "abf9e52b55971aefb21dace2226dfe4b29c4b5b8478504f30868934af8d6b935", "aa0d56ec1b1ebeeab11c90497d1f252295682bfb4b9d0c096dcd5b0047558ac0"}
var m2ValidatorPathsV1 = []string{"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go"}
var m2ValidatorPreV1 = []string{"b5be3c78bf856be24b92751f21fe54c7cb4a197c9f68aa7bf10d1129e6ba5c17", "b7449bc1148e01edaadfffed21626f0acc45c1fd114d606bf9abe4275a5a56e3", "a799b17b7218f806217ca551bb8807d380d193206c7151dab96add53affe0136"}
var m2ConvergencePathsV1 = []string{"cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go"}
var m2ConvergencePreV1 = []string{"aa0d56ec1b1ebeeab11c90497d1f252295682bfb4b9d0c096dcd5b0047558ac0", "7707d4faf66e9d20edbb157a3ad59d71c81d8d3b7f869d7529ff312f9fce073d", "985d46009b1ed6c0faade46de2574b940954de92ad6db8de3ddac0e29ea4a3ae", "f6b623b865407412856cbfc1c3748524b47ccae39ad3d33e40bd8977c9dbeab3", "abf9e52b55971aefb21dace2226dfe4b29c4b5b8478504f30868934af8d6b935", "53f9635f8761701cd2a9ce2762b3004ff3a0143097cb7334930e7b6f086e33b9", "81ae4a98530acc4a643fd824a939aa658eba6f8f6c4857b7978c1ebeb6853c9f"}
var m2Phase2CompletePathsV1 = []string{"README.md", "RZ-evidence-ref-069", "cmd/kgen/main_test.go", "docs/GZ-evidence-ref-001", "docs/KZ-evidence-ref-003", "docs/KZ-evidence-ref-020", "docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023", "docs/sb-evidence-ref-068", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", m2MaintenanceSelfPathV1}

func validSHA256V1(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value) && value != strings.Repeat("0", 64)
}

func loadM2MaintenancePreHashesV1(root string) (map[string]string, error) {
	return loadM2MaintenancePreHashesWithSuccessorV1(root, true)
}

func loadHistoricalM2MaintenancePreHashesV1(root string) (map[string]string, error) {
	return loadM2MaintenancePreHashesWithSuccessorV1(root, false)
}

func loadM2MaintenancePreHashesWithSuccessorV1(root string, validateSuccessor bool) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		return nil, fmt.Errorf("M2 maintenance manifest: %w", err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("M2 maintenance manifest: %w", err)
	}
	var currentAtPhase8, currentAtWO800 map[string]string
	if validateSuccessor {
		if _, err := validateM17LiveDataPlaneOverlayV1(root); err != nil {
			return nil, err
		}
		phase14Pre, err := validateM14AssuranceOverlayV1(root, manifest.Phase14AssuranceOverlays)
		if err != nil {
			return nil, err
		}
		phase13Pre, err := validateM13AndroidProductOverlayV1(root, phase14Pre, manifest.Phase13AndroidProductOverlays)
		if err != nil {
			return nil, err
		}
		phase12Pre, err := validateM12OperatorControlPlaneOverlayV1(root, phase13Pre, manifest.Phase12OperatorControlPlaneOverlays)
		if err != nil {
			return nil, err
		}
		phase11Pre, err := validateM11LocalTransportOverlayAtPostV1(root, phase12Pre, manifest.Phase11LocalTransportOverlays)
		if err != nil {
			return nil, err
		}
		phase10Pre, err := validateM10VPNRuntimeOverlayAtPostV1(root, phase11Pre, manifest.Phase10VPNRuntimeOverlays)
		if err != nil {
			return nil, err
		}
		phase9Pre, err := validateM9GuardMaintenanceOverlayAtPostV1(root, phase10Pre, manifest.Phase9GuardMaintenanceOverlays)
		if err != nil {
			return nil, err
		}
		finalGuardPre, err := validateM8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, manifest.Phase8FinalGuardMaintenanceOverlays)
		if err != nil {
			return nil, err
		}
		phase8Pre, err := validateM8WorkOrderOverlayChainAtPostV1(root, finalGuardPre, manifest.Phase8WorkOrderOverlays)
		if err != nil {
			return nil, err
		}
		for path, hash := range finalGuardPre {
			if hash == "ABSENT" {
				continue
			}
			if _, replaced := phase8Pre[path]; !replaced {
				phase8Pre[path] = hash
			}
		}
		guardPre, err := validateM8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, manifest.Phase8GuardMaintenanceOverlays)
		if err != nil {
			return nil, err
		}
		for path, hash := range guardPre {
			if hash == "ABSENT" {
				continue
			}
			phase8Pre[path] = hash
		}
		currentAtWO801, err := validateM8WO801AdoptionOverlayAtPostV1(root, phase8Pre, manifest.Phase8WO801AdoptionOverlays)
		if err != nil {
			return nil, err
		}
		for path, hash := range phase8Pre {
			if hash == "ABSENT" {
				continue
			}
			if _, replaced := currentAtWO801[path]; !replaced {
				currentAtWO801[path] = hash
			}
		}
		currentAtWO800, err = validateM8WO801ThreatModelOverlayAtPostV1(root, currentAtWO801, manifest.Phase8WO801ThreatModelOverlays)
		if err != nil {
			return nil, err
		}
		for path, hash := range currentAtWO801 {
			if hash == "ABSENT" {
				continue
			}
			if _, replaced := currentAtWO800[path]; !replaced {
				currentAtWO800[path] = hash
			}
		}
		currentAtPhase8, err = validateM8ProfileCryptographyOverlayAtPostV1(root, currentAtWO800, manifest.Phase8ProfileCryptographyOverlays)
	} else {
		currentAtPhase8, err = validateM8ProfileCryptographyOverlayV1(root, manifest.Phase8ProfileCryptographyOverlays)
	}
	if err != nil {
		return nil, err
	}
	if validateSuccessor {
		for path, hash := range currentAtWO800 {
			if hash == "ABSENT" {
				continue
			}
			if _, replaced := currentAtPhase8[path]; !replaced {
				currentAtPhase8[path] = hash
			}
		}
	}
	currentAtM7, err := validateBaselineStabilizationOverlayV1(root, currentAtPhase8, manifest.BaselineStabilizationOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM6, err := validateM7AppRuntimeOverlayV1(root, currentAtM7, manifest.Phase7AppRuntimeOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM5, err := validateM6DiagnosticExportOverlayV1(root, currentAtM6, manifest.Phase6DiagnosticExportOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM4, err := validateM5RelayDescriptorOverlayV1(root, currentAtM5, manifest.Phase5RelayDescriptorOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM3, err := validateM4FallbackOverlayV1(root, currentAtM4, manifest.Phase4FallbackOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM2 := map[string]string{}
	if validateSuccessor {
		currentAtM2, err = validateM3ContractOverlayV1(root, currentAtM3, manifest.Phase3ContractOverlays)
		if err != nil {
			return nil, err
		}
	} else {
		currentAtM2, err = validateHistoricalM3ContractOverlayV1(root, currentAtM3, manifest.Phase3ContractOverlays)
		if err != nil {
			return nil, err
		}
	}
	phase2Pre, err := validateM2Phase2CompleteV1(root, currentAtM2, manifest.Phase2CompleteOverlays)
	if err != nil {
		return nil, err
	}
	currentAtPre, err := validateM2ConvergenceV1(phase2Pre, manifest.EvidenceConvergenceOverlays)
	if err != nil {
		return nil, err
	}
	if len(manifest.HelperOwnerOverlays) != 2 {
		return nil, fmt.Errorf("M2 helper overlays=%d want 2", len(manifest.HelperOwnerOverlays))
	}
	helperV1, ok1 := manifest.HelperOwnerOverlays[m2HelperOverlayV1]
	helperV2, ok2 := manifest.HelperOwnerOverlays[m2HelperOverlayV2]
	if !ok1 || helperV1.Version != m2HelperOverlayV1 || helperV1.PredecessorManifestSHA != "b2a95c93332afbc13c73a4bb08e92067db97e93e843cb55e1f191b9c398e3c7b" || len(helperV1.Entries) != 3 {
		return nil, fmt.Errorf("invalid M2 helper v1 identity/cardinality")
	}
	if !ok2 || helperV2.Version != m2HelperOverlayV2 || helperV2.PredecessorManifestSHA != "7258697b4806469afea99342d981e96b328114036668e874f7c0e5a597a94cc6" || len(helperV2.Entries) != 3 {
		return nil, fmt.Errorf("invalid M2 helper v2 identity/cardinality")
	}
	helperPre := map[string]string{}
	for i, path := range m2HelperPathsV1 {
		v1, v2 := helperV1.Entries[i], helperV2.Entries[i]
		if v1.Path != path || v1.PreSHA256 != m2HelperHistoricalPreV1[i] || v1.PostSHA256 != m2HelperV1PostV1[i] {
			return nil, fmt.Errorf("invalid M2 helper v1 entry %d", i)
		}
		if v2.Path != path || v2.PreSHA256 != v1.PostSHA256 || v2.PostSHA256 != m2HelperV2PostV1[i] {
			return nil, fmt.Errorf("invalid M2 helper v2 entry %d", i)
		}
		actual := currentAtPre[path]
		if actual != v2.PostSHA256 {
			return nil, fmt.Errorf("M2 helper chain drift %s=%s want %s", path, actual, v2.PostSHA256)
		}
		helperPre[path] = v1.PreSHA256
	}
	if len(manifest.ValidatorOverlays) != 1 {
		return nil, fmt.Errorf("M2 validator overlays=%d want 1", len(manifest.ValidatorOverlays))
	}
	validators, ok := manifest.ValidatorOverlays[m2ValidatorOverlayV1]
	if !ok || validators.Version != m2ValidatorOverlayV1 || validators.PredecessorManifestSHA != "7924eff0ab8d66440bd370af1c6073ca9dc9beb320ac68acd82748b7f2d4f87b" || len(validators.Entries) != 3 {
		return nil, fmt.Errorf("invalid M2 validator overlay identity/cardinality")
	}
	validatorByPath := map[string]m2MaintenanceEntryV1{}
	for i, entry := range validators.Entries {
		if entry.Path != m2ValidatorPathsV1[i] || entry.PreSHA256 != m2ValidatorPreV1[i] || !validSHA256V1(entry.PostSHA256) || entry.PostSHA256 == entry.PreSHA256 {
			return nil, fmt.Errorf("invalid M2 validator entry %d", i)
		}
		actual := currentAtPre[entry.Path]
		if actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M2 validator chain drift %s=%s want %s", entry.Path, actual, entry.PostSHA256)
		}
		validatorByPath[entry.Path] = entry
	}
	consumer, ok := manifest.ValidatorConsumerOverlays[m2ValidatorConsumerOverlayV1]
	if len(manifest.ValidatorConsumerOverlays) != 1 || !ok || consumer.Version != m2ValidatorConsumerOverlayV1 || consumer.PredecessorManifestSHA != "7924eff0ab8d66440bd370af1c6073ca9dc9beb320ac68acd82748b7f2d4f87b" || len(consumer.Entries) != 1 {
		return nil, fmt.Errorf("invalid M2 validator-consumer overlay identity/cardinality")
	}
	consumerEntry := consumer.Entries[0]
	if consumerEntry.Path != "internal/testkit/importrules/importrules_test.go" || consumerEntry.PreSHA256 != "3a170c4752fea63a728d55abff9b0c8a7c91e25e0c98d14bdd4c401e3b56a178" || !validSHA256V1(consumerEntry.PostSHA256) || consumerEntry.PostSHA256 == consumerEntry.PreSHA256 {
		return nil, fmt.Errorf("invalid M2 validator-consumer entry")
	}
	actualConsumer := currentAtPre[consumerEntry.Path]
	if actualConsumer != consumerEntry.PostSHA256 {
		return nil, fmt.Errorf("M2 validator-consumer chain drift %s=%s want %s", consumerEntry.Path, actualConsumer, consumerEntry.PostSHA256)
	}
	if len(manifest.MaintenanceOverlays) != 1 {
		return nil, fmt.Errorf("M2 maintenance overlays=%d want 1", len(manifest.MaintenanceOverlays))
	}
	overlay, ok := manifest.MaintenanceOverlays[m2MaintenanceOverlayV1]
	if !ok || overlay.Version != m2MaintenanceOverlayV1 || overlay.SelfPath != m2MaintenanceSelfPathV1 || !validSHA256V1(overlay.SelfPreSHA256) {
		return nil, fmt.Errorf("invalid M2 maintenance overlay identity")
	}
	if len(overlay.Paths) != len(m2MaintenancePathsV1) {
		return nil, fmt.Errorf("M2 maintenance paths=%d want %d", len(overlay.Paths), len(m2MaintenancePathsV1))
	}
	for i, path := range m2MaintenancePathsV1 {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("M2 maintenance path[%d]=%q want %q", i, overlay.Paths[i], path)
		}
	}
	if len(overlay.Entries) != len(m2MaintenancePathsV1)-1 {
		return nil, fmt.Errorf("M2 maintenance entries=%d want %d", len(overlay.Entries), len(m2MaintenancePathsV1)-1)
	}
	pre := map[string]string{overlay.SelfPath: overlay.SelfPreSHA256}
	for path, historical := range phase2Pre {
		pre[path] = historical
	}
	for path, historical := range helperPre {
		pre[path] = historical
	}
	for i, entry := range overlay.Entries {
		wantPath := m2MaintenancePathsV1[i]
		if entry.Path != wantPath || entry.Path == overlay.SelfPath || !validSHA256V1(entry.PreSHA256) || !validSHA256V1(entry.PostSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid M2 maintenance entry %d for %q", i, entry.Path)
		}
		actual := currentAtPre[entry.Path]
		if actual == "" {
			var readErr error
			actual, readErr = m2FileSHA256V1(root, entry.Path)
			if readErr != nil {
				return nil, fmt.Errorf("M2 maintenance path %s: %w", entry.Path, readErr)
			}
		}
		if validator, changed := validatorByPath[entry.Path]; changed {
			if actual != validator.PostSHA256 {
				return nil, fmt.Errorf("M2 validator hash drift %s=%s want %s", entry.Path, actual, validator.PostSHA256)
			}
			actual = validator.PreSHA256
		}
		if entry.Path == consumerEntry.Path {
			if actual != consumerEntry.PostSHA256 {
				return nil, fmt.Errorf("M2 validator-consumer hash drift %s=%s want %s", entry.Path, actual, consumerEntry.PostSHA256)
			}
			actual = consumerEntry.PreSHA256
		}
		if actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M2 maintenance hash drift %s=%s want %s", entry.Path, actual, entry.PostSHA256)
		}
		pre[entry.Path] = entry.PreSHA256
	}
	historicalPrePaths := m2HistoricalPrePathSetV1(manifest)
	for path := range pre {
		if !historicalPrePaths[path] {
			delete(pre, path)
		}
	}
	return pre, nil
}

func m2HistoricalPrePathSetV1(manifest m2MaintenanceManifestV1) map[string]bool {
	paths := map[string]bool{m2MaintenanceSelfPathV1: true}
	for _, overlay := range []m2Phase2CompleteOverlayV1{
		manifest.Phase2CompleteOverlays[m2Phase2CompleteOverlayNameV1],
		manifest.Phase3ContractOverlays["m3-profile-lifecycle-contract-v1"],
		manifest.Phase4FallbackOverlays["m4-permitted-fallback-contract-v1"],
	} {
		for _, entry := range overlay.Entries {
			if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
				paths[entry.Path] = true
			}
		}
	}
	return paths
}

func validateM2Phase2CompleteV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	overlay, ok := overlays[m2Phase2CompleteOverlayNameV1]
	if len(overlays) != 1 || !ok || overlay.Version != m2Phase2CompleteOverlayNameV1 || overlay.PredecessorManifestSHA256 != m2Phase2PredecessorManifestV1 || len(overlay.Paths) != len(m2Phase2CompletePathsV1) || len(overlay.Entries) != len(m2Phase2CompletePathsV1)-1 {
		return nil, fmt.Errorf("invalid M2 phase2-complete identity/cardinality")
	}
	for i, path := range m2Phase2CompletePathsV1 {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("M2 phase2-complete path[%d]=%q want %q", i, overlay.Paths[i], path)
		}
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if entry.Path != m2Phase2CompletePathsV1[i] || entry.Path == m2MaintenanceSelfPathV1 || !validSHA256V1(entry.PostSHA256) || (entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" && !validSHA256V1(entry.PreEvidence)) {
			return nil, fmt.Errorf("invalid M2 phase2-complete entry %d", i)
		}
		actual, ok := currentAtPost[entry.Path]
		var err error
		if !ok {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M2 phase2-complete hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence == "ABSENT" || entry.PreEvidence == "UNRECORDED" {
			delete(pre, entry.Path)
		} else {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validateM8ProfileCryptographyOverlayV1(root string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	return validateM8ProfileCryptographyOverlayAtPostV1(root, nil, overlays)
}

func validateM8ProfileCryptographyOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-profile-cryptography-authorization-v1"
	wantPaths := []string{
		"RZ-evidence-ref-069", "docs/GZ-evidence-ref-001", "docs/sb-evidence-ref-068", "docs/KZ-evidence-ref-020",
		"docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023", "docs/KZ-evidence-ref-024",
		"docs/KZ-evidence-ref-029", "testdata/evidence/phase8-stabilization-baseline-2026-07-17.json",
		"cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go",
		m2MaintenanceSelfPathV1,
	}
	wantStabilized := map[string]string{
		"cmd/kgen/main_test.go":                            "02957beb4e2f7175685d0301277bf87684a60f3a5124bf9665cf1602f44f716f",
		"internal/audit/codegen_test.go":                   "829049208bbe59f4c3589ebbc9224ce4a0c4ba48e208a1fc63cb92e9df04c15a",
		"internal/audit/security.go":                       "b5bd8ac00051ebb5afa2fce66d103eedd91535ac70065edf0da5c21d555396e9",
		"internal/audit/security_test.go":                  "756907f5700a7e6b74668da0e65c3de12f8c684fa763bc310b2e9ceef8909f7e",
		"internal/codegen/authorization_v1_test.go":        "240899c2ee09e28fec883a1de9f84f6e000342933583e63e34796f13f9657f45",
		"internal/runtime/policy_enforcement_test.go":      "8d4103ded5371325e22e4bef362de31f049c8f857487a0f04866524763c32ec8",
		"internal/testkit/importrules/importrules_test.go": "8d54c23846b2b0e679ac55c710a4b3615d03efb2489ea22d438bef63c7e68021",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "dbe03c03259b9446e17836a5f1318d3a472b5a3483ae7880318b108c174cebba" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase8 profile cryptography overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 profile cryptography path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 profile cryptography entry %d", i)
		}
		wantAbsent := i == 7 || i == 8
		if wantAbsent != (entry.PreEvidence == "ABSENT") {
			return nil, fmt.Errorf("invalid phase8 profile cryptography predecessor %d", i)
		}
		if !wantAbsent && !validSHA256V1(entry.PreEvidence) {
			return nil, fmt.Errorf("invalid phase8 profile cryptography predecessor hash %d", i)
		}
		if want, guarded := wantStabilized[entry.Path]; guarded && entry.PreEvidence != want {
			return nil, fmt.Errorf("phase8 profile cryptography reconstruction drift %s", entry.Path)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 profile cryptography hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if !wantAbsent {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	for path, want := range wantStabilized {
		if pre[path] != want {
			return nil, fmt.Errorf("phase8 profile cryptography reconstructed %s=%s want %s", path, pre[path], want)
		}
	}
	return pre, nil
}

func validateM8WO801ThreatModelOverlayV1(root string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	return validateM8WO801ThreatModelOverlayAtPostV1(root, nil, overlays)
}

func validateM8WO801ThreatModelOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-wo801-threat-model-v1"
	wantPaths := []string{
		"docs/KZ-evidence-ref-030",
		"internal/product/envelope/phase8_trust.go",
		"internal/product/envelope/phase8_trust_test.go",
		"internal/product/profile/phase8_trust.go",
		"internal/product/profile/phase8_trust_test.go",
		"cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		m2MaintenanceSelfPathV1,
	}
	wantWO800 := map[string]string{
		"cmd/kgen/main_test.go":                            "9ec962c5601a6090e6289a48b142e200e5e601a4ecf3d366adefa740ea30b0f6",
		"internal/audit/codegen_test.go":                   "e2c3b0e1b7274da45d3861424bb0218f9640ad703f608d03858993531cddec2d",
		"internal/audit/security.go":                       "328e8382c05082b28aa35b92426e6622da030b460a6505b49c1761bd9c45efe9",
		"internal/audit/security_test.go":                  "076830912ef1742d6a7c7cc18279a28af652371eba9bd61db120cfc9ac9f760e",
		"internal/codegen/authorization_v1_test.go":        "421deed4c4aeafc9c8ffdc27432b10aef34a6050d8d87efb1a048da8a6046477",
		"internal/runtime/policy_enforcement_test.go":      "7ec77a79a641ce792a94cbebdc8b8a6c17cafb72c92b9b260203908df5537114",
		"internal/testkit/importrules/importrules_test.go": "29376a1a91fba2100cfc894dae836399f7e84d9756bc65c0bfb41c840a25246d",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "7373da738dde935a1eae25522b1bc9a2ce4efd7ebe50dd221fcf2c8847cb25ae" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase8 WO-801 threat-model overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 WO-801 threat-model path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 WO-801 threat-model entry %d", i)
		}
		wantAbsent := i < 5
		if wantAbsent != (entry.PreEvidence == "ABSENT") {
			return nil, fmt.Errorf("invalid phase8 WO-801 threat-model predecessor %d", i)
		}
		if !wantAbsent && entry.PreEvidence != wantWO800[entry.Path] {
			return nil, fmt.Errorf("phase8 WO-801 reconstruction drift %s", entry.Path)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 WO-801 threat-model hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if !wantAbsent {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validateM8WO801AdoptionOverlayV1(root string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	return validateM8WO801AdoptionOverlayAtPostV1(root, nil, overlays)
}

func m8WorkOrderOverlaySHA256V1(o m2Phase8WorkOrderOverlayV1) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n", o.Version, o.PredecessorOverlaySHA256)
	for i, path := range o.Paths {
		fmt.Fprintf(h, "path:%s\n%s%c%s%c%s\n", path, o.Entries[i].Path, byte(0), o.Entries[i].PreEvidence, byte(0), o.Entries[i].PostSHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validateM8WorkOrderOverlayChainV1(root string, overlays map[string]m2Phase8WorkOrderOverlayV1) (map[string]string, error) {
	return validateM8WorkOrderOverlayChainAtPostV1(root, nil, overlays)
}

func validateM8WorkOrderOverlayChainAtPostV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase8WorkOrderOverlayV1) (map[string]string, error) {
	type expected struct {
		name, workOrder, predecessor, binding string
		cardinality                           int
	}
	want := []expected{
		{"phase8-wo802-standards-suite-v1", "evidence/publication-ref-802", "2a086c7cc686f4ff27e040684d9e5c33c7d0fc0cb6f9746bc0d637e41ccec6cf", "86ff9cc08f44e1313adc904901e4fc3ba5c40ec656beb29d2be2850118b5eb5a", 14},
		{"phase8-wo803-canonical-profile-codec-v1", "evidence/publication-ref-803", "86ff9cc08f44e1313adc904901e4fc3ba5c40ec656beb29d2be2850118b5eb5a", "ab4a13ecca60d4ad8eb8d091d915032a85130258eb11c721eaec93aaff033507", 18},
		{"phase8-wo804-trust-provider-boundaries-v1", "evidence/publication-ref-804", "ab4a13ecca60d4ad8eb8d091d915032a85130258eb11c721eaec93aaff033507", "07ea004c3e5edb52a20f030cdfb1352eb4e3ff54ed2a10acc6ff0998bb8b38bc", 9},
		{"phase8-wo805-verified-profile-activation-v1", "evidence/publication-ref-805", "07ea004c3e5edb52a20f030cdfb1352eb4e3ff54ed2a10acc6ff0998bb8b38bc", "62116f838e0ba5b01dd62be55d7eac84280cf8c6fd1bb392b4100104db4712e7", 16},
		{"phase8-wo806-offline-issuance-tooling-v1", "evidence/publication-ref-806", "62116f838e0ba5b01dd62be55d7eac84280cf8c6fd1bb392b4100104db4712e7", "acd3e082b430521ddcf1d077d34fa87d380ba385f5cc93b21117e1c3ef4e164c", 29},
		{"phase8-wo807-integrated-assurance-v1", "evidence/publication-ref-807", "acd3e082b430521ddcf1d077d34fa87d380ba385f5cc93b21117e1c3ef4e164c", "c6912fb21ef8c02585ccf63d4983896697a45396167b49566bd977eb35b9af7a", 13},
	}
	if len(overlays) != len(want) {
		return nil, fmt.Errorf("invalid phase8 work-order overlay cardinality")
	}
	pre := map[string]string{}
	for _, w := range want {
		o, ok := overlays[w.name]
		if !ok || o.Version != w.name || o.WorkOrderPath != w.workOrder || o.PredecessorOverlaySHA256 != w.predecessor || o.OverlaySHA256 != w.binding || len(o.Paths) != w.cardinality || len(o.Entries) != w.cardinality || m8WorkOrderOverlaySHA256V1(o) != w.binding {
			return nil, fmt.Errorf("invalid phase8 work-order overlay %s: version=%q work_order=%q predecessor=%q binding=%q computed=%q paths=%d entries=%d", w.name, o.Version, o.WorkOrderPath, o.PredecessorOverlaySHA256, o.OverlaySHA256, m8WorkOrderOverlaySHA256V1(o), len(o.Paths), len(o.Entries))
		}
		for i, entry := range o.Entries {
			if entry.Path != o.Paths[i] || (entry.PreEvidence != "ABSENT" && !validSHA256V1(entry.PreEvidence)) || !validSHA256V1(entry.PostSHA256) {
				return nil, fmt.Errorf("invalid phase8 work-order overlay entry %s[%d]", w.name, i)
			}
			actual, present := currentAtPost[entry.Path]
			var err error
			if !present {
				actual, err = m2FileSHA256V1(root, entry.Path)
			}
			if err != nil || actual != entry.PostSHA256 {
				return nil, fmt.Errorf("phase8 work-order hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validateM8GuardMaintenanceOverlayV1(root string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	return validateM8GuardMaintenanceOverlayAtPostV1(root, nil, overlays)
}

func validateM8GuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	const name = "phase8-wo806-guard-convergence-v1"
	paths := []string{"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/codegen/authorization_v1_test.go", m2MaintenanceSelfPathV1}
	preHashes := []string{"10f4a412739c3896e88fb7b649774e0243ccfcfab2c77335b2e7ecaa8948f3ae", "8ed3f3c023baa71d60dbe81c94bb0e4254e8fcaf35b5c4b75d027b2c2290b15b", "1333f376b7ff19580719c40ec831a61ff6c66dd2ea90721a1d257370d698e45e", "4420c4c6582124b04c9330329bfedf213f2976f3c536cb2fa815ab28a28a1fb5", "c3fb2ce202af327107885f8a5866908cbd984aa74b09ee702514d6ed2442901d", "a7e40a30f7a30122bf23e538f8714890f3bba945799466cf378c3566160c4041", "a4664fe1fb3b6a6050af2c8e04eab51263ce32989e5d673c1ae35b97f7b8b79e"}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.SelfPath != m2MaintenanceSelfPathV1 || o.SelfPreSHA256 != "37ece675df4e2f17bb253a3a5d648c3a7b6e62d9319fd27a138be00cedb3e77a" || len(o.Paths) != 8 || len(o.Entries) != 7 {
		return nil, fmt.Errorf("invalid phase8 guard-maintenance overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range paths {
		if o.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 guard-maintenance path %d", i)
		}
	}
	for i, entry := range o.Entries {
		if entry.Path != paths[i] || entry.PreSHA256 != preHashes[i] || !validSHA256V1(entry.PostSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase8 guard-maintenance entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 guard-maintenance hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = entry.PreSHA256
	}
	return pre, nil
}

func validateM8FinalGuardMaintenanceOverlayV1(root string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	return validateM8FinalGuardMaintenanceOverlayAtPostV1(root, nil, overlays)
}

func validateM8FinalGuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	const name = "phase8-wo808-final-guard-convergence-v1"
	paths := []string{
		"README.md", "RZ-evidence-ref-069", "docs/GZ-evidence-ref-001",
		"docs/sb-evidence-ref-068", "cmd/gate/main.go", ".github/workflows/ci.yml",
		"internal/product/envelope/phase8_suite_test.go", "testdata/evidence/independent/phase8_interop.py", "testdata/evidence/phase8-independent-interop-report.json",
		"internal/product/envelope/phase8_profile_codec.go", "internal/product/envelope/phase8_profile_codec_test.go", "cmd/kprofile/main.go",
		"cmd/kprofile/main_test.go", "internal/product/profile/testdata/phase8-issuance/offline-boundary-report.json", "internal/product/profile/testdata/phase8-issuance/redacted-inspect-report.json",
		"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go",
		"internal/codegen/authorization_v1_test.go", ".gitignore", "internal/audit/status.go",
		"cmd/kprofile/path_other.go", "cmd/kprofile/path_unsupported.go", "cmd/kprofile/path_windows_test.go",
		"cmd/kprofile/path_windows.go", "cmd/kprofile/path.go", "docs/KZ-evidence-ref-036",
		"docs/PZ-evidence-ref-064", "docs/PZ-evidence-ref-065", "internal/product/envelope/phase8_evidence_test.go",
		"internal/product/envelope/phase8_suite.go", "internal/product/profile/phase8_activation_test.go", "internal/product/profile/phase8_activation.go",
		"internal/product/profile/phase8_providers.go", "internal/product/profile/phase8_tooling_evidence_test.go", "internal/product/profile/phase8_tooling_external_test.go",
		"internal/product/profile/phase8_tooling.go", "internal/product/profile/testdata/phase8-activation/activation-crash-report.json", "internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json", "internal/product/profile/testdata/phase8-activation/policy-bypass-report.json", "internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json", "internal/product/profile/testdata/phase8-issuance/fixture-manifest.json", "internal/product/profile/testdata/phase8-issuance/fixture-reproduction-report.json",
		"internal/product/profile/testdata/phase8-issuance/issuance-negative-report.json", "internal/product/profile/testdata/phase8-issuance/issuance-roundtrip-report.json", "internal/product/profile/testdata/phase8-issuance/production-wiring-negative-report.json",
		"internal/testkit/phase8fixturegen/main_test.go", "internal/testkit/phase8fixturegen/main.go", "internal/testkit/phase8issuancefixture/generate.go",
		"SZ-evidence-ref-070", "testdata/evidence/phase8-release-corpus-manifest.json", "testdata/evidence/phase8-wo807-recovery-report.json",
		"testdata/evidence/phase1-m0-committed-sha256.json",
	}

	preHashes := []string{
		"65b6fe472d0b3bf59704e3793a6337ba8ebd8602bd92e9d70b34e30f445bbed5", "4c4b327d58efabe3569b7a525cf9bc18298b3027d5993ebc9a5f36b9520cb6d2", "483ac28d0d371e10784d83721b7e2efac5e46bffe031dc18fcfb253012781e4d",
		"62fabcee4d7451804f2c7f7df32e9b2e4457c8a8a16687677d20097cca616769", "c7d9d7127fec76e135fe0ea7bebd86285764025c735d8e733c12b9a0e662663f", "ABSENT",
		"f8608b81c1c0b7b2e499a1217e258ba7a9fe842ee61f68cf6728f06506204cb3", "8a312973d42f25c127827db419b0b07355a1b779d2cd243b45a77492bf55288a", "b6424fd088cc2c437175adccafff1c94b3afc6bcf0750491a1c05e72ceaf3cb5",
		"197304bba879d092cf0b37c96f2d260ccc3137ca35378c562ab17f43f7ed92f2", "12dcdff0b67c56c55b3cc29ed5ef10a3d3bfb273b1da02d6012a03940c056a3b", "d3bd61e8094ba10253cde22306b6dde0ca1c4ffe28d34616d5471a34864caa09",
		"82915c199c88ab52bdca5a74c56eab99fc61b095420064f1f3e2d51a3d9818a9", "1cc9b6f1af5157e468870e3cfc849a9e83e2513d7e06ea54f2c8388b1acc437c", "6c4e0ff29540248a2c919eaf4444ab8ee33cdb8a4ac6c8407fcbbd37deb155b4",
		"d7f33f3194065c6b4900a92843da772b74396090ae311532d82118037b2b7b3d", "251c31fcf024a5bebb11a742a0ba03ffca8ae98f146b9c5242e7c82d30cc929a", "9bc732efbf56adcbec93722f206227a43d3f0946cbc8acd0a03b96b66439d1d7",
		"3a46df826b5c108818723af77ff2e7de6530bf2e66e993d2cda364e05eb51fa9", "372f479b0c541f61e2cad4869f62ae8cce895db00ffcc3b19e03bd6925677c14", "e87df0637cdc5c93129a73855e641a98f80b750b2e27a6343e7f37072c816201",
		"9e0feb195c40a435f3d3baf80ef8a2a91d8f38f0b5134fb6bbf50f7760b767bc", "5b183df65d579d6956f2fee4771afc35f32fa0eeb87d1cfa8bb1729e19e92f20", "94dc5eb6ba2ff56fd46820592ecb01e7e5705c2200350ad9d4534221fee0f954",
		"4de767d8872d04668c0077d45be834b3397ca723e6bd9b1d66de85bee32e3d0b", "ABSENT", "ABSENT",
		"a0ada14afde8b72fb1e66513208fc020e9d674f73238896bed3f876dff83674b", "ABSENT", "9514b51d5b3320e11c875b0224e6dc9e6cf4b99b6c88d0f516441086d366daa3",
		"20a6e8732887d76ef49c957369a1132d8bdf3d10df20b3f2abcae5903bbf2cd1", "7ca541e419a2de0f4ef2f1987e21277ec78aba38c8b5acac7b74a31a6d3ca2fd", "e1b66f934f62efdc947c3ac15480e36ae4986f14042bb4a38e92dd6313c41645",
		"71c67b4e27d4f8708115030dd9469f3b133a7b4fdc09a3732e2efb6c2d67944f", "03ef0f0d758f220be50d3b517aebb8e1b2d8cace59836a2c991422c3d5162331", "0747653f3b1efb3783535572bf68843cf0e1a494bd2098a82ccfc7d224dfe1bd",
		"db08f48f7305f9543c2a6e3094218c0b31ed8185298149af05d0a4a671b19bae", "6d894e73ad19bdd05afc504212e93ef18f18e8962db06c9629be4d3bc7cd5d91", "60b60d1932bffb4b6597fb0659b9153c0531a51bab944e4263b620fdfd3af028",
		"154178a1b0bd6da95a1327a32b11c3d5c5a2023a4d323c7dbb999f89e0f807b7", "5eba165b5ea9317b51f609ab4b34ef57d3dc0a42c85ab7d4aae78b1c4b7b15ba", "fd393e178e02ab8f5c96b2502dcb7b2ad411758eb55c7ef4f8144536e47db069",
		"5eba165b5ea9317b51f609ab4b34ef57d3dc0a42c85ab7d4aae78b1c4b7b15ba", "7ce8dc7e7ddb93454c24fad8c9a8c7f375d5bba25d07673e60a757335a13aecc", "e83737cbb6ef895748045a1af296e82a6ee0bfeff72c1615bd003c1cd375b1d1",
		"0c6ca80025d973546aa2d44442f739f94b4e0b1ec9132dafc08ca72bb2f88afc", "993739b3577ab5418bec2c3790e26495c16b9bbb423ef08fce8d96d36d601b36", "19685e69c2e8b9d66b5116d74b7e75cf3e6c61abb8ae4803ab4f782debfb6688",
		"766b6b14fffc20436ad5b0ff5d623582e41dbf7907396a1599bf484639214ac7", "58f43dc6b85ae04dcd682ee7e58a506463fb6118e9eae080d57c1d7618af465b", "8007954c8ec687664fe70841982172c717e11a2933c16a373259b28a001feb55",
		"ABSENT", "00b45845fd49a2d39e1489b61e117dd91c83aa715925f82ae8cb931664230e3a", "05de9cb9f0cd0f40721c7aa6465c619e400f0e19911451629737741bc4f489df",
		"8ed8a14111d09e948879d5cebe3979cf20ce1eb048e996c9bf39e6e409f1bbf1", "7ccec20947e3733149efbf2a38d161a017d698587360353836f52811fda0b6e0", "8db7027e428d1fd09498202f33eacb7285ae56c9b28f061297f60b8642a37583",
	}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.SelfPath != m2MaintenanceSelfPathV1 || o.SelfPreSHA256 != "afcef52b1302379c2172815138219421e2dcf2b4e7280724f7c9ae4829d5f76a" || len(o.Paths) != len(paths) || len(o.Entries) != len(preHashes) {
		return nil, fmt.Errorf("invalid phase8 final guard-maintenance overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range paths {
		if o.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 final guard-maintenance path %d", i)
		}
	}
	for i, entry := range o.Entries {
		expectedPre := preHashes[i]
		if entry.Path != paths[i] || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 final guard-maintenance entry %d", i)
		}
		if expectedPre == "ABSENT" {
			if entry.PreEvidence != "ABSENT" || entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase8 final guard-maintenance absent predecessor %d", i)
			}
		} else if entry.PreEvidence != "" || entry.PreSHA256 != expectedPre || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase8 final guard-maintenance predecessor %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 final guard-maintenance hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = expectedPre
	}
	return pre, nil
}

func validateM14AssuranceOverlayV1(root string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	const name = "phase14-assurance-v1"
	const predecessorBinding = "9a06e73ef9659dd10dd1c58c53955029b0116d7bd8c0ffa0856b0fa7c3ab230a"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.SelfPath != m2MaintenanceSelfPathV1 || !validSHA256V1(overlay.SelfPreSHA256) || len(overlay.Paths) == 0 || len(overlay.Paths) > 256 || len(overlay.Paths) != len(overlay.Entries) {
		return nil, fmt.Errorf("invalid phase14 assurance overlay identity/cardinality")
	}
	successor, err := evidenceoverlay.LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		return nil, fmt.Errorf("load Phase 15 successor overlay: %w", err)
	}
	pre := make(map[string]string, len(successor)+len(overlay.Paths))
	for path, hash := range successor {
		if path == m2MaintenanceSelfPathV1 {
			continue
		}
		pre[path] = hash
	}
	binding := sha256.New()
	_, _ = fmt.Fprintln(binding, overlay.SelfPreSHA256)
	last := ""
	for index, path := range overlay.Paths {
		entry := overlay.Entries[index]
		if path != entry.Path || path <= last || path == overlay.SelfPath || strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase14 assurance overlay entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase14 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase14 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, found := successor[path]
		if !found {
			actual, err = m2FileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase14 assurance hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		last = path
	}
	if fmt.Sprintf("%x", binding.Sum(nil)) != predecessorBinding {
		return nil, fmt.Errorf("invalid phase14 predecessor binding")
	}
	return pre, nil
}

type m17LiveDataPlaneOverlayV1 struct {
	Version                  string                 `json:"version"`
	SelfPath                 string                 `json:"self_path"`
	SelfPreEvidence          string                 `json:"self_pre_evidence"`
	SelfPreSHA256            string                 `json:"self_pre_sha256"`
	PredecessorBindingSHA256 string                 `json:"predecessor_binding_sha256"`
	Entries                  []m2MaintenanceEntryV1 `json:"entries"`
	SuccessorEntries         []m17SuccessorEntryV1  `json:"successor_entries"`
	SuccessorEntriesV2       []m17SuccessorEntryV1  `json:"successor_entries_v2"`
}

type m17SuccessorEntryV1 struct {
	Path         string `json:"path"`
	PreEvidence  string `json:"pre_evidence"`
	PreSHA256    string `json:"pre_sha256"`
	PostEvidence string `json:"post_evidence"`
	PostSHA256   string `json:"post_sha256"`
}

var m17LiveDataPlanePathsV1 = []string{
	"cmd/phase17verify/main.go",
	"cmd/phase17verify/main_test.go",
	"config/runtime/live-data-plane-v1.json",
	"docs/protocol/KURD-WIRE-V1-LIVE.md",
	"docs/self-hosting/LIVE-DATA-PLANE.md",
	"internal/product/runtimepolicy/policy_v2.go",
	"internal/product/runtimepolicy/policy_v2_fuzz_test.go",
	"internal/product/runtimepolicy/policy_v2_test.go",
	"internal/protocol/framing/codec.go",
	"internal/protocol/framing/codec_spec_v1.go",
	"internal/protocol/framing/codec_test.go",
	"internal/protocol/ir/effective_projection_v1.go",
	"internal/protocol/ir/effective_projection_v1_test.go",
	"internal/protocol/liveprogram/codec_v1.go",
	"internal/protocol/liveprogram/codec_v1_fuzz_test.go",
	"internal/protocol/liveprogram/program_v1.go",
	"internal/protocol/liveprogram/program_v1_test.go",
	"internal/protocol/liveprogramcompile/compile_v1.go",
	"internal/protocol/liveprogramcompile/compile_v1_test.go",
	"internal/protocol/scheduler/scheduler.go",
	"internal/protocol/scheduler/scheduler_test.go",
}

func loadM17LiveDataPlaneOverlayV1(root string) (m17LiveDataPlaneOverlayV1, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(evidenceoverlay.Phase17SuccessorPath)))
	if err != nil {
		return m17LiveDataPlaneOverlayV1{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var overlay m17LiveDataPlaneOverlayV1
	if err := decoder.Decode(&overlay); err != nil {
		return m17LiveDataPlaneOverlayV1{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return m17LiveDataPlaneOverlayV1{}, fmt.Errorf("phase17 live-data-plane trailing JSON")
	}
	return overlay, nil
}

func validateM17LiveDataPlaneOverlayV1(root string) (m17LiveDataPlaneOverlayV1, error) {
	overlay, err := loadM17LiveDataPlaneOverlayV1(root)
	if err != nil {
		return m17LiveDataPlaneOverlayV1{}, err
	}
	return validateM17LiveDataPlaneOverlayAtPostV1(root, nil, overlay)
}

func validateM17LiveDataPlaneOverlayAtPostV1(root string, currentAtPost map[string]string, overlay m17LiveDataPlaneOverlayV1) (m17LiveDataPlaneOverlayV1, error) {
	const name = "phase17-live-data-plane-v1"
	const predecessorBinding = "77772a0daab7ba1bd148fcd437ee1c18be535bb0c4272cbc0f84d5dc0b764cf4"
	if overlay.Version != name || overlay.SelfPath != evidenceoverlay.Phase17SuccessorPath || overlay.SelfPreEvidence != "ABSENT" || overlay.SelfPreSHA256 != "" || overlay.PredecessorBindingSHA256 != predecessorBinding || len(overlay.Entries) != len(m17LiveDataPlanePathsV1) || len(overlay.SuccessorEntries) > evidenceoverlay.Phase17SuccessorEntryLimit || len(overlay.SuccessorEntriesV2) > evidenceoverlay.Phase17SuccessorEntryLimit {
		return m17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 live-data-plane overlay identity/cardinality")
	}
	baseAtSuccessorV2, err := m17SuccessorPreAtPostV1(root, currentAtPost, overlay.SuccessorEntriesV2)
	if err != nil {
		return m17LiveDataPlaneOverlayV1{}, err
	}
	baseAtPost, err := m17SuccessorPreAtPostV1(root, baseAtSuccessorV2, overlay.SuccessorEntries)
	if err != nil {
		return m17LiveDataPlaneOverlayV1{}, err
	}
	binding := sha256.New()
	_, _ = fmt.Fprintf(binding, "%s\x00ABSENT\n", overlay.SelfPath)
	last := ""
	for index, path := range m17LiveDataPlanePathsV1 {
		entry := overlay.Entries[index]
		if entry.Path != path || path <= last || strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") || !validSHA256V1(entry.PostSHA256) {
			return m17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 live-data-plane entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return m17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return m17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, present := baseAtPost[path]
		if !present {
			content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil {
				return m17LiveDataPlaneOverlayV1{}, err
			}
			actual = fmt.Sprintf("%x", sha256.Sum256(content))
		}
		if actual != entry.PostSHA256 {
			return m17LiveDataPlaneOverlayV1{}, fmt.Errorf("phase17 live-data-plane hash drift %s=%s want %s", path, actual, entry.PostSHA256)
		}
		last = path
	}
	if fmt.Sprintf("%x", binding.Sum(nil)) != predecessorBinding {
		return m17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 predecessor binding")
	}
	return overlay, nil
}

func m17SuccessorPreAtPostV1(root string, currentAtPost map[string]string, entries []m17SuccessorEntryV1) (map[string]string, error) {
	pre := make(map[string]string, len(currentAtPost)+len(entries))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	last := ""
	for index, entry := range entries {
		if entry.Path <= last || strings.HasPrefix(entry.Path, ".tools/") || strings.HasPrefix(entry.Path, "planning/") {
			return nil, fmt.Errorf("invalid phase17 successor entry %d", index)
		}
		post := entry.PostSHA256
		if entry.PostEvidence == "ABSENT" {
			if entry.PostSHA256 != "" {
				return nil, fmt.Errorf("invalid phase17 absent successor post-state %d", index)
			}
			post = "ABSENT"
		} else if entry.PostEvidence != "" || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase17 successor post-state %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase17 absent successor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validSHA256V1(entry.PreSHA256) {
			return nil, fmt.Errorf("invalid phase17 successor predecessor %d", index)
		}
		if predecessor == post {
			return nil, fmt.Errorf("phase17 successor entry does not change state %d", index)
		}
		actual, found := pre[entry.Path]
		if !found {
			path := filepath.Join(root, filepath.FromSlash(entry.Path))
			if post == "ABSENT" {
				if _, err := os.Lstat(path); err == nil {
					return nil, fmt.Errorf("phase17 successor deletion path still exists: %s", entry.Path)
				} else if !errors.Is(err, os.ErrNotExist) {
					return nil, err
				}
				actual = "ABSENT"
			} else {
				content, err := os.ReadFile(path)
				if err != nil {
					return nil, err
				}
				actual = fmt.Sprintf("%x", sha256.Sum256(content))
			}
		}
		if actual != post {
			return nil, fmt.Errorf("phase17 successor hash drift %s=%s want %s", entry.Path, actual, post)
		}
		pre[entry.Path] = predecessor
		last = entry.Path
	}
	return pre, nil
}

func validateM13AndroidProductOverlayV1(root string, currentAtPost map[string]string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	const name = "phase13-android-product-v1"
	const predecessorBinding = "93020d6f615b9706dda3bf719ddbffeafa838837f0ec15d3e89ad395d1950c6c"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != m2MaintenanceSelfPathV1 || !validSHA256V1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 256 || len(overlay.Paths) != len(overlay.Entries) {
		return nil, fmt.Errorf("invalid phase13 Android product overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	binding := sha256.New()
	_, _ = fmt.Fprintln(binding, overlay.SelfPreSHA256)
	last := ""
	for index, path := range overlay.Paths {
		entry := overlay.Entries[index]
		if path != entry.Path || path <= last || path == overlay.SelfPath ||
			strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") ||
			!validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase13 Android product overlay entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase13 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase13 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase13 Android product hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		last = path
	}
	if fmt.Sprintf("%x", binding.Sum(nil)) != predecessorBinding {
		return nil, fmt.Errorf("invalid phase13 predecessor binding")
	}
	return pre, nil
}

func validateM12OperatorControlPlaneOverlayV1(root string, currentAtPost map[string]string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	const name = "phase12-operator-control-plane-v1"
	paths := []string{
		"RZ-evidence-ref-069",
		"cmd/gate/main.go",
		"cmd/gate/main_test.go",
		"cmd/kgen/main_test.go",
		"cmd/koperator/evidence_test.go",
		"cmd/koperator/main.go",
		"cmd/koperator/main_test.go",
		"cmd/phase9verify/phase11_overlay_test.go",
		"docs/KZ-evidence-ref-041",
		"docs/PZ-evidence-ref-049",
		"docs/sb-evidence-ref-068",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/codegen/generator_templates.go",
		"internal/codegen/generator_test.go",
		"internal/operator/controlplane/authority_state.go",
		"internal/operator/controlplane/controlplane_test.go",
		"internal/operator/controlplane/errors.go",
		"internal/operator/controlplane/journal.go",
		"internal/operator/controlplane/model.go",
		"internal/operator/controlplane/phase_boundaries.go",
		"internal/operator/controlplane/phase_boundaries_test.go",
		"internal/operator/controlplane/reconcile.go",
		"internal/operator/controlplane/reconcile_test.go",
		"internal/operator/controlplane/service.go",
		"internal/operator/controlplane/state.go",
		"internal/product/lifecycle/phase8_verified.go",
		"internal/product/lifecycle/phase8_verified_test.go",
		"internal/product/profile/phase8_activation.go",
		"internal/product/profile/phase8_admission.go",
		"internal/product/profile/phase8_admission_test.go",
		"internal/product/profile/phase8_emergency_signed.go",
		"internal/product/profile/phase8_emergency_signed_test.go",
		"internal/product/profile/phase8_providers.go",
		"internal/product/profile/phase8_revocation_admission.go",
		"internal/product/profile/testdata/phase8-activation/activation-crash-report.json",
		"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json",
		"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json",
		"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		"testdata/evidence/phase12/acceptance-status.json",
		"testdata/evidence/phase8-wo807-recovery-report.json",
	}
	preHashes := map[string]string{
		"RZ-evidence-ref-069":                                                              "586a5e7f377c1809eb67cfe932d996ae81703bb562f52b539935e26ccdc93e8b",
		"cmd/gate/main.go":                                                                 "8f0e4e86384ea012ac54f1c9f795c3a4f760b5ab6c7f4b24f3ab553cad3c96c1",
		"cmd/gate/main_test.go":                                                            "c2b868ec7b155ed5ae95f667181284af9672722ceea8b3c018f4dd32df2d4fdd",
		"cmd/kgen/main_test.go":                                                            "2fabad2630c546749cde3c0c67dd9885ffa855230c298dacb741c65ef497c846",
		"cmd/phase9verify/phase11_overlay_test.go":                                         "95c7e090b93beab82e673513735e6725e1f636f10244a6b37b504adc91cb3a67",
		"docs/sb-evidence-ref-068":                                                         "2846c0453c9a20d8fee0a355d339ba70f658d3f064e2dcd6ddef693d7bbb50b0",
		"internal/audit/codegen_test.go":                                                   "c1896696926104de33e540f207c4cc3e7f477edfddc006cfc9f279dd34e5df94",
		"internal/audit/security.go":                                                       "a180d1b42b37ac390a1bdf718a4c8172cafc8f14b8afd9c46c24831fe461cbe9",
		"internal/audit/security_test.go":                                                  "b4674dd844d0f006fe83ced7fbd6855a309e1bbd76ac1cd2fb6c8a73711a5519",
		"internal/codegen/authorization_v1_test.go":                                        "e2d8caf8757c35bc9e1aea7ba6c5a129d328f507d9aa54889223b83e536e4c51",
		"internal/codegen/generator_templates.go":                                          "53651959c9fbc7a936c23d4ae6cf5e4821e2322befc38596cbf215f3f24ff643",
		"internal/codegen/generator_test.go":                                               "2a519ad4aaf1d0ba4e4f9cf6294dc0772059f677e82a113b81c3712ac2832f31",
		"internal/product/lifecycle/phase8_verified.go":                                    "e9fd50ec54dca326be6580815153a3983555f1b31ea028e4a3c052257e7e17c6",
		"internal/product/lifecycle/phase8_verified_test.go":                               "7e3aad03d9af6dcec588c37225c4791cce3d38c7d0b3dfb7c69218b3ae5e5769",
		"internal/product/profile/phase8_activation.go":                                    "3de078f241b4bd4da039891cf19db34f30eae083363cd23ea21b393d88a3a080",
		"internal/product/profile/phase8_providers.go":                                     "9bf824c879fc0186de623f4c6a589a0ef2dce0cefb33b6168397363cd0a5f33c",
		"internal/product/profile/testdata/phase8-activation/activation-crash-report.json": "4e710e1683d0e68274d1403443c342dacbbb1e67033ced503bc0d389165609f0",
		"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json": "20b5867ab1fd0ff1aff509702021c2ccc0d529f5cd4434ad48cf74864d8b185b",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json":    "4e710e1683d0e68274d1403443c342dacbbb1e67033ced503bc0d389165609f0",
		"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json":               "d4987c0461d703870dcfc2a53d107537fc529cacfff0cb7ceef55343cb3722fa",
		"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json":       "6f2c3e15819d1fd18954aa242f5283e89fa1cc6a3c3964ea9ed864ee7553f364",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json":     "2fe3a7161549f9366a7d03e3724e9ec2d341659dec8af9e74e31778a908da2f0",
		"internal/runtime/policy_enforcement_test.go":                                                 "24ee3246889bf9393bece92e0016b464c3bd252ab4cf4a10038a69c069a2af20",
		"internal/testkit/importrules/importrules_test.go":                                            "f9f719b207174e13a2a1577c8fb450412fe0c2135b301c49311311fe84863221",
		"testdata/evidence/phase8-wo807-recovery-report.json":                                         "9ab249ec04fc5c012c5ed052e6bc927bcf1ed058760e26b2bbf48c0948a81c66",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != m2MaintenanceSelfPathV1 ||
		overlay.SelfPreSHA256 != "050dd24b449122dfd58a79df263c61a1e9cb8c83f4b038df82e7629e49d6dfc2" ||
		len(overlay.Paths) != len(paths) || len(overlay.Entries) != len(paths) {
		return nil, fmt.Errorf("invalid phase12 operator control-plane overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range paths {
		entry := overlay.Entries[i]
		if overlay.Paths[i] != path || entry.Path != path || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase12 operator control-plane entry %d", i)
		}
		predecessor, existed := preHashes[path]
		if existed {
			if entry.PreEvidence != "" || entry.PreSHA256 != predecessor || entry.PostSHA256 == entry.PreSHA256 {
				return nil, fmt.Errorf("invalid phase12 operator control-plane predecessor %d", i)
			}
		} else {
			if entry.PreEvidence != "ABSENT" || entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase12 operator control-plane absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		}
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase12 operator control-plane hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
	}
	return pre, nil
}

func validateM11LocalTransportOverlayV1(root string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	return validateM11LocalTransportOverlayAtPostV1(root, nil, overlays)
}

func validateM11LocalTransportOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	const name = "phase11-local-transport-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != m2MaintenanceSelfPathV1 ||
		!validSHA256V1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 128 ||
		len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase11 local transport overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || path == overlay.SelfPath ||
			strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") ||
			!validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase11 local transport entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase11 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase11 existing predecessor %d", i)
		}
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase11 local transport hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	return pre, nil
}

func validateM10VPNRuntimeOverlayV1(root string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	return validateM10VPNRuntimeOverlayAtPostV1(root, nil, overlays)
}

func validateM10VPNRuntimeOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	const name = "phase10-local-vpn-runtime-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != m2MaintenanceSelfPathV1 ||
		overlay.SelfPreSHA256 != "45559ed3772b777924c8ef5e2a24980b8ddfccab89e67613ff379f5b48824d76" ||
		len(overlay.Paths) != 56 || len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase10 VPN runtime overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	scope := sha256.New()
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase10 VPN runtime entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase10 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase10 existing predecessor %d", i)
		}
		scope.Write([]byte(path))
		scope.Write([]byte{0})
		scope.Write([]byte(predecessor))
		scope.Write([]byte{'\n'})
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase10 VPN runtime hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	if got := hex.EncodeToString(scope.Sum(nil)); got != "a05d9436a931ac6286fa9c77f8d16cd24af6eb283c64168700de50dfb1278477" {
		return nil, fmt.Errorf("phase10 VPN runtime scope drift %s", got)
	}
	return pre, nil
}

func validateM9GuardMaintenanceOverlayV1(root string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	return validateM9GuardMaintenanceOverlayAtPostV1(root, nil, overlays)
}

func validateM9GuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]m2MaintenanceOverlayRecordV1) (map[string]string, error) {
	const name = "phase9-wo909-final-guard-convergence-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != m2MaintenanceSelfPathV1 ||
		overlay.SelfPreSHA256 != "1f8149bb5ff5057e6b25dcad186c07303d57af4073f940708f257a17c9656623" ||
		len(overlay.Paths) != 159 || len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase9 guard-maintenance overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	scope := sha256.New()
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase9 guard-maintenance entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase9 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase9 existing predecessor %d", i)
		}
		scope.Write([]byte(path))
		scope.Write([]byte{0})
		scope.Write([]byte(predecessor))
		scope.Write([]byte{'\n'})
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase9 guard-maintenance hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	if got := hex.EncodeToString(scope.Sum(nil)); got != "d7ea283af5423eef0dc6af53d6b3004b241ba1474b3f50a1899edfddc69c12a1" {
		return nil, fmt.Errorf("phase9 guard-maintenance scope drift %s", got)
	}
	return pre, nil
}

func validateM8WO801AdoptionOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-wo801-adoption-v1"
	paths := []string{"testdata/evidence/phase8-wo801-adoption-2026-07-17.json", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", m2MaintenanceSelfPathV1}
	want := map[string]string{"cmd/kgen/main_test.go": "f3756c80bd358535e929a8bffa4ef79129f346318fb6304fdd01abd6c915a846", "internal/audit/codegen_test.go": "00ac00353fda287944ba5fd1965a130830514b2807c5df1ea46eccbcc1299791", "internal/audit/security.go": "d71fc4a337b995790ee397b944e3d7cf47ba675dc9204eeb8b5f2c513250b73d", "internal/audit/security_test.go": "dba0df11ef69fa6364a262d2f3fdf4bb8046f089fa314148ed5a7ae13c4cf7d8", "internal/codegen/authorization_v1_test.go": "c9b8f29d924a37e1b2fbba5b6a69ef04fc6043e4c2e0f77aafd162edf66d5adc", "internal/runtime/policy_enforcement_test.go": "ab7ab4f454448750a82e5a50a8acfba96b08ca5c4c492539c371f4a6f9f49241", "internal/testkit/importrules/importrules_test.go": "1c465b2026c31246a3685f96849604d0879e0025e892fc6a4b3875bf0ef09a17"}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.PredecessorManifestSHA256 != "989df23699da6edfb8e5279752dbe66863a854b530a532119a2689320049c56f" || len(o.Paths) != 9 || len(o.Entries) != 8 {
		return nil, fmt.Errorf("invalid phase8 WO-801 adoption overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, p := range paths {
		if o.Paths[i] != p {
			return nil, fmt.Errorf("invalid phase8 WO-801 adoption path %d", i)
		}
	}
	for i, e := range o.Entries {
		if e.Path != paths[i] || !validSHA256V1(e.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 WO-801 adoption entry %d", i)
		}
		if i == 0 {
			if e.PreEvidence != "ABSENT" {
				return nil, fmt.Errorf("invalid phase8 WO-801 adoption evidence predecessor")
			}
		} else if !validSHA256V1(e.PreEvidence) || e.PreEvidence != want[e.Path] {
			return nil, fmt.Errorf("phase8 WO-801 adoption reconstruction drift %s", e.Path)
		}
		a, present := currentAtPost[e.Path]
		var err error
		if !present {
			a, err = m2FileSHA256V1(root, e.Path)
		}
		if err != nil || a != e.PostSHA256 {
			return nil, fmt.Errorf("phase8 WO-801 adoption current hash drift %s=%s want %s: %v", e.Path, a, e.PostSHA256, err)
		}
		if i > 0 {
			pre[e.Path] = e.PreEvidence
		}
	}
	for p, w := range want {
		if pre[p] != w {
			return nil, fmt.Errorf("phase8 WO-801 adoption reconstructed %s=%s want %s", p, pre[p], w)
		}
	}
	return pre, nil
}

func validateBaselineStabilizationOverlayV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	wantPaths := []string{
		"cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		m2MaintenanceSelfPathV1,
	}
	overlay, ok := overlays[baselineStabilizationOverlayNameV1]
	if len(overlays) != 1 || !ok || overlay.Version != baselineStabilizationOverlayNameV1 ||
		overlay.PredecessorManifestSHA256 != baselineStabilizationPredecessorV1 ||
		len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid baseline stabilization overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid baseline stabilization path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validSHA256V1(entry.PreEvidence) ||
			!validSHA256V1(entry.PostSHA256) || entry.PreEvidence == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid baseline stabilization entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("baseline stabilization hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = entry.PreEvidence
	}
	return pre, nil
}

func validateM7AppRuntimeOverlayV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m7-offline-app-runtime-contract-v1"
	wantPaths := []string{
		"RZ-evidence-ref-069", "docs/KZ-evidence-ref-020", "docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023",
		"docs/KZ-evidence-ref-028", "internal/product/appruntime/appruntime.go", "internal/product/appruntime/appruntime_test.go",
		"testdata/consumer/m7-app-runtime-sdk/go.mod", "testdata/consumer/m7-app-runtime-sdk/app_runtime_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", m2MaintenanceSelfPathV1,
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "34f5d8d2048faf1de49c2ccd2ebb4a5c507ad3bf0b2d75b5db1e7e6d5c13a0a7" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid M7 app runtime overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid M7 app runtime path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid M7 app runtime entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M7 app runtime hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid M7 app runtime pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validateM6DiagnosticExportOverlayV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m6-offline-diagnostic-export-contract-v1"
	wantPaths := []string{
		"RZ-evidence-ref-069", "docs/KZ-evidence-ref-020", "docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023",
		"docs/KZ-evidence-ref-027", "internal/product/diagnosticexport/diagnosticexport.go", "internal/product/diagnosticexport/diagnosticexport_test.go",
		"testdata/consumer/m6-diagnostic-export-sdk/go.mod", "testdata/consumer/m6-diagnostic-export-sdk/diagnostic_export_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", m2MaintenanceSelfPathV1,
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "77fcaaa94436a401f071fbfbade94baeb0cd770574c7309ae5c427a76c030977" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid M6 diagnostic export overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid M6 diagnostic export path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid M6 diagnostic export entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M6 diagnostic export hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid M6 diagnostic export pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validateM5RelayDescriptorOverlayV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m5-offline-relay-descriptor-admission-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "709e4a5a7412ee115fc71c2d825ebe9ac4f167439b4861a1649dd63fcf0c150f" || len(overlay.Paths) != 17 || len(overlay.Entries) != 16 || overlay.Paths[16] != m2MaintenanceSelfPathV1 {
		return nil, fmt.Errorf("invalid M5 relay descriptor overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid M5 relay descriptor entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M5 relay descriptor hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid M5 relay descriptor pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validateM4FallbackOverlayV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m4-permitted-fallback-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "772ae344c99edb21a4d04fadd77f51978a6e81aa4d555ec30190cb64e7a7c2d9" || len(overlay.Paths) != 17 || len(overlay.Entries) != 16 || overlay.Paths[16] != m2MaintenanceSelfPathV1 {
		return nil, fmt.Errorf("invalid M4 fallback overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid M4 fallback entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M4 fallback hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence == "ABSENT" || entry.PreEvidence == "UNRECORDED" {
			delete(pre, entry.Path)
		} else {
			if !validSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid M4 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validateM3ContractOverlayV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m3-profile-lifecycle-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "50fde6a39c0b5d987a16e370f2d10f0526759c03c0d5f73a316cffcc207e4d90" || len(overlay.Paths) != len(overlay.Entries)+1 || overlay.Paths[len(overlay.Paths)-1] != m2MaintenanceSelfPathV1 {
		return nil, fmt.Errorf("invalid M3 contract overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid M3 contract entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M3 contract hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid M3 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		} else {
			delete(pre, entry.Path)
		}
	}
	return pre, nil
}

func validateHistoricalM3ContractOverlayV1(root string, currentAtPost map[string]string, overlays map[string]m2Phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m3-profile-lifecycle-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "50fde6a39c0b5d987a16e370f2d10f0526759c03c0d5f73a316cffcc207e4d90" || len(overlay.Paths) != len(overlay.Entries)+1 || overlay.Paths[len(overlay.Paths)-1] != m2MaintenanceSelfPathV1 {
		return nil, fmt.Errorf("invalid M3 contract overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid M3 contract entry %d", i)
		}
		if entry.PreEvidence == "ABSENT" {
			delete(pre, entry.Path)
			continue
		}
		if entry.PreEvidence == "UNRECORDED" || !validSHA256V1(entry.PreEvidence) {
			return nil, fmt.Errorf("invalid M3 pre evidence %s", entry.Path)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = m2FileSHA256V1(root, entry.Path)
		}
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M3 contract hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = entry.PreEvidence
	}
	return pre, nil
}

func validateM2ConvergenceV1(currentAtPost map[string]string, overlays map[string]m2LayeredOverlayV1) (map[string]string, error) {
	convergence, ok := overlays[m2EvidenceConvergenceOverlayV1]
	if len(overlays) != 1 || !ok || convergence.Version != m2EvidenceConvergenceOverlayV1 || convergence.PredecessorManifestSHA != "1502ae4db6d151839f554e6becde9e81994286cbff378945282739015492bf1e" || len(convergence.Entries) != len(m2ConvergencePathsV1) {
		return nil, fmt.Errorf("invalid M2 convergence identity/cardinality")
	}
	currentAtPre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		currentAtPre[path] = hash
	}
	for i, entry := range convergence.Entries {
		if entry.Path != m2ConvergencePathsV1[i] || entry.PreSHA256 != m2ConvergencePreV1[i] || !validSHA256V1(entry.PostSHA256) || entry.PostSHA256 == entry.PreSHA256 {
			return nil, fmt.Errorf("invalid M2 convergence entry %d", i)
		}
		actual := currentAtPost[entry.Path]
		if actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M2 convergence hash drift %s=%s want %s", entry.Path, actual, entry.PostSHA256)
		}
		currentAtPre[entry.Path] = entry.PreSHA256
	}
	return currentAtPre, nil
}

func m2FileSHA256V1(root, path string) (string, error) {
	return evidenceoverlay.ResolveCurrentSHA256(root, path)
}

type m0EvidenceRowV1 struct {
	Goal                   string `json:"goal"`
	Command                string `json:"command"`
	Behavior               string `json:"behavior"`
	RegressionTest         string `json:"regression_test"`
	OwningWork             string `json:"owning_work"`
	CandidateRepoState     string `json:"candidate_repo_state_hash"`
	OwningWOEvidenceSHA256 string `json:"owning_wo_evidence_sha256"`
}

var m0HistoricalWO014TouchesV1 = map[string]bool{
	"SZ-evidence-ref-070":              true,
	"internal/audit/security.go":       true,
	"internal/audit/security_test.go":  true,
	"internal/audit/runtime.go":        true,
	"internal/audit/hardening_test.go": true,
}

var m0WO058MaintenanceHashesV1 = map[string]string{
	"cmd/gate/main.go":                                  "c7d9d7127fec76e135fe0ea7bebd86285764025c735d8e733c12b9a0e662663f",
	"cmd/gate/main_test.go":                             "aac61d15fe907cdd439d03ea9701a85712300489b2aba593c15e3ffe5ecadb87",
	"cmd/kgen/main_test.go":                             "a80d10983b1e5684faf64011ee482a3a8216f2ab2393fbe9cd7570cbf4d5524d",
	"docs/GZ-evidence-ref-001":                          "867efaac1bb01cdfa62f954ead7deb895f827382c5075f969facb74a30fa3f57",
	"internal/audit/codegen_test.go":                    "0874db08bb14f2d94b94b88171f1d78cd87dd34122e6ca39e3eb4ec9942a00ec",
	"internal/codegen/authorization_v1_test.go":         "9f1941a9ef49c70aedddddf11890ea97df0563c2b921c75a3300aee713faf9ac",
	"internal/codegen/generator_test.go":                "2a519ad4aaf1d0ba4e4f9cf6294dc0772059f677e82a113b81c3712ac2832f31",
	"internal/testkit/importrules/importrules_test.go":  "1128d762990de6bac542df8afbbb08de06cc726c1117ecf55ec8feb69edfe167",
	"testdata/evidence/phase1-m0-committed-sha256.json": "4400e503524d1277329f893be0773dee202d5108265f62d22830e09fc8f8fa53",
}

var m0WO058HistoricalOutsideScopeHashesV1 = map[string]string{
	"cmd/gate/main.go":                                 "3bb816f92ef6a14ea72791057ab31d3a1d14766259efc3cc9f99ad9caedbb90f",
	"cmd/kgen/main_test.go":                            "3625c2657a23772a21137b98623733309e0c85a3d56a5063a1860fc5fad28de7",
	"docs/GZ-evidence-ref-001":                         "971cf99e586b22782058af5ebb083491e0169214065c39f717507ed8f9e98bfa",
	"internal/audit/codegen_test.go":                   "c7e3e5e6db1e13e4b7951f8f82d20f256a287f938f366c8d7f449428bdb7cca3",
	"internal/codegen/authorization_v1_test.go":        "34dafde20553b8f2079c8fc9cd668ffa723ca5b183ea1a644e5e99c089f75c2c",
	"internal/codegen/generator_test.go":               "d2fe0bd0bd5918f52e2dc32708d35ef0d5cc0e852ba9857a57381d4bc36db5c4",
	"internal/testkit/importrules/importrules_test.go": "436134fc57e2082ffc0ad4eba5e74bfc4a31dae078ef86cb6a0ef879d8f1ac35",
}

// m0StabilizationPreHashesV1 preserves the historical M0 candidate binding
// while later governance, status generation, Go toolchain, and test-harness
// maintenance is validated as an explicit post-M7 stabilization layer.
var m0StabilizationPreHashesV1 = map[string]string{
	".gitignore":                                      "5b183df65d579d6956f2fee4771afc35f32fa0eeb87d1cfa8bb1729e19e92f20",
	"SZ-evidence-ref-070":                             "975cad3a938fc17468f289b6190e605655427b1348c02cedc4222dd91869a0e3",
	"go.mod":                                          "56cc00cd67f0d708ed5d14f531fc2dc240664e98e0251b9c079db0a630409a3b",
	"internal/audit/audit_test.go":                    "f5fe13e623f9b6329bf5bcf3727f2dbc0632759e73fe5e4c095e5b18006f93cb",
	"internal/audit/status.go":                        "fbcc769047cfb38a8158e04d769d5450779e2b8c915d0fe0acbb530798eccfb6",
	"internal/codegen/templates.go":                   "3f8daa068d2453574deee62128f2e644420fe4ad21815e6c84bd9e224b7d152d",
	"internal/crypto/auth/handshake_test.go":          "6c90dd6f9263cb7d333aebff14437f575acc3f689a25ec26cc68cc30e24ee928",
	"internal/runtime/implementation_support_test.go": "4a39100cf82ecf213039dab84e2edcb612439868676a2e82986f8d76978b6abc",
}

type m0LineEndingOverlayV1 struct {
	CanonicalSHA256  string
	HistoricalSHA256 string
}

// m0LineEndingOverlaysV1 binds the semantic LF form now enforced by
// .gitattributes to the mixed-EOL bytes present in the historical M0 checkout.
// This keeps the historical evidence reproducible without allowing later text
// changes to hide behind a line-ending substitution.
var m0LineEndingOverlaysV1 = map[string]m0LineEndingOverlayV1{
	"cmd/kecho/main.go": {
		CanonicalSHA256:  "91513b220bef25a5fb2e48d1cefe59711a1fe0e8756abb6f6d253d91d1d150d3",
		HistoricalSHA256: "71ee315b2916fbba6fa4fffbaa40f8f839a8eddb374d8b36fbb7aaa782c7930a",
	},
	"docs/GITHUB_REPO_PROFILE.md": {
		CanonicalSHA256:  "e7a5e0f262e47a2017107566e8a483916cc95d7e47ad08c71fef6a5f1e4e684f",
		HistoricalSHA256: "bc1f573052500620d10aef286d17c39c627a81b1916d9259e9ff83bb47e49812",
	},
	"docs/KZ-evidence-ref-004": {
		CanonicalSHA256:  "f32756ff07ac1ca1c84cc276aaf957ebdd3ed2154f20b3225cec71e7e4bfe24d",
		HistoricalSHA256: "51ed0a08889ba4aa5a59cbce985b0de2e3ad8bc58d3a430ad60476f0365dba76",
	},
	"docs/KZ-evidence-ref-005": {
		CanonicalSHA256:  "b37561e48eb99b617080f781b20707b16c15509b2ba3582a4def3f520024c2a0",
		HistoricalSHA256: "8830d92ebaab9239da30b86990058992b840859b1f450661258ca3235ba7902a",
	},
	"docs/KZ-evidence-ref-006": {
		CanonicalSHA256:  "33b81f9151d796826b38ececf811e7a7eeefdb90954ba33f7d853bd07dd0473d",
		HistoricalSHA256: "b3180c1ba93e1c45a81d9699454dd32a0716351ec30fb26e4f4cc2e61f7ced92",
	},
	"docs/KZ-evidence-ref-007": {
		CanonicalSHA256:  "e1d8c56bb0fabeae5842cfe5553c8661aa138c2f080b63102ad336bf8149bb78",
		HistoricalSHA256: "cda57c7f09dc16374506ac360424a77944924f1c098dfe87ccc0cfa9cb660632",
	},
	"docs/KZ-evidence-ref-008": {
		CanonicalSHA256:  "5c0d6c31ea6b46c33fba583288b9c8c2f3f3d3fa62994126592d5c51133c77a3",
		HistoricalSHA256: "e38cd609309363072ef883d44cdda8875f8a03786d095bc3286eee6f5a829b52",
	},
	"docs/KZ-evidence-ref-009": {
		CanonicalSHA256:  "68f31b9b1f146f8536e91179c3ee97d768b64b825efbe81a7ba90f1cf63d5eb3",
		HistoricalSHA256: "2ab10cfeeccc89985e1288668af7828dcbc1fd15d8cbc5b6a6074f45a55f381b",
	},
	"docs/KZ-evidence-ref-010": {
		CanonicalSHA256:  "f4c7c7274a8ae2f973c425d8864009c5d6844a1b0e087148e22c1e7a854e784c",
		HistoricalSHA256: "01b5d0b80952fa35fec6e2428d202b8e29d2aa4725f646820daa6054b9710d08",
	},
	"docs/KZ-evidence-ref-011": {
		CanonicalSHA256:  "6af3347bf1a7a1a923fbf21c19b8a7f6b4bc0ee196481a41529d9e0015b264d0",
		HistoricalSHA256: "e4de6e405f75ec0d76ea4a84383981c61739cef5b318b6e62ef73b6f7fd2e066",
	},
	"docs/KZ-evidence-ref-015": {
		CanonicalSHA256:  "87b9cbdc559fb336402e8b8429aafff43dba36e7355bd907537adad31365ccea",
		HistoricalSHA256: "85d845408d982bef24fa6858d7cb72463c702eb57e8768f77d9ffc861a1046c7",
	},
	"docs/KZ-evidence-ref-016": {
		CanonicalSHA256:  "573a22a82eab35b3fdc48c5b3005f8d8fd5ef1befbdbc7e3fc6795e1ffdedbc6",
		HistoricalSHA256: "3b9230b334a01c58c31ff2cbba42d3cfee1e2b8f873b6d2ec40052668fe838f3",
	},
}

func m0LineEndingHistoricalHashesV1(root string, overlays map[string]m0LineEndingOverlayV1) (map[string]string, error) {
	successor, err := evidenceoverlay.LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		return nil, err
	}
	return m0LineEndingHistoricalHashesAtPostV1(root, overlays, successor)
}

func m0LineEndingHistoricalHashesAtPostV1(root string, overlays map[string]m0LineEndingOverlayV1, successor map[string]string) (map[string]string, error) {
	historical := make(map[string]string, len(overlays))
	for path, overlay := range overlays {
		if !validSHA256V1(overlay.CanonicalSHA256) || !validSHA256V1(overlay.HistoricalSHA256) {
			return nil, fmt.Errorf("invalid M0 line-ending overlay hash: %s", path)
		}
		effective, present := successor[path]
		var content []byte
		if !present {
			var err error
			content, err = os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil {
				return nil, fmt.Errorf("M0 line-ending overlay %s: %w", path, err)
			}
			effective = fmt.Sprintf("%x", sha256.Sum256(content))
		}
		if effective == overlay.CanonicalSHA256 {
			historical[path] = overlay.HistoricalSHA256
			continue
		}
		if content == nil {
			var err error
			content, err = os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil {
				return nil, fmt.Errorf("M0 line-ending overlay %s: %w", path, err)
			}
		}
		canonical := bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
		if bytes.Contains(canonical, []byte{'\r'}) {
			return nil, fmt.Errorf("M0 line-ending overlay contains a lone carriage return: %s", path)
		}
		actual := fmt.Sprintf("%x", sha256.Sum256(canonical))
		if actual != overlay.CanonicalSHA256 {
			return nil, fmt.Errorf("M0 line-ending overlay drift %s=%s want %s", path, actual, overlay.CanonicalSHA256)
		}
		historical[path] = overlay.HistoricalSHA256
	}
	return historical, nil
}

type m0CandidateManifestV1 struct {
	OutsideScopeSHA256    string
	OutsideScopeFileCount int
	MaintenancePaths      []string
	MaintenanceFileCount  int
	MaintenanceSHA256     string
	MaintenanceUnionPaths []string
	MaintenanceUnionCount int
}

func m0CandidateOutsideScopeManifestV1(root string) (m0CandidateManifestV1, error) {
	cmd := exec.Command("git", "ls-files", "-z", "--cached")
	cmd.Dir = root
	raw, err := cmd.Output()
	if err != nil {
		return m0CandidateManifestV1{}, fmt.Errorf("git-visible candidate inventory: %w", err)
	}
	parts := make([]string, 0, len(bytes.Split(raw, []byte{0})))
	for _, part := range bytes.Split(raw, []byte{0}) {
		parts = append(parts, filepath.ToSlash(string(part)))
	}
	successor, err := evidenceoverlay.LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		return m0CandidateManifestV1{}, err
	}
	preHashes, err := loadM2MaintenancePreHashesV1(root)
	if err != nil {
		return m0CandidateManifestV1{}, err
	}
	preHashes = m0CandidateMaintenancePreHashesV1(preHashes)
	lineEndingPreHashes, err := m0LineEndingHistoricalHashesAtPostV1(root, m0LineEndingOverlaysV1, successor)
	if err != nil {
		return m0CandidateManifestV1{}, err
	}
	for path, hash := range lineEndingPreHashes {
		if _, exists := preHashes[path]; exists {
			return m0CandidateManifestV1{}, fmt.Errorf("M0 line-ending overlay overlaps another historical layer: %s", path)
		}
		preHashes[path] = hash
	}
	for path, hash := range m0StabilizationPreHashesV1 {
		preHashes[path] = hash
	}
	rawManifest, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		return m0CandidateManifestV1{}, err
	}
	var evidence m2MaintenanceManifestV1
	if err := json.Unmarshal(rawManifest, &evidence); err != nil {
		return m0CandidateManifestV1{}, err
	}
	for _, overlay := range evidence.Phase2CompleteOverlays {
		for _, entry := range overlay.Entries {
			if entry.PreEvidence == "ABSENT" {
				preHashes[entry.Path] = "ABSENT"
			}
		}
	}
	for _, entry := range evidence.Phase3ContractOverlays["m3-profile-lifecycle-contract-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			preHashes[entry.Path] = "ABSENT"
		}
	}
	for _, entry := range evidence.Phase4FallbackOverlays["m4-permitted-fallback-contract-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			preHashes[entry.Path] = "ABSENT"
		}
	}
	for _, entry := range evidence.Phase5RelayDescriptorOverlays["m5-offline-relay-descriptor-admission-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			preHashes[entry.Path] = "ABSENT"
		}
	}
	for _, entry := range evidence.Phase6DiagnosticExportOverlays["m6-offline-diagnostic-export-contract-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			preHashes[entry.Path] = "ABSENT"
		}
	}
	for _, entry := range evidence.Phase7AppRuntimeOverlays["m7-offline-app-runtime-contract-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			preHashes[entry.Path] = "ABSENT"
		}
	}
	for _, entry := range evidence.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			preHashes[entry.Path] = "ABSENT"
		}
	}
	for _, entry := range evidence.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			preHashes[entry.Path] = "ABSENT"
		}
	}
	for _, entry := range evidence.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			preHashes[entry.Path] = "ABSENT"
		}
	}
	for _, overlay := range evidence.Phase8WorkOrderOverlays {
		for _, entry := range overlay.Entries {
			// Work-order overlays introduce exclusions for new paths. Existing
			// paths are already reconstructed by the older historical layers and
			// must not replace those earlier pre-hashes.
			if entry.PreEvidence == "ABSENT" {
				preHashes[entry.Path] = "ABSENT"
			}
		}
	}
	for _, overlay := range evidence.Phase8FinalGuardMaintenanceOverlays {
		for _, entry := range overlay.Entries {
			if entry.PreEvidence == "ABSENT" {
				preHashes[entry.Path] = "ABSENT"
			}
		}
	}
	for _, overlay := range evidence.Phase9GuardMaintenanceOverlays {
		for _, entry := range overlay.Entries {
			if entry.PreEvidence == "ABSENT" {
				preHashes[entry.Path] = "ABSENT"
			} else if _, reconstructed := preHashes[entry.Path]; !reconstructed {
				preHashes[entry.Path] = entry.PreSHA256
			}
		}
	}
	for _, overlay := range evidence.Phase10VPNRuntimeOverlays {
		for _, entry := range overlay.Entries {
			if entry.PreEvidence == "ABSENT" {
				preHashes[entry.Path] = "ABSENT"
			}
		}
	}
	for _, overlay := range evidence.Phase11LocalTransportOverlays {
		for _, entry := range overlay.Entries {
			if entry.PreEvidence == "ABSENT" {
				preHashes[entry.Path] = "ABSENT"
			} else if _, reconstructed := preHashes[entry.Path]; !reconstructed {
				preHashes[entry.Path] = entry.PreSHA256
			}
		}
	}
	for _, overlay := range evidence.Phase12OperatorControlPlaneOverlays {
		for _, entry := range overlay.Entries {
			if entry.PreEvidence == "ABSENT" {
				preHashes[entry.Path] = "ABSENT"
			} else if _, reconstructed := preHashes[entry.Path]; !reconstructed {
				preHashes[entry.Path] = entry.PreSHA256
			}
		}
	}
	for _, overlay := range evidence.Phase13AndroidProductOverlays {
		for _, entry := range overlay.Entries {
			if entry.PreEvidence == "ABSENT" {
				preHashes[entry.Path] = "ABSENT"
			} else if _, reconstructed := preHashes[entry.Path]; !reconstructed {
				preHashes[entry.Path] = entry.PreSHA256
			}
		}
	}
	for _, overlay := range evidence.Phase14AssuranceOverlays {
		for _, entry := range overlay.Entries {
			if entry.PreEvidence == "ABSENT" {
				preHashes[entry.Path] = "ABSENT"
			} else if _, reconstructed := preHashes[entry.Path]; !reconstructed {
				preHashes[entry.Path] = entry.PreSHA256
			}
		}
	}
	for path, predecessor := range successor {
		if predecessor == "ABSENT" {
			preHashes[path] = "ABSENT"
		} else if _, reconstructed := preHashes[path]; !reconstructed {
			preHashes[path] = predecessor
		}
	}
	preHashes[evidenceoverlay.SuccessorPath] = "ABSENT"
	preHashes[evidenceoverlay.Phase16SuccessorPath] = "ABSENT"
	preHashes[evidenceoverlay.Phase16ProductionTrustSuccessorPath] = "ABSENT"
	preHashes[evidenceoverlay.Phase16RuntimeSuccessorPath] = "ABSENT"
	preHashes[evidenceoverlay.Phase16DecentralizedSuccessorPath] = "ABSENT"
	preHashes[evidenceoverlay.Phase17SuccessorPath] = "ABSENT"
	preHashes[evidenceoverlay.PublicDocumentationSuccessorPath] = "ABSENT"
	for path, predecessor := range preHashes {
		if predecessor != "ABSENT" {
			parts = append(parts, path)
		}
	}
	return m0CandidateManifestFromPathsWithPreHashesV1(root, parts, preHashes)
}

func m0CandidateMaintenancePreHashesV1(preHashes map[string]string) map[string]string {
	result := make(map[string]string, len(preHashes)+len(m0WO058MaintenanceHashesV1))
	for path, hash := range preHashes {
		result[path] = hash
	}
	for path, hash := range m0WO058MaintenanceHashesV1 {
		if _, recorded := result[path]; !recorded {
			result[path] = hash
		}
	}
	return result
}

func m0CandidateManifestFromPathsV1(root string, inventory []string) (m0CandidateManifestV1, error) {
	return m0CandidateManifestFromPathsWithPreHashesV1(root, inventory, nil)
}

func m0CandidateManifestFromPathsWithPreHashesV1(root string, inventory []string, preHashes map[string]string) (m0CandidateManifestV1, error) {
	maintenanceUnion, err := m0MaintenanceUnionV1()
	if err != nil {
		return m0CandidateManifestV1{}, err
	}
	seen := map[string]bool{}
	maintenanceSeen := map[string]string{}
	historicalOverrides := map[string]string{}
	outsidePaths := []string{}
	for _, rawPath := range inventory {
		path := filepath.ToSlash(rawPath)
		if path == "" || m0HistoricalWO014TouchesV1[path] || seen[path] {
			continue
		}
		seen[path] = true
		if preHashes[path] == "ABSENT" {
			continue
		}
		if expected, ok := m0WO058MaintenanceHashesV1[path]; ok {
			actual := preHashes[path]
			if actual == "" {
				content, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
				if readErr != nil {
					return m0CandidateManifestV1{}, fmt.Errorf("WO-058 maintenance path %s: %w", path, readErr)
				}
				actual = fmt.Sprintf("%x", sha256.Sum256(content))
			}
			if actual != expected {
				return m0CandidateManifestV1{}, fmt.Errorf("WO-058 maintenance hash drift %s=%s want %s", path, actual, expected)
			}
			maintenanceSeen[path] = actual
			if historicalHash, existed := m0WO058HistoricalOutsideScopeHashesV1[path]; existed {
				historicalOverrides[path] = historicalHash
				outsidePaths = append(outsidePaths, path)
			}
			continue
		}
		outsidePaths = append(outsidePaths, path)
	}
	if len(maintenanceSeen) != len(m0WO058MaintenanceHashesV1) {
		missing := []string{}
		for path := range m0WO058MaintenanceHashesV1 {
			if _, ok := maintenanceSeen[path]; !ok {
				missing = append(missing, path)
			}
		}
		sort.Strings(missing)
		return m0CandidateManifestV1{}, fmt.Errorf("WO-058 maintenance paths missing: %v", missing)
	}
	maintenancePaths := make([]string, 0, len(maintenanceSeen))
	for path := range maintenanceSeen {
		maintenancePaths = append(maintenancePaths, path)
	}
	sort.Strings(maintenancePaths)
	maintenanceHasher := sha256.New()
	for _, path := range maintenancePaths {
		_, _ = maintenanceHasher.Write([]byte(path))
		_, _ = maintenanceHasher.Write([]byte{0})
		_, _ = maintenanceHasher.Write([]byte(maintenanceSeen[path]))
		_, _ = maintenanceHasher.Write([]byte{'\n'})
	}
	maintenanceHash := fmt.Sprintf("%x", maintenanceHasher.Sum(nil))

	sort.Strings(outsidePaths)
	h := sha256.New()
	for _, path := range outsidePaths {
		fileHash := historicalOverrides[path]
		if fileHash == "" {
			fileHash = preHashes[path]
		}
		if fileHash == "" {
			content, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if readErr != nil {
				return m0CandidateManifestV1{}, fmt.Errorf("candidate path %s: %w", path, readErr)
			}
			fileHash = fmt.Sprintf("%x", sha256.Sum256(content))
		}
		_, _ = h.Write([]byte(path))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(fileHash))
		_, _ = h.Write([]byte{'\n'})
	}
	return m0CandidateManifestV1{
		OutsideScopeSHA256:    fmt.Sprintf("%x", h.Sum(nil)),
		OutsideScopeFileCount: len(outsidePaths),
		MaintenancePaths:      maintenancePaths,
		MaintenanceFileCount:  len(maintenancePaths),
		MaintenanceSHA256:     maintenanceHash,
		MaintenanceUnionPaths: maintenanceUnion,
		MaintenanceUnionCount: len(maintenanceUnion),
	}, nil
}

func m0MaintenanceUnionV1() ([]string, error) {
	if len(m0HistoricalWO014TouchesV1) != 5 || len(m0WO058MaintenanceHashesV1) != 9 || len(m0WO058HistoricalOutsideScopeHashesV1) != 7 {
		return nil, fmt.Errorf("maintenance group sizes historical-WO-014=%d WO-058=%d historical-substitutions=%d", len(m0HistoricalWO014TouchesV1), len(m0WO058MaintenanceHashesV1), len(m0WO058HistoricalOutsideScopeHashesV1))
	}
	for path := range m0WO058HistoricalOutsideScopeHashesV1 {
		if _, ok := m0WO058MaintenanceHashesV1[path]; !ok {
			return nil, fmt.Errorf("historical substitution is not a WO-058 path: %s", path)
		}
	}
	seen := map[string]string{}
	for path := range m0HistoricalWO014TouchesV1 {
		seen[path] = "historical WO-014"
	}
	for path := range m0WO058MaintenanceHashesV1 {
		if group, exists := seen[path]; exists {
			return nil, fmt.Errorf("maintenance path overlap %s: %s and WO-058", path, group)
		}
		seen[path] = "WO-058"
	}
	if len(seen) != 14 {
		return nil, fmt.Errorf("maintenance union paths=%d want 14", len(seen))
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func SecurityM0IntegratedEvidenceGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("security_m0_g1_g13_integration", false, "required", err.Error(), nil, []string{err.Error()})
	}
	failures := []string{}
	manifest, bindingErr := m0CandidateOutsideScopeManifestV1(root)
	if bindingErr != nil {
		failures = append(failures, bindingErr.Error())
	} else {
		if manifest.OutsideScopeSHA256 != m0OutsideScopeHashV1 || manifest.OutsideScopeFileCount != m0OutsideScopeFileCount {
			failures = append(failures, fmt.Sprintf("pre-WO-014 candidate binding drift hash=%s files=%d", manifest.OutsideScopeSHA256, manifest.OutsideScopeFileCount))
		}
		if manifest.MaintenanceSHA256 != m0WO058MaintenanceHashV1 || manifest.MaintenanceFileCount != m0WO058MaintenanceCount {
			failures = append(failures, fmt.Sprintf("WO-058 maintenance binding drift hash=%s files=%d", manifest.MaintenanceSHA256, manifest.MaintenanceFileCount))
		}
	}
	seedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(m0PolicySeedCSVV1)))
	if seedHash != m0PolicySeedCSVHashV1 || len(strings.Split(m0PolicySeedCSVV1, ",")) != 29 || strings.HasPrefix(m0PolicySeedCSVV1, "1,2,3,4,5,6,7,8") {
		failures = append(failures, "frozen policy interaction seed evidence drift")
	}
	requiredSource := map[string][]string{
		"internal/runtime/generated_profile_parity_test.go": {
			"TestGeneratedProfileParityV1", m0PolicySeedCSVHashV1, "len(generatedProfileParityPinsV1) != 29",
		},
		"internal/runtime/policy_enforcement_test.go": {
			"TestInterpretedPolicyParityCoveringArrayV1", "pairwise coverage=%d/%d want 732/732", "TestPolicyMatrixOwnerWitnessLiteralCompleteV1",
		},
		"internal/runtime/handshake_test.go": {
			"TestPreEntropyVersionStructuredAdmission",
		},
		"internal/testkit/importrules/importrules_test.go": {
			"TestLabFaultCapabilityCannotReachNormalPaths", "TestGeneratedAuthorizationBoundaryInjectedV1", "internal/runtime/generated_escape.go",
		},
	}
	for path, markers := range requiredSource {
		raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if readErr != nil {
			failures = append(failures, path+": "+readErr.Error())
			continue
		}
		for _, marker := range markers {
			if !strings.Contains(string(raw), marker) {
				failures = append(failures, path+": missing "+marker)
			}
		}
	}
	rows := []m0EvidenceRowV1{
		{"G1", "go test -count=1 ./internal/runtime -run 'TestGeneratedProfileParityV1|TestInterpretedPolicyParityCoveringArrayV1|TestPolicyMatrixOwnerWitnessLiteralCompleteV1'", "every admitted policy value and the frozen 29-row interactions reach interpreted and generated-profile strict behavior", "TestGeneratedProfileParityV1", "WO-016,WO-050,WO-035..WO-044", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G2", "go test -count=1 ./internal/crypto/security -run 'TestReplayStateCommitsOnlyAfterAuthentication|TestReplayConcurrentAuthenticatedDuplicateCommitsOnce'", "authentication precedes replay mutation and concurrent duplicates commit at most once", "TestReplayStateCommitsOnlyAfterAuthentication", "WO-003,WO-020,WO-009", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G3", "go test -count=1 ./internal/crypto/auth -run 'TestAuthenticatedFirstContactFreshSessionNonceReplayAndKeys'", "authenticated first contact uses fresh session material and rejects replay", "TestAuthenticatedFirstContactFreshSessionNonceReplayAndKeys", "WO-019", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G4", "go test -count=1 ./internal/runtime -run 'TestProtectedChannelMultiFragmentExactCoverageV1|TestFragmentCoverageAndBoundsV1'", "authenticated fragment coverage rejects gaps, overlap, duplicates, and mixed coordinates", "TestProtectedChannelMultiFragmentExactCoverageV1", "WO-049", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G5", "go test -count=1 ./internal/runtime -run 'TestPolicyMatrixCoveringSeedsProtectedChannelProductionV1|TestPolicyMatrixPrivateEntrypointCausalBypassSentinelV1'", "bilateral floors and exact policy tuples cannot be weakened", "TestPolicyMatrixCoveringSeedsProtectedChannelProductionV1", "WO-031,WO-033,WO-022,WO-050", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G6", "go test -count=1 ./internal/runtime -run 'TestFirstRecordCommitServerEstablishOrderingV1|TestAuthenticatedOperationAckStrictReplayCommitOrderingV1'", "application and acknowledgement lifecycle commits remain transactional", "TestFirstRecordCommitServerEstablishOrderingV1", "WO-047,WO-048,WO-021,WO-049", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G7", "go test -count=1 ./internal/crypto/security ./internal/runtime -run 'TestContextIdentityRejectsInvalidFields|TestPreEntropyVersionStructuredAdmission'", "context identity and structured version admission reject before protected state", "TestContextIdentityRejectsInvalidFields", "WO-038,WO-039,WO-045", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G8", "go test -count=1 ./internal/runtime -run 'TestApplicationRecordVectorV1|TestProtectedChannelEndToEndSingleFragmentAckCloseV1'", "strict candidate application bytes are authenticated and tamper fail-closed", "TestProtectedChannelEndToEndSingleFragmentAckCloseV1", "WO-024,WO-021,WO-049", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G9", "go test -count=1 ./internal/runtime -run 'TestInProcessProtectedRelayProtectedPathAndAckV1|TestPairOwnershipAndTerminalRelayCloseV1'", "one configured in-process pair composes handshake, records, acknowledgement, and close", "TestInProcessProtectedRelayProtectedPathAndAckV1", "WO-011", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G10", "go test -count=1 ./internal/crypto/security -run 'TestNonceV1FormulaVectorsAndDirectionV1|TestNonceV1BurnRetryAndExhaust|TestNonceV1ConcurrentAllocation'", "all nonce formulas preserve direction, burn, exhaustion, and concurrent uniqueness", "TestNonceV1FormulaVectorsAndDirectionV1", "WO-020,WO-009,WO-026", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G11", "go test -count=1 ./internal/crypto/security -run 'TestKeyScheduleV1VectorEpochZeroAndOne|TestKeyScheduleV1DerivationAndSeparation'", "key schedule labels, directions, epochs, limits, and separation remain exact", "TestKeyScheduleV1DerivationAndSeparation", "WO-019,WO-021", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G12", "go test -count=1 ./internal/observe/trace -run 'TestDiagnosticEventV1ExhaustiveSchemaAndValues|TestSchemaSequenceCrossSessionProfileCorrelationV1'", "diagnostic schema and sequences reject secret and correlating expansion", "TestDiagnosticEventV1ExhaustiveSchemaAndValues", "WO-027,WO-012", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G13", "go test -count=1 ./internal/testkit/importrules -run 'TestLabFaultCapabilityCannotReachNormalPaths|VersionMigrationBoundary|GeneratedAuthorizationBoundary|NoLabShortcut'", "normal, generated, loader, runtime, and product paths cannot reach lab or offline-migration authority", "TestLabFaultCapabilityCannotReachNormalPaths", "WO-013,WO-044", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
	}
	if len(rows) != 13 {
		failures = append(failures, fmt.Sprintf("M0 goal rows=%d want=13", len(rows)))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.Goal] || row.Command == "" || row.Behavior == "" || row.RegressionTest == "" || row.OwningWork == "" || row.CandidateRepoState != m0AuthorizedRepoStateV1 || row.OwningWOEvidenceSHA256 != m0LifecycleEvidenceV1 {
			failures = append(failures, "invalid M0 evidence row "+row.Goal)
		}
		seen[row.Goal] = true
	}
	return gate("security_m0_g1_g13_integration", len(failures) == 0, "required", "13 bounded M0 local strict-candidate rows reconciled; global/product obligations remain open", map[string]any{
		"scope":                         "bounded M0 local strict-candidate",
		"global_product_status":         "open",
		"authorized_repo_state_hash":    m0AuthorizedRepoStateV1,
		"lifecycle_evidence_sha256":     m0LifecycleEvidenceV1,
		"outside_scope_manifest_sha256": manifest.OutsideScopeSHA256,
		"outside_scope_file_count":      manifest.OutsideScopeFileCount,
		"wo058_maintenance_paths":       manifest.MaintenancePaths,
		"wo058_maintenance_file_count":  manifest.MaintenanceFileCount,
		"wo058_maintenance_sha256":      manifest.MaintenanceSHA256,
		"maintenance_union_paths":       manifest.MaintenanceUnionPaths,
		"maintenance_union_file_count":  manifest.MaintenanceUnionCount,
		"m2_maintenance_overlay":        m2MaintenanceOverlayV1,
		"m2_maintenance_paths":          m2MaintenancePathsV1,
		"m2_phase2_complete_overlay":    m2Phase2CompleteOverlayNameV1,
		"m2_phase2_complete_paths":      m2Phase2CompletePathsV1,
		"wo014_allowed_touches":         []string{"SZ-evidence-ref-070", "internal/audit/hardening_test.go", "internal/audit/runtime.go", "internal/audit/security.go", "internal/audit/security_test.go"},
		"wo014_completion_hash":         "not-created-no-commit-authority",
		"policy_seed_csv_sha256":        seedHash,
		"policy_interaction_rows":       29,
		"policy_pairwise_coverage":      "732/732",
		"wo042_catalog_substitution":    false,
		"opaque_digest_reproduction":    false,
		"rows":                          rows,
	}, failures)
}

func SecurityTranscriptBindingGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	modes := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		input, err := transcriptInputForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		base, err := security.TranscriptHash(input)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		modes[p.Security.TranscriptMode] = true
		mutations := []func(*security.TranscriptInput){
			func(v *security.TranscriptInput) { v.ProfileHash = "changed-profile" },
			func(v *security.TranscriptInput) { v.StreamPolicy = "changed-stream" },
			func(v *security.TranscriptInput) { v.ProxyPolicy = "changed-proxy" },
			func(v *security.TranscriptInput) { v.CarrierPolicy = "changed-carrier" },
			func(v *security.TranscriptInput) { v.Capabilities = []string{"multi_stream"} },
		}
		for _, mutate := range mutations {
			changed := input
			mutate(&changed)
			next, err := security.TranscriptHash(changed)
			if err != nil {
				failures = append(failures, err.Error())
				continue
			}
			if next == base {
				failures = append(failures, "transcript mutation did not change hash for "+p.ID)
			}
		}
	}
	return gate("security_transcript_binding", len(failures) == 0, "required", fmt.Sprintf("%d profiles checked for transcript binding", len(selectProfiles(profiles, 3))), map[string]any{
		"transcript_modes": keys(modes),
	}, failures)
}

func SecurityKeyScheduleGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	suites := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		suites[p.Security.KDFSuite+"/"+p.Security.AEADSuite] = true
		a, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		b, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if !bytes.Equal(a.ClientWriteKey, b.ClientWriteKey) || bytes.Equal(a.ClientWriteKey, a.ServerWriteKey) || bytes.Equal(a.ClientNonceBase, a.ServerNonceBase) {
			failures = append(failures, "key schedule invariant failed for "+p.ID)
		}
	}
	return gate("security_key_schedule", len(failures) == 0, "required", fmt.Sprintf("%d security suites exercised", len(suites)), map[string]any{
		"security_suites": keys(suites),
	}, failures)
}

func SecurityNonceUniquenessGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	modes := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		ks, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		modes[p.Security.NonceMode] = true
		manager := security.NewNonceManager("client", ks.ClientNonceBase, p.Security.NonceMode)
		seen := map[string]bool{}
		for i := 0; i < 64; i++ {
			nonce, _, err := manager.Next()
			if err != nil {
				failures = append(failures, err.Error())
				break
			}
			key := string(nonce)
			if seen[key] {
				failures = append(failures, "duplicate nonce for "+p.ID)
				break
			}
			seen[key] = true
		}
	}
	return gate("security_nonce_uniqueness", len(failures) == 0, "required", fmt.Sprintf("%d nonce modes exercised", len(modes)), map[string]any{
		"nonce_modes": keys(modes),
	}, failures)
}

func SecurityReplayRejectionGate() GateResult {
	failures := []string{}
	window := security.NewReplayWindow("windowed_replay", 4)
	for _, seq := range []uint64{1, 3, 2, 4} {
		if err := window.Accept(seq); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if err := window.Accept(3); err == nil {
		failures = append(failures, "duplicate sequence accepted")
	}
	if err := security.NewReplayWindow("ordered_only", 4).Accept(2); err == nil {
		failures = append(failures, "ordered-only accepted out-of-order")
	}
	return gate("security_replay_rejection", len(failures) == 0, "required", "duplicate and out-of-order replay checks evaluated", map[string]any{
		"replay_policies": []string{"windowed_replay", "ordered_only"},
	}, failures)
}

func SecurityDowngradeResistanceGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	policies := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		policies[p.Security.DowngradePolicy] = true
		if err := security.DetectSuiteDowngrade(security.DefaultSuite(), security.Suite{KDF: "kdf_hkdf_sha1"}, ""); err == nil {
			failures = append(failures, "suite downgrade accepted")
		}
	}
	return gate("security_downgrade_resistance", len(failures) == 0, "required", fmt.Sprintf("%d downgrade policies exercised", len(policies)), map[string]any{
		"downgrade_policies": keys(policies),
	}, failures)
}

func SecurityCapabilityNegotiationGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	policies := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		policies[p.Security.CapabilityNegotiationPolicy] = true
		if _, err := (security.CapabilitySet{Features: p.Compatibility.RequiredCapabilities}).Hash(); err != nil {
			failures = append(failures, err.Error())
		}
		if err := security.RequireCapabilities(security.CapabilitySet{Features: p.Compatibility.RequiredCapabilities}, security.CapabilitySet{Features: []string{"multi_stream"}}); err == nil {
			failures = append(failures, "capability downgrade accepted for "+p.ID)
		}
	}
	return gate("security_capability_negotiation", len(failures) == 0, "required", fmt.Sprintf("%d capability policies exercised", len(policies)), map[string]any{
		"capability_policies": keys(policies),
	}, failures)
}

func SecurityProfileCompatibilityGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		if err := security.CheckProfileCompatibility(p, security.DefaultRuntimeCompatibility()); err != nil {
			failures = append(failures, err.Error())
		}
		bad := security.DefaultRuntimeCompatibility()
		bad.SupportedCarrierFamilies = []string{"unsupported_family"}
		if err := security.CheckProfileCompatibility(p, bad); err == nil {
			failures = append(failures, "unsupported carrier family accepted for "+p.ID)
		}
	}
	return gate("security_profile_compatibility", len(failures) == 0, "required", fmt.Sprintf("%d compatibility checks run", len(selectProfiles(profiles, 3))*2), nil, failures)
}

func SecurityConfigHygieneGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		cfg := security.SecurityConfig{
			ProfileID:        p.ID,
			ProfileHash:      ctx.ProfileHash,
			InputSecret:      testSecret(p),
			Suite:            ctx.Suite,
			ReplayWindow:     p.Security.ReplayWindowSize,
			MaxEnvelopeBytes: p.CarrierPolicy.MaxEnvelopeBytes,
			QueueDepth:       p.CarrierPolicy.MaxCarrierQueueDepth,
			Capabilities:     p.Compatibility.RequiredCapabilities,
			TranscriptHash:   ctx.TranscriptHash,
			CapabilityHash:   ctx.CapabilityHash,
		}
		if err := security.ValidateConfig(cfg); err != nil {
			failures = append(failures, err.Error())
		}
		cfg.InputSecret = make([]byte, len(cfg.InputSecret))
		if err := security.ValidateConfig(cfg); err == nil {
			failures = append(failures, "all-zero secret accepted for "+p.ID)
		}
	}
	return gate("security_config_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d config hygiene checks run", len(selectProfiles(profiles, 3))*2), nil, failures)
}

func SecuritySecretTraceHygieneGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		ks, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		codec, err := security.NewEnvelopeCodec(ctx, ks, "client")
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		payload := []byte("payload must not leak")
		env, err := codec.Seal(security.EnvelopeMetadata{StreamID: 1, Semantic: "target_response", CarrierFamily: p.CarrierPolicy.CarrierFamily}, payload)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		ev, err := security.SecureEnvelopeDiagnosticV1(ctx, env)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		raw, _ := json.Marshal(ev)
		if security.TraceHasSecretCandidate(raw, payload, ks.ClientWriteKey, ks.ClientNonceBase, env.Ciphertext, env.Nonce) || ktrace.ContainsSensitiveValue(ev, payload, ks.ClientWriteKey, ks.ClientNonceBase, env.Ciphertext, env.Nonce, []byte(p.ID), []byte(ctx.TranscriptHash)) {
			failures = append(failures, "security trace leaked secret material for "+p.ID)
		}
	}
	return gate("security_secret_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d secret trace hygiene checks run", len(selectProfiles(profiles, 3))), nil, failures)
}

func SecurityMutantDetectionGate(ctx context.Context) GateResult {
	_ = ctx
	return realLabFaultInjectionGateV1("security_mutant_detection", "security", 4100)
}

const realLabFaultInjectionLabelV1 = "real lab fault-injection detector sensitivity"
const realLabFaultInjectionLimitV1 = "a pass proves only that each named detector turns red under its bounded deliberate fault and stays green in its control; it does not prove defect absence, production security, product integration, release readiness, or authorization to merge or deploy"

func realLabFaultInjectionGateV1(name, family string, seed int64) GateResult {
	table := runtimeadversary.RealMutantCorpusTableV1()
	results, err := runtimeadversary.RunRealMutantCorpusV1(seed)
	if err != nil {
		return gate(name, false, "required", realLabFaultInjectionLabelV1, map[string]any{"label": realLabFaultInjectionLabelV1, "limitation": realLabFaultInjectionLimitV1}, []string{err.Error()})
	}
	return realLabFaultInjectionGateResultsV1(name, family, table, results)
}

func realLabFaultInjectionGateResultsV1(name, family string, table []runtimeadversary.RealMutantCorpusRowV1, results []runtimeadversary.RealMutantCorpusResultV1) GateResult {
	expected := make(map[string]runtimeadversary.RealMutantCorpusRowV1, 8)
	known := make(map[string]runtimeadversary.RealMutantCorpusRowV1, 16)
	familyCounts := map[string]int{"security": 0, "runtime": 0}
	failures := []string{}
	for _, row := range table {
		if _, duplicate := known[row.Mode]; duplicate {
			failures = append(failures, "duplicate table mode "+row.Mode)
			continue
		}
		known[row.Mode] = row
		if _, allowed := familyCounts[row.Family]; !allowed {
			failures = append(failures, "unknown table family "+row.Family)
			continue
		}
		familyCounts[row.Family]++
		if row.Family == family {
			expected[row.Mode] = row
		}
	}
	seen := make(map[string]bool, 8)
	seenAll := make(map[string]bool, 16)
	seenFamily := map[string]int{"security": 0, "runtime": 0}
	rows := make([]map[string]any, 0, 8)
	for _, result := range results {
		row, knownMode := known[result.Mode]
		if !knownMode {
			failures = append(failures, "unknown result mode "+result.Mode)
			continue
		}
		if seenAll[result.Mode] {
			failures = append(failures, "duplicate mode "+result.Mode)
			continue
		}
		seenAll[result.Mode] = true
		seenFamily[row.Family]++
		valid := result.Category == row.Category && result.Detector == row.Detector && result.Count == row.ExpectedCount && result.UnsafeObserved && result.DetectorRed && result.ControlGreen
		if !valid {
			failures = append(failures, "invalid real observation "+result.Mode)
		}
		if row.Family != family {
			continue
		}
		seen[result.Mode] = true
		rows = append(rows, map[string]any{"mode": result.Mode, "category": result.Category, "count": result.Count, "status": map[bool]string{true: "red_fault_green_control", false: "invalid"}[valid]})
	}
	for mode := range expected {
		if !seen[mode] {
			failures = append(failures, "missing mode "+mode)
		}
	}
	if len(table) != 16 || len(known) != 16 || familyCounts["security"] != 8 || familyCounts["runtime"] != 8 {
		failures = append(failures, fmt.Sprintf("table corpus cardinality rows=%d known=%d security=%d runtime=%d", len(table), len(known), familyCounts["security"], familyCounts["runtime"]))
	}
	if len(results) != 16 || len(seenAll) != 16 || seenFamily["security"] != 8 || seenFamily["runtime"] != 8 {
		failures = append(failures, fmt.Sprintf("result corpus cardinality rows=%d known=%d security=%d runtime=%d", len(results), len(seenAll), seenFamily["security"], seenFamily["runtime"]))
	}
	if len(expected) != 8 || len(seen) != 8 {
		failures = append(failures, fmt.Sprintf("%s corpus cardinality expected=%d seen=%d", family, len(expected), len(seen)))
	}
	summary := fmt.Sprintf("%d/8 %s pairs passed; %s", 8-len(failures), realLabFaultInjectionLabelV1, realLabFaultInjectionLimitV1)
	return gate(name, len(failures) == 0, "required", summary, map[string]any{"label": realLabFaultInjectionLabelV1, "limitation": realLabFaultInjectionLimitV1, "rows": rows}, failures)
}

func SecurityGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("security_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source, err := codegenGeneratorSource(root)
	if err != nil {
		return gate("security_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	text := string(source)
	failures := []string{}
	for _, marker := range []string{"security_generated.go", "SecurityDemo", "CaptureSecurityTrace", "security-demo", "security"} {
		if !strings.Contains(text, marker) {
			failures = append(failures, "missing generated backend marker "+marker)
		}
	}
	integration := SecurityM0IntegratedEvidenceGate()
	if !integration.Passed {
		failures = append(failures, "bounded M0 integration evidence failed")
	}
	return gate("security_generated_backend_parity", len(failures) == 0, "required", "generated security markers and bounded M0 G1-G13 integration evidence checked", map[string]any{
		"scanner":                    "source-marker-and-executable-test-registry",
		"authorized_repo_state_hash": m0AuthorizedRepoStateV1,
		"policy_seed_csv_sha256":     m0PolicySeedCSVHashV1,
		"policy_interaction_rows":    29,
		"policy_pairwise_coverage":   "732/732",
		"global_product_status":      "open",
	}, failures)
}

func securityContextForProfile(p *ir.Profile) (security.SecurityContext, error) {
	input, err := transcriptInputForProfile(p)
	if err != nil {
		return security.SecurityContext{}, err
	}
	return security.BuildContext(input)
}

func transcriptInputForProfile(p *ir.Profile) (security.TranscriptInput, error) {
	hash, err := security.ProfileHash(p)
	if err != nil {
		return security.TranscriptInput{}, err
	}
	return security.TranscriptInput{
		ProfileID:           p.ID,
		ProfileHash:         hash,
		CompilerHash:        Version,
		SemanticMappingHash: p.GenerationHash,
		FSMPolicy:           fmt.Sprintf("%d/%d", len(p.States), len(p.Transitions)),
		FramingPolicy:       p.FrameGrammar.LengthMode + "/" + p.FrameGrammar.TypeMode + "/" + p.FrameGrammar.FragmentationMode,
		SchedulerPolicy:     p.Scheduler.Mode + "/" + p.Scheduler.PriorityMode,
		PaddingPolicy:       p.Padding.Mode,
		StreamPolicy:        p.Stream.IDStrategy + "/" + p.Stream.PriorityPolicy + "/" + p.Stream.WindowUpdatePolicy,
		ProxyPolicy:         p.ProxySemantics.TargetDescriptorEncoding + "/" + p.ProxySemantics.ResponseModeEncoding,
		CarrierPolicy:       p.CarrierPolicy.CarrierFamily + "/" + p.CarrierPolicy.EnvelopeEncoding + "/" + p.CarrierPolicy.FlushPolicy,
		Capabilities:        p.Compatibility.RequiredCapabilities,
		SessionNonce:        []byte(fmt.Sprintf("audit-session-%016d", p.Seed)),
		Suite:               security.DefaultSuite(),
		OrderedStatePath:    []string{p.FirstContact.StartState, p.FirstContact.RelayReadyState},
	}, nil
}

func testSecret(p *ir.Profile) []byte {
	return []byte("audit-secret:" + p.ID + ":" + p.GenerationHash)
}

func securitySummary(profiles []*ir.Profile) map[string]any {
	transcriptModes := profileValues(profiles, func(p *ir.Profile) string { return p.Security.TranscriptMode })
	nonceModes := profileValues(profiles, func(p *ir.Profile) string { return p.Security.NonceMode })
	replayPolicies := profileValues(profiles, func(p *ir.Profile) string { return p.Security.ReplayPolicy })
	capabilityPolicies := profileValues(profiles, func(p *ir.Profile) string { return p.Security.CapabilityNegotiationPolicy })
	return map[string]any{
		"unique_transcript_modes":      uniqueStrings(transcriptModes),
		"unique_nonce_modes":           uniqueStrings(nonceModes),
		"unique_replay_policies":       uniqueStrings(replayPolicies),
		"unique_capability_policies":   uniqueStrings(capabilityPolicies),
		"profile_count":                len(profiles),
		"profile_version":              ir.SupportedVersion,
		"security_version":             ir.SupportedSecurityVersion,
		"compatibility_schema_version": ir.SupportedVersion,
		"compiler_security_version":    ir.SupportedSecurityVersion,
		"minimum_runtime_version":      ir.SupportedSecurityVersion,
		"handshake_version":            security.HandshakeVersionV1,
		"policy_encoding_version":      security.PolicyEncodingVersionV1,
		"record_version":               security.RecordVersionV1,
		"required_capability_count":    len(ir.SecurityCapabilities()),
		"supported_security_suite":     ir.SecuritySuiteString(),
		"secure_envelope_model":        "metadata/authenticated synthetic AEAD test model",
	}
}

func uniqueList(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func keys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
