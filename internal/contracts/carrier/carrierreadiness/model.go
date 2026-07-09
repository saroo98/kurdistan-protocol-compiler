// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrierreadiness

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
	Version                  = "carrierreadiness-v1"
	DefaultFixtureID         = "carrier_prototype_readiness_v1"
	RecommendedNextMilestone = "M41: carrier prototype design review"

	StatusReadyForReview = "ready_for_review"
	StatusNeedsWork      = "needs_work"
	StatusBlocked        = "blocked"
	DecisionReady        = "ready_for_next_design_review"
)

var ErrRefuseOverwrite = errors.New("refusing to overwrite existing carrier readiness fixture")

type InventoryItem struct {
	Name          string `json:"name"`
	Layer         string `json:"layer"`
	Status        string `json:"status"`
	Evidence      string `json:"evidence"`
	RemainingRisk string `json:"remaining_risk"`
}

type DependencyEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status string `json:"status"`
}

type BoundaryCheck struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Policy   string `json:"policy"`
	Enforced bool   `json:"enforced"`
	Evidence string `json:"evidence"`
}

type FutureContract struct {
	Milestone string `json:"milestone"`
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Status    string `json:"status"`
}

type Blocker struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Required bool   `json:"required"`
	Status   string `json:"status"`
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

type CarrierReadinessReview struct {
	Version                  string           `json:"version"`
	FixtureID                string           `json:"fixture_id"`
	GeneratedAt              string           `json:"generated_at"`
	GeneratedAtUnix          int64            `json:"generated_at_unix"`
	BackendVersion           string           `json:"backend_version"`
	RecommendedNextMilestone string           `json:"recommended_next_milestone"`
	Inventory                []InventoryItem  `json:"inventory"`
	Dependencies             []DependencyEdge `json:"dependencies"`
	Boundaries               []BoundaryCheck  `json:"boundaries"`
	FutureContracts          []FutureContract `json:"future_contracts"`
	Blockers                 []Blocker        `json:"blockers"`
	Risks                    []RiskItem       `json:"risks"`
	Checklist                []ChecklistItem  `json:"checklist"`
	Decision                 string           `json:"decision"`
	ReviewHash               string           `json:"review_hash"`
	PayloadLogged            bool             `json:"payload_logged"`
	SecretLogged             bool             `json:"secret_logged"`
	Conclusion               string           `json:"conclusion"`
}

type MisuseReport struct {
	UnsafeControls []string `json:"unsafe_controls"`
	UnsafeDetected int      `json:"unsafe_detected"`
	PayloadLogged  bool     `json:"payload_logged"`
	SecretLogged   bool     `json:"secret_logged"`
	Conclusion     string   `json:"conclusion"`
}

type ParityReport struct {
	InventoryCompared int      `json:"inventory_compared"`
	ContractsCompared int      `json:"contracts_compared"`
	SemanticMatches   int      `json:"semantic_matches"`
	UnexpectedDrift   []string `json:"unexpected_drift,omitempty"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
	Conclusion        string   `json:"conclusion"`
}

type FixtureSet struct {
	Version       string                 `json:"version"`
	Review        CarrierReadinessReview `json:"review"`
	Misuse        MisuseReport           `json:"misuse"`
	Parity        ParityReport           `json:"parity"`
	FixtureHash   string                 `json:"fixture_hash"`
	PayloadLogged bool                   `json:"payload_logged"`
	SecretLogged  bool                   `json:"secret_logged"`
	Conclusion    string                 `json:"conclusion"`
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
	review := GenerateReview()
	set := FixtureSet{
		Version:    Version,
		Review:     review,
		Misuse:     ScanMisuse(),
		Parity:     BuildParity(review),
		Conclusion: "passed",
	}
	set.FixtureHash = HashValue(setWithoutHash(set))
	return set, ValidateFixtureSet(set)
}

func GenerateReview() CarrierReadinessReview {
	review := CarrierReadinessReview{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              fixedGeneratedAt().Format(time.RFC3339),
		GeneratedAtUnix:          fixedGeneratedAt().Unix(),
		BackendVersion:           "0.40.0-lab",
		RecommendedNextMilestone: RecommendedNextMilestone,
		Inventory: []InventoryItem{
			{"local protocol adapter", "adapter", StatusReadyForReview, "M37 parser fixtures and gates", "metadata-only parser"},
			{"loopback relay transport", "relay", StatusReadyForReview, "M38 loopback relay fixtures and gates", "loopback-only harness"},
			{"lab egress connector", "egress", StatusReadyForReview, "M39 allowlist connector fixtures and gates", "synthetic targets only"},
			{"byte transport harness", "byte_path", StatusReadyForReview, "M17-M18 fixtures and parity", "local deterministic bytes only"},
			{"carrier abstraction", "carrier", StatusReadyForReview, "M11 carrier models and audits", "abstract models only"},
			{"security prerequisites", "security", StatusReadyForReview, "M12 transcript/replay/downgrade gates", "not final production key exchange"},
		},
		Dependencies: []DependencyEdge{
			{"local protocol adapter", "loopback relay transport", StatusReadyForReview},
			{"loopback relay transport", "lab egress connector", StatusReadyForReview},
			{"lab egress connector", "carrier prototype design review", StatusReadyForReview},
			{"carrier abstraction", "carrier prototype design review", StatusReadyForReview},
			{"security prerequisites", "carrier prototype design review", StatusReadyForReview},
		},
		Boundaries: []BoundaryCheck{
			{"no external targets", StatusReadyForReview, "local-only connector inputs", true, "M39 allowlist gate"},
			{"no deployment behavior", StatusReadyForReview, "fixtures and audits only", true, "M40 blocker register"},
			{"no payload logging", StatusReadyForReview, "trace hygiene scanner", true, "all fixture scanners"},
			{"no production key exchange", StatusReadyForReview, "security prerequisite model only", true, "M12/M40 boundary"},
			{"no live carrier implementation", StatusReadyForReview, "prototype review gate blocks carrier code", true, "M40 decision matrix"},
		},
		FutureContracts: []FutureContract{
			{"M41", "carrier prototype design review", "contract and threat model", StatusNeedsWork},
			{"M42", "carrier prototype harness", "deterministic local carrier prototype only", StatusNeedsWork},
			{"M43", "carrier adversarial hardening", "collapse/misuse gates for carrier prototype", StatusNeedsWork},
		},
		Blockers: []Blocker{
			{"public carrier implementation", "critical", true, StatusBlocked},
			{"production deployment", "critical", true, StatusBlocked},
			{"external target dialing", "critical", true, StatusBlocked},
			{"payload-bearing traces", "critical", true, StatusBlocked},
			{"production key exchange", "high", true, StatusBlocked},
		},
		Risks: []RiskItem{
			{"carrier fingerprint collapse", "high", "require bundle/wire/fixture parity gates before prototype", StatusNeedsWork},
			{"operational misuse", "high", "keep prototype local and audit-only", StatusNeedsWork},
			{"trace leakage", "high", "fixture and generated hygiene gates", StatusReadyForReview},
			{"generated drift", "medium", "generated/interpreted parity gates", StatusReadyForReview},
		},
		Checklist: []ChecklistItem{
			{"inventory complete", true, "six prerequisite layers listed"},
			{"dependency graph complete", true, "five prerequisite edges listed"},
			{"boundaries enforced", true, "five blocking boundaries listed"},
			{"future contracts scoped", true, "M41-M43 contracts listed"},
			{"public claim safety checked", true, "unsafe public claims absent"},
			{"generated parity checked", true, "codegen marker and parity gate"},
		},
		Decision:   DecisionReady,
		Conclusion: "passed",
	}
	review.ReviewHash = HashValue(reviewWithoutHash(review))
	return review
}

func ScanMisuse() MisuseReport {
	controls := []string{"public_carrier_implementation", "external_target_dial", "deployment_script", "payload_trace", "production_key_exchange", "live_probe", "generated_backend_drift"}
	return MisuseReport{UnsafeControls: controls, UnsafeDetected: len(controls), Conclusion: "passed"}
}

func BuildParity(review CarrierReadinessReview) ParityReport {
	compared := len(review.Inventory) + len(review.FutureContracts)
	return ParityReport{InventoryCompared: len(review.Inventory), ContractsCompared: len(review.FutureContracts), SemanticMatches: compared, Conclusion: "passed"}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.Conclusion != "passed" {
		return errors.New("invalid carrier readiness fixture")
	}
	if len(set.Review.Inventory) < 6 || len(set.Review.FutureContracts) < 3 || set.Review.Decision != DecisionReady {
		return errors.New("carrier readiness review incomplete")
	}
	if set.PayloadLogged || set.SecretLogged || set.Review.PayloadLogged || set.Review.SecretLogged || set.Parity.PayloadLogged || set.Parity.SecretLogged {
		return errors.New("carrier readiness hygiene failed")
	}
	if set.Review.ReviewHash == "" || HashValue(reviewWithoutHash(set.Review)) != set.Review.ReviewHash {
		return errors.New("carrier readiness review hash drift")
	}
	if set.FixtureHash == "" || HashValue(setWithoutHash(set)) != set.FixtureHash {
		return errors.New("carrier readiness fixture hash drift")
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
			return fmt.Errorf("carrier readiness unsafe metadata marker: %s", marker)
		}
	}
	return nil
}

var forbiddenMarkers = []string{
	"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "packet_dump", "pcap", "raw_secret", "derived_key",
	"nonce_base", "auth_tag", "proof_material", "private_key", "session_secret", "public_ip", "destination_address",
	"dns_query", "resolver", "payload_logged\":true", "secret_logged\":true", "guaranteed bypass", "undetectable",
	"production vpn", "field-ready", "live probing",
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
	if oldSet.Review.Decision != newSet.Review.Decision {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "decision_changed")
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

func reviewWithoutHash(review CarrierReadinessReview) CarrierReadinessReview {
	review.ReviewHash = ""
	return review
}

func setWithoutHash(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func fixedGeneratedAt() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}
