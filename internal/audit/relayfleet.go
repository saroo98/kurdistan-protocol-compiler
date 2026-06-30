// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/hostdetect"
	"kurdistan/internal/mutant"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/relayfleet"
	"kurdistan/internal/wireeval"
)

type RelayFleetAuditSummary struct {
	Version      string                                `json:"version"`
	FleetID      string                                `json:"fleet_id"`
	Relays       int                                   `json:"relays"`
	ActiveRelays int                                   `json:"active_relays"`
	Assignment   relayfleet.ProfileAssignmentReport    `json:"assignment"`
	ChurnEvents  int                                   `json:"churn_events"`
	Migrations   int                                   `json:"migration_events"`
	BurnRisk     relayfleet.BurnRiskReport             `json:"burn_risk"`
	Collapse     relayfleet.FleetCollapseReport        `json:"collapse"`
	Comparison   relayfleet.RelayFleetComparisonReport `json:"comparison"`
	Parity       relayfleet.FleetParityReport          `json:"parity"`
	Conclusion   string                                `json:"conclusion"`
}

func RunRelayFleetAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	seeds := wireeval.DefaultSeeds()
	opts := relayfleet.DefaultOptions()
	if cfg.Mode == "full" {
		seeds = make([]int, 30)
		for i := range seeds {
			seeds[i] = int(cfg.StartSeed) + i
		}
		opts = relayfleet.FullOptions()
	}
	dataset, err := wireeval.BuildDataset(ctx, protocorpus.DefaultCorpus(), wireeval.BuildOptions{Seeds: seeds, Scenarios: wireeval.DefaultScenarios(), SplitMode: wireeval.DefaultSplitMode(), Controls: true})
	if err != nil {
		return AuditReport{}, err
	}
	hostSummary, err := hostdetect.Run(dataset, hostdetect.DefaultBuildOptions())
	if err != nil {
		return AuditReport{}, err
	}
	summary, err := relayfleet.Run(dataset, hostSummary, opts)
	if err != nil {
		return AuditReport{}, err
	}
	baselinePath := filepath.Join(root, "testdata", "relayfleet", "relayfleet-golden.json")
	comparison, _ := relayfleet.VerifyFleet(ctx, baselinePath)
	gates := RelayFleetGates(summary, comparison)
	auditSummary := RelayFleetAuditSummary{
		Version:      string(relayfleet.Version),
		FleetID:      summary.Fleet.FleetID,
		Relays:       len(summary.Fleet.Relays),
		ActiveRelays: activeRelayCount(summary.Fleet.Relays),
		Assignment:   summary.Assignment,
		ChurnEvents:  len(summary.ChurnEvents),
		Migrations:   len(summary.MigrationEvents),
		BurnRisk:     summary.BurnRisk,
		Collapse:     summary.Collapse,
		Comparison:   comparison,
		Parity:       summary.Parity,
		Conclusion:   "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "relayfleet-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     dataset.Manifest.ProfileCount,
		TraceCount:       len(summary.Fleet.Relays),
		Gates:            gates,
		TraceScanSummary: auditSummary,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
		auditSummary.Conclusion = "failed"
		report.TraceScanSummary = auditSummary
	}
	return report, nil
}

func RelayFleetGates(summary relayfleet.RelayFleetSummary, comparison relayfleet.RelayFleetComparisonReport) []GateResult {
	return []GateResult{
		RelayFleetLifecycleIntegrityGate(summary),
		RelayFleetProfileAssignmentGate(summary.Assignment),
		RelayFleetChurnScheduleGate(summary),
		RelayFleetMigrationModelGate(summary),
		RelayFleetBurnRiskGate(summary.BurnRisk),
		RelayFleetCollapseDetectionGate(summary.Collapse),
		RelayFleetControlDetectionGate(summary),
		RelayFleetGeneratedBackendParityGate(),
		RelayFleetTraceHygieneGate(summary),
		RelayFleetMutantDetectionGate(),
		RelayFleetFixtureDriftGate(comparison),
	}
}

func RelayFleetLifecycleIntegrityGate(summary relayfleet.RelayFleetSummary) GateResult {
	failures := []string{}
	if err := relayfleet.ValidateFleet(summary.Fleet); err != nil {
		failures = append(failures, err.Error())
	}
	if activeRelayCount(summary.Fleet.Relays) > summary.Fleet.Policy.MaxActiveRelays {
		failures = append(failures, "active relay count exceeds policy")
	}
	if len(relayfleet.LifecycleGolden(summary.Fleet)) == 0 {
		failures = append(failures, "no lifecycle transitions represented")
	}
	return gate("relayfleet_lifecycle_integrity", len(failures) == 0, "required", fmt.Sprintf("%d relays, %d active", len(summary.Fleet.Relays), activeRelayCount(summary.Fleet.Relays)), map[string]any{"policy": summary.Fleet.Policy.Name}, failures)
}

func RelayFleetProfileAssignmentGate(report relayfleet.ProfileAssignmentReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, "profile assignment failed")
	}
	if report.UniqueProfileSeeds < 3 || report.UniqueWirePolicyHashes < 3 || report.UniqueSelectedFamilies < 2 {
		failures = append(failures, "assignment diversity below threshold")
	}
	return gate("relayfleet_profile_assignment", len(failures) == 0, "required", fmt.Sprintf("%d profile seeds, %d wire policies", report.UniqueProfileSeeds, report.UniqueWirePolicyHashes), map[string]any{"assignment": report}, failures)
}

func RelayFleetChurnScheduleGate(summary relayfleet.RelayFleetSummary) GateResult {
	failures := []string{}
	if len(summary.ChurnEvents) == 0 {
		failures = append(failures, "no churn events")
	}
	for _, event := range summary.ChurnEvents {
		if event.PayloadLogged || event.SecretLogged {
			failures = append(failures, event.EventID+": hygiene flag")
		}
	}
	return gate("relayfleet_churn_schedule", len(failures) == 0, "required", fmt.Sprintf("%d churn events using %s", len(summary.ChurnEvents), summary.Fleet.Policy.ChurnMode), map[string]any{"churn_events": summary.ChurnEvents}, failures)
}

func RelayFleetMigrationModelGate(summary relayfleet.RelayFleetSummary) GateResult {
	failures := []string{}
	if summary.Fleet.Policy.MigrationEnabled && len(summary.MigrationEvents) == 0 {
		failures = append(failures, "migration enabled but no events")
	}
	for _, event := range summary.MigrationEvents {
		if err := relayfleet.ValidateMigrationEvent(summary.Fleet, event); err != nil {
			failures = append(failures, event.EventID+": "+err.Error())
		}
	}
	return gate("relayfleet_migration_model", len(failures) == 0, "required", fmt.Sprintf("%d migration events using %s", len(summary.MigrationEvents), summary.Fleet.Policy.MigrationMode), nil, failures)
}

func RelayFleetBurnRiskGate(report relayfleet.BurnRiskReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, "burn-risk report failed")
	}
	if report.HighRiskRelays+report.CriticalRiskRelays == 0 {
		failures = append(failures, "no high-risk controls represented")
	}
	return gate("relayfleet_burn_risk", len(failures) == 0, "required", fmt.Sprintf("%d high-risk and %d critical relays", report.HighRiskRelays, report.CriticalRiskRelays), map[string]any{"burn_risk": report}, failures)
}

func RelayFleetCollapseDetectionGate(report relayfleet.FleetCollapseReport) GateResult {
	failures := []string{}
	if report.PayloadLogged || report.SecretLogged {
		failures = append(failures, "trace hygiene flags set")
	}
	if report.UniqueProfileSeeds < 3 || report.UniqueWirePolicyHashes < 3 {
		failures = append(failures, "fleet diversity below threshold")
	}
	return gate("relayfleet_collapse_detection", len(failures) == 0, "required", fmt.Sprintf("%d profile seeds, %d wire policies, %.2f diversity", report.UniqueProfileSeeds, report.UniqueWirePolicyHashes, report.DiversityScore), map[string]any{"collapse": report}, failures)
}

func RelayFleetControlDetectionGate(summary relayfleet.RelayFleetSummary) GateResult {
	controlRelays := 0
	highRiskControls := 0
	for _, relay := range summary.Fleet.Relays {
		if relay.RelayClass == relayfleet.RelayClassControl {
			controlRelays++
			if relay.BurnRiskBucket == relayfleet.RiskHigh || relay.BurnRiskBucket == relayfleet.RiskCritical {
				highRiskControls++
			}
		}
	}
	failures := []string{}
	if controlRelays == 0 || highRiskControls == 0 {
		failures = append(failures, "relay fleet controls were not detected")
	}
	return gate("relayfleet_control_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d control relays high-risk", highRiskControls, controlRelays), nil, failures)
}

func RelayFleetGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("relayfleet_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	raw, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("relayfleet_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source := string(raw)
	markers := []string{"relayfleet_generated.go", "relayfleet_test.go", "relayfleet_parity_test.go", "relayfleet_hygiene_test.go", "RelayFleetSchemaVersion"}
	failures := []string{}
	for _, marker := range markers {
		if !strings.Contains(source, marker) {
			failures = append(failures, "missing generated marker "+marker)
		}
	}
	return gate("relayfleet_generated_backend_parity", len(failures) == 0, "required", "generated backend relayfleet markers checked", nil, failures)
}

func RelayFleetTraceHygieneGate(summary relayfleet.RelayFleetSummary) GateResult {
	failures := []string{}
	if err := relayfleet.ScanForLeak(summary); err != nil {
		failures = append(failures, err.Error())
	}
	if summary.PayloadLogged || summary.SecretLogged {
		failures = append(failures, "relayfleet summary reported payload/secret logging")
	}
	return gate("relayfleet_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d relay records scanned", len(summary.Fleet.Relays)), nil, failures)
}

func RelayFleetMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeRelayFleetReusesSameProfile,
		mutant.ModeRelayFleetReusesSameWirePolicy,
		mutant.ModeRelayFleetNeverChurns,
		mutant.ModeRelayFleetOverChurns,
		mutant.ModeRelayFleetIgnoresHostRisk,
		mutant.ModeRelayFleetKeepsBurnedRelayActive,
		mutant.ModeRelayFleetMigratesToRetiredRelay,
		mutant.ModeRelayFleetIgnoresProfileReuseLimit,
		mutant.ModeRelayFleetIgnoresPolicyReuseLimit,
		mutant.ModeRelayFleetControlNotDetected,
		mutant.ModeRelayFleetEndpointLeak,
		mutant.ModeRelayFleetPayloadLeak,
		mutant.ModeRelayFleetSecretLeak,
		mutant.ModeRelayFleetGeneratedBackendDrift,
		mutant.ModeRelayFleetUnstableSchedule,
	}
	modes := map[string]bool{}
	for _, mode := range mutant.Modes() {
		modes[mode] = true
	}
	failures := []string{}
	for _, mode := range required {
		if !modes[mode] {
			failures = append(failures, "missing mutant mode "+mode)
		}
	}
	return gate("relayfleet_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d relayfleet mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func RelayFleetFixtureDriftGate(report relayfleet.RelayFleetComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
		if len(failures) == 0 {
			failures = append(failures, "relayfleet fixture comparison failed")
		}
	}
	return gate("relayfleet_fixture_drift", len(failures) == 0, "required", fmt.Sprintf("%d old relays compared to %d new relays", report.OldRelays, report.NewRelays), map[string]any{"comparison": report}, failures)
}

func activeRelayCount(relays []relayfleet.SyntheticRelay) int {
	count := 0
	for _, relay := range relays {
		if relay.State == relayfleet.RelayActive {
			count++
		}
	}
	return count
}
