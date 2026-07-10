// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import (
	"context"
	"encoding/json"
	"os"
)

type FixtureSet struct {
	Version        string                     `json:"version"`
	Scenarios      []string                   `json:"scenarios"`
	Summaries      []LocalProxyIngressSummary `json:"summaries"`
	Backpressure   BackpressureReport         `json:"backpressure"`
	ErrorReset     ErrorResetReport           `json:"error_reset"`
	PayloadLogged  bool                       `json:"payload_logged"`
	SecretLogged   bool                       `json:"secret_logged"`
	FixtureSetHash string                     `json:"fixture_set_hash"`
}

func GenerateFixtureSet(ctx context.Context, scenarios []string) (FixtureSet, error) {
	if len(scenarios) == 0 {
		scenarios = QuickScenarios()
	}
	set := FixtureSet{Version: string(Version), Scenarios: append([]string(nil), scenarios...)}
	cfg := DefaultConfig()
	for _, scenario := range scenarios {
		summary, err := RunScenario(ctx, scenario, cfg)
		if err != nil {
			return FixtureSet{}, err
		}
		set.Summaries = append(set.Summaries, summary)
		set.PayloadLogged = set.PayloadLogged || summary.PayloadLogged
		set.SecretLogged = set.SecretLogged || summary.SecretLogged
	}
	for _, summary := range set.Summaries {
		if summary.Scenario == ScenarioBackpressurePressure {
			set.Backpressure = BackpressureFromSummary(summary, summary.QueueStats)
		}
		if summary.Scenario == ScenarioResetMidRequest || summary.Scenario == ScenarioTargetErrorAfterOpen {
			set.ErrorReset = ErrorResetFromSummary(summary)
		}
	}
	set.FixtureSetHash = HashValue(struct {
		Version   string                     `json:"version"`
		Scenarios []string                   `json:"scenarios"`
		Summaries []LocalProxyIngressSummary `json:"summaries"`
	}{set.Version, set.Scenarios, set.Summaries})
	return set, ValidateFixtureSet(set)
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != string(Version) || set.PayloadLogged || set.SecretLogged || len(set.Summaries) == 0 {
		return ErrInvalidSummary
	}
	for _, summary := range set.Summaries {
		if err := ValidateSummary(summary); err != nil {
			return err
		}
	}
	return nil
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

func CompareFixtureSets(oldSet, newSet FixtureSet) ComparisonReport {
	report := ComparisonReport{Version: string(Version), OldHash: oldSet.FixtureSetHash, NewHash: newSet.FixtureSetHash, Conclusion: "passed"}
	if oldSet.FixtureSetHash != newSet.FixtureSetHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_set_hash")
		report.Conclusion = "failed"
	}
	if len(oldSet.Summaries) != len(newSet.Summaries) {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "summary_count")
		report.Conclusion = "failed"
	}
	return report
}

type ComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	Conclusion      string   `json:"conclusion"`
}
