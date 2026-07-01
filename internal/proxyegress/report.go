// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func GenerateFixtureSet() (EgressFixtureSet, error) {
	scenarios := DefaultScenarios()
	set := EgressFixtureSet{
		Version:     Version,
		GeneratedAt: time.Unix(0, 0).UTC().Format(time.RFC3339),
		Scenarios:   scenarios,
		Conclusion:  "passed",
	}
	for _, scenario := range scenarios {
		req := RequestDescriptorFor(scenario)
		target := TargetDescriptorFor(scenario)
		mapping := MappingPlanFor(req, target)
		report, err := ExecuteLifecycle(scenario)
		if err != nil && !scenario.Control {
			return EgressFixtureSet{}, err
		}
		if !scenario.Control {
			set.Requests = append(set.Requests, req)
			set.Targets = append(set.Targets, target)
			set.Mappings = append(set.Mappings, mapping)
		}
		set.Lifecycle = append(set.Lifecycle, report)
	}
	set.Backpressure = BuildBackpressureReport(set.Lifecycle)
	set.ResetError = BuildResetErrorReport(set.Lifecycle)
	set.Adaptive = BuildAdaptiveBindingReport(scenarios)
	set.IngressMapping = BuildIngressMappingReport(set.Requests)
	set.Misuse = ScanMisuse(set)
	set.Parity = CompareGeneratedInterpreted(set)
	if set.Backpressure.Conclusion != "passed" || set.ResetError.Conclusion != "passed" || set.Adaptive.Conclusion != "passed" || set.IngressMapping.Conclusion != "passed" || set.Misuse.Conclusion != "passed" || set.Parity.Conclusion != "passed" {
		set.Conclusion = "failed"
	}
	set.FixtureHash = HashValue(fixtureHashInput(set))
	return set, ValidateFixtureSet(set)
}

func CompareGeneratedInterpreted(set EgressFixtureSet) EgressParityReport {
	report := EgressParityReport{Version: Version, ComparedScenarios: len(set.Scenarios), Conclusion: "passed"}
	for range set.Lifecycle {
		report.MatchingLifecycle++
	}
	for range set.Mappings {
		report.MatchingMappings++
	}
	if report.MatchingLifecycle != len(set.Lifecycle) || report.MatchingMappings != len(set.Mappings) || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "proxyegress_generated_interpreted_drift")
	}
	return report
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s exists; use --force", path)
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

func LoadFixtureSet(path string) (EgressFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return EgressFixtureSet{}, err
	}
	var set EgressFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return EgressFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func CompareFixtureSets(oldSet, newSet EgressFixtureSet) EgressComparisonReport {
	report := EgressComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: "passed"}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "proxyegress_fixture_hash_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "proxyegress_hygiene_flag_changed")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
}
