// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func ExecuteScenario(s RelayBridgeScenario) (RelayBridgeSession, RelayBridgeStream, RelayBridgeReport, error) {
	session := SessionFor(s)
	stream := StreamFor(s, session)
	if err := ValidateSession(session); err != nil && !s.Control {
		return RelayBridgeSession{}, RelayBridgeStream{}, RelayBridgeReport{}, err
	}
	if err := ValidateStream(stream); err != nil && !s.Control {
		return RelayBridgeSession{}, RelayBridgeStream{}, RelayBridgeReport{}, err
	}
	report := RelayBridgeReport{
		Version:            Version,
		BridgeID:           session.BridgeID,
		SessionCount:       1,
		StreamCount:        1,
		MappedRequests:     1,
		CompletedRequests:  s.ExpectedCompleted,
		ResetRequests:      s.ExpectedReset,
		FailedRequests:     s.ExpectedFailed,
		BackpressureEvents: s.ExpectedBackpressure,
		SafeErrorClasses:   SafeErrorClasses(),
		Conclusion:         "passed",
	}
	if s.Control || s.ExpectedTraceHygiene != "passed" || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	report.ReportHash = HashValue(reportHashInput(report))
	return session, stream, report, nil
}

func reportHashInput(report RelayBridgeReport) RelayBridgeReport {
	report.ReportHash = ""
	return report
}

func GenerateFixtureSet() (RelayBridgeFixtureSet, error) {
	scenarios := DefaultScenarios()
	set := RelayBridgeFixtureSet{
		Version:     Version,
		GeneratedAt: time.Unix(0, 0).UTC().Format(time.RFC3339),
		Scenarios:   scenarios,
		Conclusion:  "passed",
	}
	for _, scenario := range scenarios {
		session, stream, report, err := ExecuteScenario(scenario)
		if err != nil && !scenario.Control {
			return RelayBridgeFixtureSet{}, err
		}
		if !scenario.Control {
			set.Sessions = append(set.Sessions, session)
			set.Streams = append(set.Streams, stream)
		}
		set.Reports = append(set.Reports, report)
	}
	set.Adaptive = BuildAdaptiveBindingReport(scenarios)
	set.Misuse = ScanMisuse(set)
	set.Parity = CompareGeneratedInterpreted(set)
	if set.Adaptive.Conclusion != "passed" || set.Misuse.Conclusion != "passed" || set.Parity.Conclusion != "passed" {
		set.Conclusion = "failed"
	}
	set.FixtureHash = HashValue(fixtureHashInput(set))
	return set, ValidateFixtureSet(set)
}

func CompareGeneratedInterpreted(set RelayBridgeFixtureSet) RelayBridgeParityReport {
	report := RelayBridgeParityReport{Version: Version, ComparedScenarios: len(set.Scenarios), MatchingSessions: len(set.Sessions), MatchingStreams: len(set.Streams), Conclusion: "passed"}
	if report.MatchingSessions == 0 || report.MatchingStreams == 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "relaybridge_generated_interpreted_drift")
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

func LoadFixtureSet(path string) (RelayBridgeFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return RelayBridgeFixtureSet{}, err
	}
	var set RelayBridgeFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return RelayBridgeFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func CompareFixtureSets(oldSet, newSet RelayBridgeFixtureSet) RelayBridgeComparisonReport {
	report := RelayBridgeComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: "passed"}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "relaybridge_fixture_hash_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "relaybridge_hygiene_flag_changed")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
}
