// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

import "context"

type AdaptivePathFixtureSet struct {
	Version          string                      `json:"version"`
	Families         []CandidateFamilyDescriptor `json:"families"`
	Conditions       []SyntheticPathCondition    `json:"conditions"`
	Candidates       []PathCandidate             `json:"candidates"`
	Observations     []PathObservation           `json:"observations"`
	Freshness        FreshnessReport             `json:"freshness"`
	ViabilityReports []CandidateViabilityReport  `json:"viability_reports"`
	DecisionInputs   CandidateDecisionSet        `json:"decision_inputs"`
	MisuseReport     AdaptivePathMisuseReport    `json:"misuse_report"`
	CollapsedControl AdaptivePathMisuseReport    `json:"collapsed_control"`
	Parity           AdaptivePathParityReport    `json:"parity"`
	PayloadLogged    bool                        `json:"payload_logged"`
	SecretLogged     bool                        `json:"secret_logged"`
	FixtureSetHash   string                      `json:"fixture_set_hash"`
}

type AdaptivePathComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

func GenerateFixtureSet(ctx context.Context) (AdaptivePathFixtureSet, error) {
	_ = ctx
	candidates := DefaultCandidates()
	observations := DefaultObservations(candidates)
	set := AdaptivePathFixtureSet{
		Version:          string(Version),
		Families:         FamilyDescriptors(),
		Conditions:       DefaultConditions(),
		Candidates:       candidates,
		Observations:     observations,
		Freshness:        SummarizeFreshness(observations),
		ViabilityReports: EvaluateAll(candidates, observations),
		DecisionInputs:   BuildDecisionSet(candidates, observations),
		MisuseReport:     ScanMisuse(candidates, observations, nil),
		CollapsedControl: CollapsedControlReport(candidates, observations),
		Parity:           CompareGeneratedInterpreted(candidates, observations),
	}
	set.FixtureSetHash = HashValue(fixtureSetHashInput(set))
	return set, ValidateFixtureSet(set)
}

func fixtureSetHashInput(set AdaptivePathFixtureSet) AdaptivePathFixtureSet {
	set.FixtureSetHash = ""
	return set
}

func CompareFixtureSets(oldSet, newSet AdaptivePathFixtureSet) AdaptivePathComparisonReport {
	report := AdaptivePathComparisonReport{Version: string(Version), OldHash: oldSet.FixtureSetHash, NewHash: newSet.FixtureSetHash, Conclusion: "passed"}
	if err := ValidateFixtureSet(oldSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if err := ValidateFixtureSet(newSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if oldSet.FixtureSetHash != newSet.FixtureSetHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.PayloadLogged || newSet.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload_logged")
	}
	if oldSet.SecretLogged || newSet.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret_logged")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
}
