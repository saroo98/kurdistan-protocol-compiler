// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import (
	"context"

	"kurdistan/internal/hostdetect"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wireeval"
)

type RelayFleetSummary struct {
	Version         string                  `json:"version"`
	Fleet           RelayFleet              `json:"fleet"`
	Assignment      ProfileAssignmentReport `json:"assignment"`
	ChurnEvents     []ChurnEvent            `json:"churn_events"`
	MigrationEvents []MigrationEvent        `json:"migration_events"`
	BurnRisk        BurnRiskReport          `json:"burn_risk"`
	Collapse        FleetCollapseReport     `json:"collapse"`
	Parity          FleetParityReport       `json:"parity"`
	PayloadLogged   bool                    `json:"payload_logged"`
	SecretLogged    bool                    `json:"secret_logged"`
	Conclusion      string                  `json:"conclusion"`
}

func GenerateGoldenSummary(ctx context.Context) (RelayFleetSummary, error) {
	dataset, err := wireeval.BuildDataset(ctx, protocorpus.DefaultCorpus(), wireeval.BuildOptions{
		Seeds:     wireeval.DefaultSeeds(),
		Scenarios: wireeval.DefaultScenarios(),
		Controls:  true,
	})
	if err != nil {
		return RelayFleetSummary{}, err
	}
	hostSummary, err := hostdetect.Run(dataset, hostdetect.DefaultBuildOptions())
	if err != nil {
		return RelayFleetSummary{}, err
	}
	return Run(dataset, hostSummary, DefaultOptions())
}

func Run(dataset wireeval.Dataset, hostSummary hostdetect.HostDetectSummary, opts Options) (RelayFleetSummary, error) {
	opts = NormalizeOptions(opts)
	fleet, err := BuildFleet(dataset, hostSummary, opts)
	if err != nil {
		return RelayFleetSummary{}, err
	}
	assignment := AnalyzeProfileAssignment(fleet)
	churn := GenerateChurnSchedule(fleet)
	migrations := GenerateMigrationEvents(fleet)
	for _, event := range migrations {
		if err := ValidateMigrationEvent(fleet, event); err != nil {
			return RelayFleetSummary{}, err
		}
	}
	risk := ScoreBurnRisk(fleet, churn)
	collapse := ScanCollapse(fleet, assignment, churn, migrations, risk)
	summary := RelayFleetSummary{
		Version:         string(Version),
		Fleet:           fleet,
		Assignment:      assignment,
		ChurnEvents:     churn,
		MigrationEvents: migrations,
		BurnRisk:        risk,
		Collapse:        collapse,
		Conclusion:      "passed",
	}
	summary.PayloadLogged = fleet.PayloadLogged || assignment.PayloadLogged || risk.PayloadLogged || collapse.PayloadLogged
	summary.SecretLogged = fleet.SecretLogged || assignment.SecretLogged || risk.SecretLogged || collapse.SecretLogged
	summary.Parity = CompareFleets(summary, summary)
	if assignment.Conclusion != "passed" || risk.Conclusion != "passed" || summary.PayloadLogged || summary.SecretLogged {
		summary.Conclusion = "failed"
	}
	return summary, ValidateSummary(summary)
}
