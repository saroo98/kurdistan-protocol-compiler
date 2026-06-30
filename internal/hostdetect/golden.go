// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import (
	"context"

	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wireeval"
)

func GenerateGoldenSummary(ctx context.Context) (HostDetectSummary, error) {
	dataset, err := wireeval.BuildDataset(ctx, protocorpus.DefaultCorpus(), wireeval.BuildOptions{
		Seeds:     wireeval.DefaultSeeds(),
		Scenarios: wireeval.DefaultScenarios(),
		Controls:  true,
	})
	if err != nil {
		return HostDetectSummary{}, err
	}
	return Run(dataset, DefaultBuildOptions())
}

func Run(dataset wireeval.Dataset, opts BuildOptions) (HostDetectSummary, error) {
	set, err := BuildObservations(dataset, opts)
	if err != nil {
		return HostDetectSummary{}, err
	}
	aggregates := Aggregate(set.Observations)
	detection := Detect(aggregates, set.Window, DefaultConfidenceModel())
	resistance := Resistance(aggregates)
	collapse := Collapse(aggregates)
	summary := HostDetectSummary{
		Version:        string(Version),
		ObservationSet: set,
		Aggregates:     aggregates,
		Detection:      detection,
		Resistance:     resistance,
		Collapse:       collapse,
		PayloadLogged:  set.PayloadLogged || detection.PayloadLogged || resistance.PayloadLogged || collapse.PayloadLogged,
		SecretLogged:   set.SecretLogged || detection.SecretLogged || resistance.SecretLogged || collapse.SecretLogged,
		Conclusion:     "passed",
	}
	if detection.Conclusion != "passed" || resistance.Conclusion != "passed" || collapse.Conclusion != "passed" || summary.PayloadLogged || summary.SecretLogged {
		summary.Conclusion = "failed"
	}
	return summary, ValidateSummary(summary)
}
