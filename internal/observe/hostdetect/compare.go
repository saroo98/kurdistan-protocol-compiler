// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import "context"

func CompareObservationSets(oldSet, newSet HostObservationSet) HostDetectComparisonReport {
	report := HostDetectComparisonReport{Version: string(Version), OldObservations: len(oldSet.Observations), NewObservations: len(newSet.Observations), Conclusion: "passed"}
	oldMap := map[string]HostObservation{}
	newMap := map[string]HostObservation{}
	for _, observation := range oldSet.Observations {
		oldMap[observation.ObservationID] = observation
		report.PayloadLogged = report.PayloadLogged || observation.PayloadLogged
		report.SecretLogged = report.SecretLogged || observation.SecretLogged
	}
	for _, observation := range newSet.Observations {
		newMap[observation.ObservationID] = observation
		report.PayloadLogged = report.PayloadLogged || observation.PayloadLogged
		report.SecretLogged = report.SecretLogged || observation.SecretLogged
	}
	for id, oldObservation := range oldMap {
		newObservation, ok := newMap[id]
		if !ok {
			report.Removed++
			report.UnexpectedDrift = append(report.UnexpectedDrift, "removed:"+id)
			continue
		}
		if HashValue(oldObservation) != HashValue(newObservation) {
			report.Changed++
			report.UnexpectedDrift = append(report.UnexpectedDrift, "changed:"+id)
		}
	}
	for id := range newMap {
		if _, ok := oldMap[id]; !ok {
			report.Added++
			report.UnexpectedDrift = append(report.UnexpectedDrift, "added:"+id)
		}
	}
	if len(report.UnexpectedDrift) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func VerifyObservationSet(ctx context.Context, path string) (HostDetectComparisonReport, error) {
	_ = ctx
	oldSet, err := LoadObservationSet(path)
	if err != nil {
		return HostDetectComparisonReport{Version: string(Version), Conclusion: "failed"}, err
	}
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		return HostDetectComparisonReport{Version: string(Version), Conclusion: "failed"}, err
	}
	report := CompareObservationSets(oldSet, summary.ObservationSet)
	if report.Conclusion != "passed" {
		return report, ErrInvalidReport
	}
	return report, nil
}
