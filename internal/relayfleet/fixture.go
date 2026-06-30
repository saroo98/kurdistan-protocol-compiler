// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import (
	"context"
	"encoding/json"
	"os"
)

func LoadFleet(path string) (RelayFleet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return RelayFleet{}, err
	}
	var fleet RelayFleet
	if err := json.Unmarshal(raw, &fleet); err != nil {
		return RelayFleet{}, err
	}
	return fleet, ValidateFleet(fleet)
}

func WriteFleet(path string, fleet RelayFleet, force bool) error {
	if err := ValidateFleet(fleet); err != nil {
		return err
	}
	return WriteJSON(path, fleet, force)
}

func CompareFleetsOnly(oldFleet, newFleet RelayFleet) RelayFleetComparisonReport {
	report := RelayFleetComparisonReport{Version: string(Version), OldRelays: len(oldFleet.Relays), NewRelays: len(newFleet.Relays), Conclusion: "passed"}
	oldMap := map[RelayID]SyntheticRelay{}
	newMap := map[RelayID]SyntheticRelay{}
	for _, relay := range oldFleet.Relays {
		oldMap[relay.RelayID] = relay
		report.PayloadLogged = report.PayloadLogged || relay.PayloadLogged
		report.SecretLogged = report.SecretLogged || relay.SecretLogged
	}
	for _, relay := range newFleet.Relays {
		newMap[relay.RelayID] = relay
		report.PayloadLogged = report.PayloadLogged || relay.PayloadLogged
		report.SecretLogged = report.SecretLogged || relay.SecretLogged
	}
	for id, oldRelay := range oldMap {
		newRelay, ok := newMap[id]
		if !ok {
			report.Removed++
			report.UnexpectedDrift = append(report.UnexpectedDrift, "removed:"+string(id))
			continue
		}
		if HashValue(oldRelay) != HashValue(newRelay) {
			report.Changed++
			report.UnexpectedDrift = append(report.UnexpectedDrift, "changed:"+string(id))
		}
	}
	for id := range newMap {
		if _, ok := oldMap[id]; !ok {
			report.Added++
			report.UnexpectedDrift = append(report.UnexpectedDrift, "added:"+string(id))
		}
	}
	if report.Added > 0 || report.Removed > 0 || report.Changed > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func VerifyFleet(ctx context.Context, path string) (RelayFleetComparisonReport, error) {
	_ = ctx
	oldFleet, err := LoadFleet(path)
	if err != nil {
		return RelayFleetComparisonReport{Version: string(Version), Conclusion: "failed"}, err
	}
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		return RelayFleetComparisonReport{Version: string(Version), Conclusion: "failed"}, err
	}
	report := CompareFleetsOnly(oldFleet, summary.Fleet)
	if report.Conclusion != "passed" {
		return report, ErrInvalidReport
	}
	return report, nil
}
