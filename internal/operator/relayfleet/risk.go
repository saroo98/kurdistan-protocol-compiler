// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

type BurnRiskReport struct {
	Version                  string `json:"version"`
	FleetID                  string `json:"fleet_id"`
	RelayCount               int    `json:"relay_count"`
	ActiveRelays             int    `json:"active_relays"`
	LowRiskRelays            int    `json:"low_risk_relays"`
	MediumRiskRelays         int    `json:"medium_risk_relays"`
	HighRiskRelays           int    `json:"high_risk_relays"`
	CriticalRiskRelays       int    `json:"critical_risk_relays"`
	BurnedRelays             int    `json:"burned_relays"`
	QuarantinedRelays        int    `json:"quarantined_relays"`
	RiskTriggeredChurnEvents int    `json:"risk_triggered_churn_events"`
	AvgRelayAgeBucket        string `json:"avg_relay_age_bucket"`
	AvgObservationBucket     string `json:"avg_observation_bucket"`
	PayloadLogged            bool   `json:"payload_logged"`
	SecretLogged             bool   `json:"secret_logged"`
	Conclusion               string `json:"conclusion"`
}

func ScoreBurnRisk(fleet RelayFleet, churn []ChurnEvent) BurnRiskReport {
	report := BurnRiskReport{Version: string(Version), FleetID: fleet.FleetID, RelayCount: len(fleet.Relays), Conclusion: "passed"}
	totalAge := 0
	totalObs := 0
	for _, relay := range fleet.Relays {
		switch relay.BurnRiskBucket {
		case RiskLow:
			report.LowRiskRelays++
		case RiskMedium:
			report.MediumRiskRelays++
		case RiskHigh:
			report.HighRiskRelays++
		case RiskCritical:
			report.CriticalRiskRelays++
		default:
			report.HighRiskRelays++
		}
		if relay.State == RelayActive {
			report.ActiveRelays++
		}
		if relay.State == RelayBurned {
			report.BurnedRelays++
		}
		if relay.State == RelayQuarantined {
			report.QuarantinedRelays++
		}
		totalAge += max(0, relay.ActivatedAtTick-relay.CreatedAtTick)
		totalObs += relay.ObservationCount
		report.PayloadLogged = report.PayloadLogged || relay.PayloadLogged
		report.SecretLogged = report.SecretLogged || relay.SecretLogged
	}
	for _, event := range churn {
		if event.ReasonBucket == "risk_threshold" {
			report.RiskTriggeredChurnEvents++
		}
	}
	report.AvgRelayAgeBucket = bucket(totalAge, len(fleet.Relays))
	report.AvgObservationBucket = bucket(totalObs, len(fleet.Relays))
	if report.ActiveRelays > fleet.Policy.MaxActiveRelays || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func bucket(total, count int) string {
	if count == 0 {
		return "zero"
	}
	avg := total / count
	switch {
	case avg == 0:
		return "zero"
	case avg <= 3:
		return "small"
	case avg <= 8:
		return "medium"
	default:
		return "large"
	}
}
