// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

const (
	FreshSeconds = "fresh_seconds"
	FreshShort   = "fresh_short"
	StaleShort   = "stale_short"
	StaleMedium  = "stale_medium"
	Expired      = "expired"
	FreshUnknown = "unknown"
)

const (
	TTLSeconds      = "ttl_seconds"
	TTLOneMinute    = "ttl_one_minute"
	TTLFiveMinutes  = "ttl_five_minutes"
	TTLShortSession = "ttl_short_session"
	TTLExpired      = "ttl_expired"
)

type FreshnessPolicy struct {
	PolicyID         string `json:"policy_id"`
	SuccessTTLClass  string `json:"success_ttl_class"`
	FailureTTLClass  string `json:"failure_ttl_class"`
	VolatileTTLClass string `json:"volatile_ttl_class"`
	HighRiskTTLClass string `json:"high_risk_ttl_class"`
	ExpiryBehavior   string `json:"expiry_behavior"`
}

type FreshnessReport struct {
	ObservationCount    int    `json:"observation_count"`
	FreshObservations   int    `json:"fresh_observations"`
	StaleObservations   int    `json:"stale_observations"`
	ExpiredObservations int    `json:"expired_observations"`
	UncertaintyBucket   string `json:"uncertainty_bucket"`
	PayloadLogged       bool   `json:"payload_logged"`
	SecretLogged        bool   `json:"secret_logged"`
	Conclusion          string `json:"conclusion"`
}

func DefaultFreshnessPolicy() FreshnessPolicy {
	return FreshnessPolicy{
		PolicyID:         "adaptivepath_freshness_policy_v1",
		SuccessTTLClass:  TTLShortSession,
		FailureTTLClass:  TTLSeconds,
		VolatileTTLClass: TTLSeconds,
		HighRiskTTLClass: TTLExpired,
		ExpiryBehavior:   "stale_success_never_strong",
	}
}

func FreshnessAtTick(observationTick int, ttlClass string, currentTick int) string {
	if ttlClass == TTLExpired || currentTick < observationTick {
		return Expired
	}
	age := currentTick - observationTick
	switch ttlClass {
	case TTLSeconds:
		if age <= 3 {
			return FreshSeconds
		}
		if age <= 8 {
			return StaleShort
		}
		return Expired
	case TTLOneMinute:
		if age <= 10 {
			return FreshShort
		}
		if age <= 25 {
			return StaleMedium
		}
		return Expired
	case TTLFiveMinutes, TTLShortSession:
		if age <= 20 {
			return FreshShort
		}
		if age <= 50 {
			return StaleMedium
		}
		return Expired
	default:
		return FreshUnknown
	}
}

func SummarizeFreshness(observations []PathObservation) FreshnessReport {
	report := FreshnessReport{ObservationCount: len(observations), Conclusion: "passed"}
	failures := 0
	for _, obs := range observations {
		switch obs.FreshnessClass {
		case FreshSeconds, FreshShort:
			report.FreshObservations++
		case StaleShort, StaleMedium:
			report.StaleObservations++
		case Expired:
			report.ExpiredObservations++
		default:
			failures++
		}
		if isFailureObservation(obs.Kind) {
			failures++
		}
	}
	report.UncertaintyBucket = UncertaintyBucket(report.FreshObservations, failures, report.ExpiredObservations)
	if report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}
