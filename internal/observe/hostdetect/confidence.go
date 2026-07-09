// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

type ConfidenceModel struct {
	Name                  string  `json:"name"`
	MinObservations       int     `json:"min_observations"`
	DominantShareCutoff   float64 `json:"dominant_share_cutoff"`
	EntropyCutoff         float64 `json:"entropy_cutoff"`
	GeneratedPenalty      float64 `json:"generated_penalty"`
	BaselineTolerance     float64 `json:"baseline_tolerance"`
	RejectBelowConfidence bool    `json:"reject_below_confidence"`
}

func DefaultConfidenceModel() ConfidenceModel {
	return ConfidenceModel{
		Name:                  "deterministic-consistency-v1",
		MinObservations:       3,
		DominantShareCutoff:   0.82,
		EntropyCutoff:         0.35,
		GeneratedPenalty:      0.05,
		BaselineTolerance:     0.1,
		RejectBelowConfidence: true,
	}
}

func ScoreHost(aggregate HostAggregate, model ConfidenceModel) HostConfidence {
	if model.Name == "" {
		model = DefaultConfidenceModel()
	}
	conf := HostConfidence{
		SyntheticHostID:  string(aggregate.SyntheticHostID),
		ObservationCount: aggregate.ObservationCount,
		ConsistencyScore: aggregate.ConsistencyScore,
		EntropyScore:     1 - aggregate.ConsistencyScore,
		ConfidenceScore:  aggregate.ConsistencyScore,
		EvidenceBuckets:  []string{aggregate.RiskBucket},
	}
	if aggregate.ObservationCount < model.MinObservations {
		conf.RejectReason = "insufficient_observations"
		return conf
	}
	if aggregate.HostClass == HostClassGeneratedRelay {
		conf.ConfidenceScore -= model.GeneratedPenalty
	}
	if aggregate.HostClass == HostClassCorpusBaseline {
		conf.ConfidenceScore -= model.BaselineTolerance
	}
	if aggregate.HostClass == HostClassControlFixed || aggregate.HostClass == HostClassControlPadding {
		conf.ConfidenceScore += 0.1
	}
	conf.Flagged = conf.ConfidenceScore >= model.DominantShareCutoff || conf.EntropyScore <= model.EntropyCutoff
	if !conf.Flagged && model.RejectBelowConfidence {
		conf.RejectReason = "below_confidence"
	}
	return conf
}
