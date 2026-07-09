// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

type HostConfidence struct {
	SyntheticHostID  string   `json:"synthetic_host_id"`
	ObservationCount int      `json:"observation_count"`
	ConfidenceScore  float64  `json:"confidence_score"`
	ConsistencyScore float64  `json:"consistency_score"`
	EntropyScore     float64  `json:"entropy_score"`
	Flagged          bool     `json:"flagged"`
	RejectReason     string   `json:"reject_reason,omitempty"`
	EvidenceBuckets  []string `json:"evidence_buckets,omitempty"`
}

type HostDetectionReport struct {
	Version               string            `json:"version"`
	HostCount             int               `json:"host_count"`
	ObservationCount      int               `json:"observation_count"`
	Window                ObservationWindow `json:"window"`
	Threshold             string            `json:"threshold"`
	HostsFlagged          int               `json:"hosts_flagged"`
	GeneratedHostsFlagged int               `json:"generated_hosts_flagged"`
	ControlHostsFlagged   int               `json:"control_hosts_flagged"`
	BaselineHostsFlagged  int               `json:"baseline_hosts_flagged"`
	FalsePositiveEstimate float64           `json:"false_positive_estimate"`
	FalseNegativeEstimate float64           `json:"false_negative_estimate"`
	PrecisionEstimate     float64           `json:"precision_estimate"`
	RecallEstimate        float64           `json:"recall_estimate"`
	HighRiskHosts         []string          `json:"high_risk_hosts,omitempty"`
	PayloadLogged         bool              `json:"payload_logged"`
	SecretLogged          bool              `json:"secret_logged"`
	Conclusion            string            `json:"conclusion"`
}

type HostResistanceReport struct {
	Version                 string   `json:"version"`
	HostCount               int      `json:"host_count"`
	GeneratedHostCount      int      `json:"generated_host_count"`
	ObservationCount        int      `json:"observation_count"`
	AvgObservationsPerHost  float64  `json:"avg_observations_per_host"`
	AvgUniqueFeatureHashes  float64  `json:"avg_unique_feature_hashes"`
	AvgUniqueFirstNShapes   float64  `json:"avg_unique_first_n_shapes"`
	AvgConsistencyScore     float64  `json:"avg_consistency_score"`
	AvgRotationScore        float64  `json:"avg_rotation_score"`
	HighRiskGeneratedHosts  int      `json:"high_risk_generated_hosts"`
	ControlCollapseDetected bool     `json:"control_collapse_detected"`
	PaddingOnlyDetected     bool     `json:"padding_only_detected"`
	RecommendedNextActions  []string `json:"recommended_next_actions,omitempty"`
	PayloadLogged           bool     `json:"payload_logged"`
	SecretLogged            bool     `json:"secret_logged"`
	Conclusion              string   `json:"conclusion"`
}

type HostCollapseReport struct {
	HostCount                int      `json:"host_count"`
	ObservationCount         int      `json:"observation_count"`
	UniqueFeatureHashes      int      `json:"unique_feature_hashes"`
	UniqueFirstNShapes       int      `json:"unique_first_n_shapes"`
	HighConsistencyHosts     int      `json:"high_consistency_hosts"`
	PaddingOnlyHosts         int      `json:"padding_only_hosts"`
	CollapsedControlDetected bool     `json:"collapsed_control_detected"`
	SuspiciousMetrics        []string `json:"suspicious_metrics,omitempty"`
	DiversityScore           float64  `json:"diversity_score"`
	PayloadLogged            bool     `json:"payload_logged"`
	SecretLogged             bool     `json:"secret_logged"`
	Conclusion               string   `json:"conclusion"`
}

type HostDetectComparisonReport struct {
	Version         string   `json:"version"`
	OldObservations int      `json:"old_observations"`
	NewObservations int      `json:"new_observations"`
	Added           int      `json:"added"`
	Removed         int      `json:"removed"`
	Changed         int      `json:"changed"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

type HostDetectSummary struct {
	Version        string               `json:"version"`
	ObservationSet HostObservationSet   `json:"observation_set"`
	Aggregates     []HostAggregate      `json:"aggregates"`
	Detection      HostDetectionReport  `json:"detection"`
	Resistance     HostResistanceReport `json:"resistance"`
	Collapse       HostCollapseReport   `json:"collapse"`
	PayloadLogged  bool                 `json:"payload_logged"`
	SecretLogged   bool                 `json:"secret_logged"`
	Conclusion     string               `json:"conclusion"`
}
