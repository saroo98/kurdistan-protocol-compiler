// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

const (
	Version                  = "measurementreview-v1"
	RecommendedNextMilestone = "M33: local proxy egress and relay bridge model"
)

const (
	ObservationPathAvailabilityBucket     = "path_availability_bucket"
	ObservationHandshakeOutcomeBucket     = "handshake_outcome_bucket"
	ObservationFirstUsefulByteBucket      = "first_useful_byte_bucket"
	ObservationStallPatternBucket         = "stall_pattern_bucket"
	ObservationResetLikeFailureBucket     = "reset_like_failure_bucket"
	ObservationBlackholeLikeFailureBucket = "blackhole_like_failure_bucket"
	ObservationDNSPoisoningLikeBucket     = "dns_poisoning_like_bucket"
	ObservationDNSTruncationLikeBucket    = "dns_truncation_like_bucket"
	ObservationDNSRateLimitLikeBucket     = "dns_rate_limit_like_bucket"
	ObservationRelayBurnLikeBucket        = "relay_burn_like_bucket"
	ObservationCarrierFamilyBucket        = "carrier_family_bucket"
	ObservationBundleCandidateBucket      = "bundle_candidate_bucket"
	ObservationScoreBucket                = "score_bucket"
	ObservationHealthStateBucket          = "health_state_bucket"
	ObservationFailoverOutcomeBucket      = "failover_outcome_bucket"
	ObservationCoarsePlatformClass        = "coarse_platform_class"
	ObservationCoarseNetworkClass         = "coarse_network_class"
	ObservationCoarseTimeBucket           = "coarse_time_bucket"
)

const (
	RedactionDrop                 = "drop"
	RedactionBucket               = "bucket"
	RedactionHashWithLocalSalt    = "hash_with_local_salt"
	RedactionAggregateOnly        = "aggregate_only"
	RedactionManualReviewRequired = "manual_review_required"
	RedactionRejected             = "rejected"
)

const (
	ConsentDisabled         = "disabled"
	ConsentLocalOnly        = "local_only"
	ConsentExplicitOptIn    = "explicit_opt_in"
	ConsentAggregateOptIn   = "aggregate_opt_in"
	ConsentManualExportOnly = "manual_export_only"
	ConsentRejectedUnsafe   = "rejected_unsafe"
)

const (
	RetentionNone             = "none"
	RetentionSessionOnly      = "session_only"
	RetentionShortLocal       = "short_local"
	RetentionAggregateOnly    = "aggregate_only"
	RetentionManualExportOnly = "manual_export_only"
	RetentionRejected         = "rejected"
)

type ObservationField struct {
	Name             string `json:"name"`
	Class            string `json:"class"`
	RedactionClass   string `json:"redaction_class"`
	RetentionClass   string `json:"retention_class"`
	AllowedInFixture bool   `json:"allowed_in_fixture"`
}

type MeasurementPrivacyPolicy struct {
	ConsentMode                string   `json:"consent_mode"`
	RetentionClass             string   `json:"retention_class"`
	LocalDiagnosticsOnly       bool     `json:"local_diagnostics_only"`
	BackgroundCollection       bool     `json:"background_collection"`
	ManualExportRequiresReview bool     `json:"manual_export_requires_review"`
	AllowedObservationClasses  []string `json:"allowed_observation_classes"`
	RejectedObservationClasses []string `json:"rejected_observation_classes"`
}

type LocalDiagnosticReport struct {
	Version          string         `json:"version"`
	ReportID         string         `json:"report_id"`
	ObservationCount int            `json:"observation_count"`
	FieldCount       int            `json:"field_count"`
	BucketCounts     map[string]int `json:"bucket_counts"`
	ConsentMode      string         `json:"consent_mode"`
	RetentionClass   string         `json:"retention_class"`
	LocalOnly        bool           `json:"local_only"`
	PayloadLogged    bool           `json:"payload_logged"`
	SecretLogged     bool           `json:"secret_logged"`
	ReportHash       string         `json:"report_hash"`
	Conclusion       string         `json:"conclusion"`
}

type MeasurementReviewMatrix struct {
	Layers map[string]string `json:"layers"`
}

type MeasurementReview struct {
	Version       string                     `json:"version"`
	ReviewID      string                     `json:"review_id"`
	Fields        []ObservationField         `json:"fields"`
	Policy        MeasurementPrivacyPolicy   `json:"policy"`
	Diagnostics   LocalDiagnosticReport      `json:"diagnostics"`
	Matrix        MeasurementReviewMatrix    `json:"matrix"`
	Misuse        MeasurementMisuseReport    `json:"misuse"`
	Parity        MeasurementParityReport    `json:"parity"`
	Readiness     MeasurementReadinessReport `json:"readiness"`
	PayloadLogged bool                       `json:"payload_logged"`
	SecretLogged  bool                       `json:"secret_logged"`
	ReviewHash    string                     `json:"review_hash"`
	Conclusion    string                     `json:"conclusion"`
}

type MeasurementReadinessReport struct {
	FieldsChecked            int      `json:"fields_checked"`
	BucketedFields           int      `json:"bucketed_fields"`
	RejectedUnsafeFields     int      `json:"rejected_unsafe_fields"`
	BlockingIssues           []string `json:"blocking_issues,omitempty"`
	RecommendedNextMilestone string   `json:"recommended_next_milestone"`
	Conclusion               string   `json:"conclusion"`
}

type MeasurementMisuseReport struct {
	FieldsChecked     int      `json:"fields_checked"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
	Conclusion        string   `json:"conclusion"`
}

type MeasurementParityReport struct {
	ComparedFields        int      `json:"compared_fields"`
	RedactionMatches      int      `json:"redaction_matches"`
	RetentionMatches      int      `json:"retention_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type MeasurementReviewComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}
