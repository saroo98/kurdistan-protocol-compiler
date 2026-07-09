// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

func DefaultPrivacyPolicy(fields []ObservationField) MeasurementPrivacyPolicy {
	return MeasurementPrivacyPolicy{
		ConsentMode:                ConsentLocalOnly,
		RetentionClass:             RetentionSessionOnly,
		LocalDiagnosticsOnly:       true,
		BackgroundCollection:       false,
		ManualExportRequiresReview: true,
		AllowedObservationClasses:  ObservationNames(fields),
		RejectedObservationClasses: []string{
			"raw_payload",
			"raw_packet",
			"exact_destination",
			"dns_query",
			"resolver_ip",
			"precise_location",
			"subscriber_or_device_identifier",
			"secret_material",
		},
	}
}

func AllowedRedactionClasses() []string {
	return []string{RedactionDrop, RedactionBucket, RedactionHashWithLocalSalt, RedactionAggregateOnly, RedactionManualReviewRequired, RedactionRejected}
}

func AllowedConsentModes() []string {
	return []string{ConsentDisabled, ConsentLocalOnly, ConsentExplicitOptIn, ConsentAggregateOptIn, ConsentManualExportOnly, ConsentRejectedUnsafe}
}

func AllowedRetentionClasses() []string {
	return []string{RetentionNone, RetentionSessionOnly, RetentionShortLocal, RetentionAggregateOnly, RetentionManualExportOnly, RetentionRejected}
}
