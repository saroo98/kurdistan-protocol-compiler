// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

func DefaultObservationFields() []ObservationField {
	names := []string{
		ObservationPathAvailabilityBucket,
		ObservationHandshakeOutcomeBucket,
		ObservationFirstUsefulByteBucket,
		ObservationStallPatternBucket,
		ObservationResetLikeFailureBucket,
		ObservationBlackholeLikeFailureBucket,
		ObservationDNSPoisoningLikeBucket,
		ObservationDNSTruncationLikeBucket,
		ObservationDNSRateLimitLikeBucket,
		ObservationRelayBurnLikeBucket,
		ObservationCarrierFamilyBucket,
		ObservationBundleCandidateBucket,
		ObservationScoreBucket,
		ObservationHealthStateBucket,
		ObservationFailoverOutcomeBucket,
		ObservationCoarsePlatformClass,
		ObservationCoarseNetworkClass,
		ObservationCoarseTimeBucket,
	}
	fields := make([]ObservationField, 0, len(names))
	for _, name := range names {
		fields = append(fields, ObservationField{
			Name:             name,
			Class:            "safe_bucket",
			RedactionClass:   RedactionBucket,
			RetentionClass:   RetentionSessionOnly,
			AllowedInFixture: true,
		})
	}
	return fields
}

func ObservationNames(fields []ObservationField) []string {
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		out = append(out, field.Name)
	}
	return out
}
