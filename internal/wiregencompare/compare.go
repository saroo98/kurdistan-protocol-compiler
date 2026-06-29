// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregencompare

import (
	"fmt"
	"strings"

	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
)

type PolicyFeatureComparisonReport struct {
	PoliciesCompared      int      `json:"policies_compared"`
	FeaturesCompared      int      `json:"features_compared"`
	PolicyFeatureMatches  int      `json:"policy_feature_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

func ExpectedVector(policy wiregen.WireShapePolicy, scenario, backend, profileID string) wirefeatures.WireFeatureVector {
	summary := wiregen.SummarizePolicy(policy)
	feature := wirefeatures.WireFeatureVector{
		ProfileID:           profileID,
		ProfileSeed:         policy.ProfileSeed,
		Backend:             backend,
		Scenario:            scenario,
		PhaseShape:          summary.PhaseShape,
		FieldLayoutClass:    policy.FieldLayoutPlan.LayoutClass,
		FirstFlightBucket:   firstSizeBucket(policy),
		FirstNPacketShape:   wiregen.FirstNShapeHash(policy),
		DirectionPattern:    policy.FirstFlightPlan.DirectionPattern,
		FrameSizeBuckets:    append([]string(nil), policy.FrameSizePlan.SizeBuckets...),
		FragmentRhythm:      policy.FragmentRhythmPlan.Strategy,
		ControlRichness:     policy.ControlPlan.Richness,
		MetadataExposure:    policy.MetadataExposurePlan.ExposureClass,
		PayloadVisibility:   payloadVisibility(policy),
		SequenceBehavior:    "monotonic",
		BackpressurePattern: backpressurePattern(scenario),
		ResetClosePattern:   policy.ControlPlan.ResetClass + "/" + policy.ControlPlan.CloseClass,
		ErrorMappingPattern: "safe_metadata",
		WirePolicyID:        policy.PolicyID,
		WirePolicyHash:      policy.PolicyHash,
		WireSelectedFamily:  string(policy.SelectedFamily),
		WireCorpusEntry:     policy.SelectedCorpusEntry,
	}
	feature.ByteShapeHash = safeHash(policy.PolicyHash + ":" + scenario + ":" + strings.Join(feature.FrameSizeBuckets, ",") + ":" + feature.FragmentRhythm)
	feature.FeatureHash = safeHash(fmt.Sprintf("%s:%s:%s:%s:%s:%s", feature.PhaseShape, feature.FieldLayoutClass, feature.FirstNPacketShape, feature.FragmentRhythm, feature.MetadataExposure, scenario))
	return feature
}

func firstSizeBucket(policy wiregen.WireShapePolicy) string {
	if len(policy.FirstFlightPlan.SizeBuckets) > 0 {
		return policy.FirstFlightPlan.SizeBuckets[0]
	}
	if len(policy.FrameSizePlan.SizeBuckets) > 0 {
		return policy.FrameSizePlan.SizeBuckets[0]
	}
	return "size_65_128"
}

func payloadVisibility(policy wiregen.WireShapePolicy) string {
	for _, field := range policy.MetadataExposurePlan.CleartextFields {
		if string(field) == "payload_shape" {
			return "cleartext"
		}
	}
	for _, field := range policy.MetadataExposurePlan.DerivedOnlyFields {
		if string(field) == "payload_shape" {
			return "derived"
		}
	}
	return "protected"
}

func backpressurePattern(scenario string) string {
	if strings.Contains(scenario, "large") || strings.Contains(scenario, "queue") {
		return "backpressure_observed"
	}
	return "bounded"
}

func ComparePoliciesToFeatures(policies []wiregen.WireShapePolicy, vectors []wirefeatures.WireFeatureVector) PolicyFeatureComparisonReport {
	byPolicy := map[string]wiregen.WireShapePolicy{}
	for _, policy := range policies {
		byPolicy[policy.PolicyHash] = policy
	}
	report := PolicyFeatureComparisonReport{PoliciesCompared: len(policies), FeaturesCompared: len(vectors), Conclusion: "passed"}
	for _, vector := range vectors {
		report.PayloadLogged = report.PayloadLogged || vector.PayloadLogged
		report.SecretLogged = report.SecretLogged || vector.SecretLogged
		policy, ok := byPolicy[vector.WirePolicyHash]
		if !ok {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, vector.ProfileID+"/"+vector.Scenario+": missing policy hash")
			continue
		}
		expected := ExpectedVector(policy, vector.Scenario, vector.Backend, vector.ProfileID)
		if expected.FirstNPacketShape != vector.FirstNPacketShape {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, vector.ProfileID+"/"+vector.Scenario+": first-n mismatch")
		}
		if expected.FragmentRhythm != vector.FragmentRhythm {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, vector.ProfileID+"/"+vector.Scenario+": fragment rhythm mismatch")
		}
		if expected.MetadataExposure != vector.MetadataExposure {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, vector.ProfileID+"/"+vector.Scenario+": metadata exposure mismatch")
		}
		if expected.WireSelectedFamily != "" && vector.WireSelectedFamily != "" && expected.WireSelectedFamily != vector.WireSelectedFamily {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, vector.ProfileID+"/"+vector.Scenario+": selected family mismatch")
		}
		report.PolicyFeatureMatches++
	}
	if report.PayloadLogged || report.SecretLogged {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "trace hygiene failure")
	}
	if len(report.UnexpectedDifferences) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func safeHash(value string) string {
	hash, err := wiregen.HashValue(value)
	if err != nil {
		return "hash_error"
	}
	return hash
}
