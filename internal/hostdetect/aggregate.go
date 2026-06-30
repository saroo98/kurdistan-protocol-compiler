// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

type HostAggregate struct {
	SyntheticHostID       SyntheticHostID `json:"synthetic_host_id"`
	HostClass             HostClass       `json:"host_class"`
	ObservationCount      int             `json:"observation_count"`
	UniqueProfileSeeds    int             `json:"unique_profile_seeds"`
	UniqueFeatureHashes   int             `json:"unique_feature_hashes"`
	UniqueFirstNShapes    int             `json:"unique_first_n_shapes"`
	UniqueFamilies        int             `json:"unique_families"`
	UniqueMetadataClasses int             `json:"unique_metadata_classes"`
	UniqueFragmentRhythms int             `json:"unique_fragment_rhythms"`
	DominantFeatureShare  float64         `json:"dominant_feature_share"`
	DominantFirstNShare   float64         `json:"dominant_first_n_share"`
	DominantFamilyShare   float64         `json:"dominant_family_share"`
	ConsistencyScore      float64         `json:"consistency_score"`
	RotationScore         float64         `json:"rotation_score"`
	RiskBucket            string          `json:"risk_bucket"`
	PayloadLogged         bool            `json:"payload_logged"`
	SecretLogged          bool            `json:"secret_logged"`
}
