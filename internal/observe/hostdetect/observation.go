// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

type HostObservation struct {
	Version          string          `json:"version"`
	ObservationID    string          `json:"observation_id"`
	SyntheticHostID  SyntheticHostID `json:"synthetic_host_id"`
	HostClass        HostClass       `json:"host_class"`
	LogicalTime      int             `json:"logical_time"`
	DatasetRecordID  string          `json:"dataset_record_id"`
	ProfileID        string          `json:"profile_id"`
	ProfileSeed      int             `json:"profile_seed"`
	Scenario         string          `json:"scenario"`
	SelectedFamily   string          `json:"selected_family"`
	FeatureHash      string          `json:"feature_hash"`
	FirstNShapeHash  string          `json:"first_n_shape_hash"`
	ByteShapeHash    string          `json:"byte_shape_hash"`
	MetadataExposure string          `json:"metadata_exposure"`
	FragmentRhythm   string          `json:"fragment_rhythm"`
	ControlRichness  string          `json:"control_richness"`
	Split            string          `json:"split"`
	PayloadLogged    bool            `json:"payload_logged"`
	SecretLogged     bool            `json:"secret_logged"`
}

type HostObservationSet struct {
	Version          string            `json:"version"`
	GeneratedAt      string            `json:"generated_at"`
	AssignmentMode   string            `json:"assignment_mode"`
	Window           ObservationWindow `json:"window"`
	HostCount        int               `json:"host_count"`
	ObservationCount int               `json:"observation_count"`
	PayloadLogged    bool              `json:"payload_logged"`
	SecretLogged     bool              `json:"secret_logged"`
	DatasetHash      string            `json:"dataset_hash"`
	Observations     []HostObservation `json:"observations"`
}
