// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type CorpusManifest struct {
	Version              CorpusVersion        `json:"version"`
	GeneratedAt          string               `json:"generated_at"`
	Name                 string               `json:"name"`
	FeatureSchemaVersion string               `json:"feature_schema_version"`
	PayloadLogged        bool                 `json:"payload_logged"`
	SecretLogged         bool                 `json:"secret_logged"`
	Entries              []ProtocolShapeEntry `json:"entries"`
	Buckets              FeatureBuckets       `json:"buckets"`
}

type FeatureBuckets struct {
	Size             []string `json:"size"`
	RoundTrip        []string `json:"round_trip"`
	DirectionPattern []string `json:"direction_pattern"`
	MetadataExposure []string `json:"metadata_exposure"`
}

func NewManifest(name string, entries []ProtocolShapeEntry) CorpusManifest {
	if name == "" {
		name = "abstract-protocol-feature-corpus"
	}
	return CorpusManifest{
		Version:              CorpusSchemaVersion,
		GeneratedAt:          "2026-06-29T00:00:00Z",
		Name:                 name,
		FeatureSchemaVersion: FeatureSchemaVersion,
		Entries:              append([]ProtocolShapeEntry(nil), entries...),
		Buckets: FeatureBuckets{
			Size:             SupportedSizeBuckets(),
			RoundTrip:        SupportedRoundTripBuckets(),
			DirectionPattern: SupportedDirectionPatterns(),
			MetadataExposure: SupportedMetadataExposureBuckets(),
		},
	}
}

func (m *CorpusManifest) Normalize() {
	if m.GeneratedAt == "" {
		m.GeneratedAt = time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Name < m.Entries[j].Name })
	for i := range m.Entries {
		sort.Strings(m.Entries[i].FrameSizeBuckets)
	}
	m.PayloadLogged = false
	m.SecretLogged = false
}

func LoadManifest(path string) (CorpusManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CorpusManifest{}, err
	}
	var manifest CorpusManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return CorpusManifest{}, err
	}
	return manifest, nil
}

func WriteManifest(path string, manifest CorpusManifest, force bool) error {
	if path == "" {
		return ErrMissingPath
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	manifest.Normalize()
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
