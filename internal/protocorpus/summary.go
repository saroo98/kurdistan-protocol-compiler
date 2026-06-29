// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

type CorpusSummary struct {
	Version          CorpusVersion `json:"version"`
	FeatureSchema    string        `json:"feature_schema"`
	EntryCount       int           `json:"entry_count"`
	FamilyCount      int           `json:"family_count"`
	PhaseKindCount   int           `json:"phase_kind_count"`
	FieldKindCount   int           `json:"field_kind_count"`
	PayloadLogged    bool          `json:"payload_logged"`
	SecretLogged     bool          `json:"secret_logged"`
	ManifestHash     string        `json:"manifest_hash"`
	ValidationStatus string        `json:"validation_status"`
}

func Summarize(manifest CorpusManifest) CorpusSummary {
	families := map[ProtocolFamily]bool{}
	phases := map[ProtocolPhase]bool{}
	fields := map[FieldKind]bool{}
	for _, entry := range manifest.Entries {
		families[entry.Family] = true
		for _, phase := range entry.Phases {
			phases[phase.Phase] = true
			for _, field := range phase.Fields {
				fields[field.Kind] = true
			}
		}
	}
	hash, _ := HashValue(manifest)
	status := "passed"
	if err := ValidateManifest(manifest); err != nil {
		status = "failed"
	}
	return CorpusSummary{
		Version:          manifest.Version,
		FeatureSchema:    manifest.FeatureSchemaVersion,
		EntryCount:       len(manifest.Entries),
		FamilyCount:      len(families),
		PhaseKindCount:   len(phases),
		FieldKindCount:   len(fields),
		PayloadLogged:    manifest.PayloadLogged,
		SecretLogged:     manifest.SecretLogged,
		ManifestHash:     hash,
		ValidationStatus: status,
	}
}
