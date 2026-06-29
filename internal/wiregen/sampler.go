// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import (
	"fmt"

	"kurdistan/internal/protocorpus"
)

func SamplePolicy(seed int64, corpus protocorpus.CorpusManifest) (WireShapePolicy, error) {
	entry, err := SelectCorpusEntry(seed, corpus)
	if err != nil {
		return WireShapePolicy{}, err
	}
	phase := phasePlan(entry)
	layout := fieldLayoutPlan(seed, entry)
	firstFlight := firstFlightPlan(seed, entry)
	policy := WireShapePolicy{
		Version:              PolicyVersion,
		CorpusVersion:        string(corpus.Version),
		PolicyID:             fmt.Sprintf("wsp_%d_%s", seed, entry.Name),
		ProfileSeed:          int(seed),
		SelectedFamily:       entry.Family,
		SelectedCorpusEntry:  entry.Name,
		PhasePlan:            phase,
		FieldLayoutPlan:      layout,
		FirstFlightPlan:      firstFlight,
		FirstNPlan:           firstNPlan(seed, entry, firstFlight),
		FrameSizePlan:        frameSizePlan(seed, entry),
		FragmentRhythmPlan:   fragmentRhythmPlan(seed, entry),
		ControlPlan:          controlPlan(seed, entry),
		MetadataExposurePlan: metadataExposurePlan(layout, entry),
		LengthAlonePlan:      lengthAlonePlan(seed, entry),
	}
	if err := setPolicyHash(&policy); err != nil {
		return WireShapePolicy{}, err
	}
	if err := ValidatePolicy(policy, corpus); err != nil {
		return WireShapePolicy{}, err
	}
	return policy, nil
}
