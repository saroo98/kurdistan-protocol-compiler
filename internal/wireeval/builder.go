// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
	"kurdistan/internal/wiregencompare"
)

func DefaultSeeds() []int {
	return []int{12345, 12346, 12347, 12348, 12349, 12350, 12351, 12352}
}

func DefaultScenarios() []string {
	return wiregencompare.DefaultScenarios()
}

func BuildDataset(ctx context.Context, corpus protocorpus.CorpusManifest, opts BuildOptions) (Dataset, error) {
	_ = ctx
	seeds := opts.Seeds
	if len(seeds) == 0 {
		seeds = DefaultSeeds()
	}
	scenarios := opts.Scenarios
	if len(scenarios) == 0 {
		scenarios = DefaultScenarios()
	}
	splitMode := opts.SplitMode
	if splitMode == "" {
		splitMode = DefaultSplitMode()
	}
	backend := opts.Backend
	if backend == "" {
		backend = "interpreted"
	}
	records := make([]WireEvalRecord, 0, len(seeds)*len(scenarios))
	for _, seed := range seeds {
		policy, err := wiregen.SamplePolicy(int64(seed), corpus)
		if err != nil {
			return Dataset{}, err
		}
		for _, scenario := range scenarios {
			vector := wiregencompare.ExpectedVector(policy, scenario, backend, fmt.Sprintf("profile-%d", seed))
			record := RecordFromVector(vector, LabelGeneratedKurdistan, SplitTrain)
			record.Split = SplitForRecord(len(records), record, splitMode)
			records = append(records, record)
		}
	}
	if opts.Controls {
		records = append(records, ControlRecords(records)...)
	}
	sortRecords(records)
	manifest := BuildManifest(records, string(corpus.Version), splitMode)
	dataset := Dataset{Manifest: manifest, Records: records}
	if err := ValidateDataset(dataset); err != nil {
		return Dataset{}, err
	}
	return dataset, nil
}

func RecordFromVector(vector wirefeatures.WireFeatureVector, label WireEvalLabel, split DatasetSplit) WireEvalRecord {
	record := WireEvalRecord{
		DatasetVersion:      string(Version),
		ProfileID:           vector.ProfileID,
		ProfileSeed:         vector.ProfileSeed,
		Scenario:            vector.Scenario,
		Backend:             vector.Backend,
		Split:               split,
		Label:               label,
		SelectedFamily:      firstNonEmpty(vector.WireSelectedFamily, "generated_family"),
		SelectedCorpusEntry: firstNonEmpty(vector.WireCorpusEntry, "generated_entry"),
		PhaseShape:          vector.PhaseShape,
		FieldLayoutClass:    vector.FieldLayoutClass,
		FirstNShapeHash:     vector.FirstNPacketShape,
		DirectionSequence:   directionSequence(vector.DirectionPattern),
		PacketSizeBuckets:   append([]string(nil), vector.FrameSizeBuckets...),
		FrameSizeBuckets:    append([]string(nil), vector.FrameSizeBuckets...),
		FragmentRhythm:      vector.FragmentRhythm,
		ControlRichness:     vector.ControlRichness,
		MetadataExposure:    vector.MetadataExposure,
		BackpressureClass:   vector.BackpressurePattern,
		ResetCloseClass:     vector.ResetClosePattern,
		ErrorMappingClass:   vector.ErrorMappingPattern,
		FeatureHash:         vector.FeatureHash,
		ByteShapeHash:       vector.ByteShapeHash,
		PayloadLogged:       vector.PayloadLogged,
		SecretLogged:        vector.SecretLogged,
	}
	record.RecordID = StableRecordID(record)
	return record
}

func BuildManifest(records []WireEvalRecord, corpusVersion, splitMode string) WireEvalDatasetManifest {
	profiles := map[int]bool{}
	scenarios := map[string]bool{}
	splits := map[string]int{}
	labels := map[string]int{}
	payloadLogged, secretLogged := false, false
	for _, record := range records {
		profiles[record.ProfileSeed] = true
		scenarios[record.Scenario] = true
		splits[string(record.Split)]++
		labels[string(record.Label)]++
		payloadLogged = payloadLogged || record.PayloadLogged
		secretLogged = secretLogged || record.SecretLogged
	}
	_ = splitMode
	return WireEvalDatasetManifest{
		DatasetVersion:       string(Version),
		CorpusVersion:        corpusVersion,
		WiregenPolicyVersion: wiregen.PolicyVersion,
		FeatureSchemaVersion: wirefeatures.SchemaVersion,
		GeneratedAt:          FixedGeneratedAt,
		RecordCount:          len(records),
		ProfileCount:         len(profiles),
		ScenarioCount:        len(scenarios),
		SplitCounts:          splits,
		LabelCounts:          labels,
		PayloadLogged:        payloadLogged,
		SecretLogged:         secretLogged,
		DatasetHash:          DatasetHash(records),
	}
}

func StableRecordID(record WireEvalRecord) string {
	return "rec_" + HashValue(fmt.Sprintf("%s:%d:%s:%s:%s", record.ProfileID, record.ProfileSeed, record.Scenario, record.Backend, record.Label))[:16]
}

func sortRecords(records []WireEvalRecord) {
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		return strings.Join([]string{string(a.Split), string(a.Label), a.ProfileID, a.Scenario, a.Backend, a.RecordID}, "/") <
			strings.Join([]string{string(b.Split), string(b.Label), b.ProfileID, b.Scenario, b.Backend, b.RecordID}, "/")
	})
}

func directionSequence(pattern string) []string {
	switch pattern {
	case "client_server_client", "client_to_server/server_to_client/client_to_server":
		return []string{"client_to_server", "server_to_client", "client_to_server"}
	case "server_client_server":
		return []string{"server_to_client", "client_to_server", "server_to_client"}
	case "server_first":
		return []string{"server_to_client", "client_to_server"}
	default:
		return []string{"client_to_server", "server_to_client"}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
