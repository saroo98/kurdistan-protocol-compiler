// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import (
	"context"
	"fmt"

	"kurdistan/internal/bytetransport"
	"kurdistan/internal/codegen"
	"kurdistan/internal/compiler"
)

func GenerateBytePathManifest(ctx context.Context, opts ManifestOptions) (FixtureManifest, error) {
	if opts.BackendVersion == "" {
		opts.BackendVersion = codegen.Version
	}
	if opts.Backend == "" {
		opts.Backend = BackendLab
	}
	manifest := NewManifest(opts)
	cfg := bytetransport.DefaultConfig("bytepath-fixture")
	cfg.DeterministicSeed = 18
	for _, seed := range manifest.ProfileSeeds {
		p, err := compiler.Generate(int64(seed))
		if err != nil {
			return FixtureManifest{}, fmt.Errorf("profile seed %d: %w", seed, err)
		}
		for _, scenarioName := range manifest.ScenarioNames {
			scenario := bytetransport.DefaultScenario(scenarioName)
			result, err := bytetransport.RunScenario(ctx, p, scenario, cfg)
			if err != nil {
				return FixtureManifest{}, fmt.Errorf("profile seed %d scenario %s: %w", seed, scenarioName, err)
			}
			summary := NormalizeSummary(p.ID, seed, opts.Backend, result.Summary)
			entry, err := EntryForSummary(summary)
			if err != nil {
				return FixtureManifest{}, err
			}
			manifest.Summaries = append(manifest.Summaries, summary)
			manifest.Entries = append(manifest.Entries, entry)
		}
	}
	manifest.Normalize()
	if err := ValidateManifest(manifest); err != nil {
		return FixtureManifest{}, err
	}
	return manifest, nil
}

func NormalizeSummary(profileID string, seed int, backend string, summary bytetransport.ByteTransportSummary) BytePathFixtureSummary {
	if backend == "" {
		backend = BackendLab
	}
	wireFirstNHash := ""
	if summary.WireFirstNShape != "" {
		wireFirstNHash = summary.WireFirstNShape
	}
	return BytePathFixtureSummary{
		ProfileID:            profileID,
		ProfileSeed:          seed,
		Scenario:             summary.Scenario,
		Backend:              backend,
		FramesEncoded:        summary.FramesEncoded,
		FramesDecoded:        summary.FramesDecoded,
		FragmentsCreated:     summary.FragmentsCreated,
		FragmentsReassembled: summary.FragmentsReassembled,
		BytesWrittenBucket:   bucketBytes(summary.BytesWritten),
		BytesReadBucket:      bucketBytes(summary.BytesRead),
		BackpressureEvents:   summary.BackpressureEvents,
		SequenceRejected:     summary.SequenceRejected,
		MalformedRejected:    summary.MalformedRejected,
		CorruptionRejected:   summary.CorruptionRejected,
		ReplaysRejected:      summary.ReplayRejected,
		RuntimeStreamsMapped: summary.RuntimeStreamsMapped,
		TargetErrors:         summary.TargetErrors,
		TargetResets:         summary.TargetResets,
		SinkCompleted:        summary.Completed,
		PayloadLogged:        summary.PayloadLogged,
		SecretLogged:         summary.SecretLogged,
		WirePolicyID:         summary.WirePolicyID,
		WirePolicyHash:       summary.WirePolicyHash,
		WireSelectedFamily:   summary.WireSelectedFamily,
		WireCorpusEntry:      summary.WireCorpusEntry,
		WirePhaseShape:       summary.WirePhaseShape,
		WireFieldLayoutClass: summary.WireFieldLayoutClass,
		WireFirstFlightClass: summary.WireFirstFlightClass,
		WireFirstNShape:      wireFirstNHash,
		WireFrameSizeBuckets: append([]string(nil), summary.WireFrameSizeBuckets...),
		WireFragmentRhythm:   summary.WireFragmentRhythm,
		WireControlRichness:  summary.WireControlRichness,
		WireMetadataExposure: summary.WireMetadataExposure,
	}
}

func EntryForSummary(summary BytePathFixtureSummary) (FixtureEntry, error) {
	summaryHash, err := SummaryHash(summary)
	if err != nil {
		return FixtureEntry{}, err
	}
	traceHash, err := TraceHash(summary)
	if err != nil {
		return FixtureEntry{}, err
	}
	byteShapeHash, err := ByteShapeHash(summary)
	if err != nil {
		return FixtureEntry{}, err
	}
	result := "passed"
	if !summary.SinkCompleted || summary.PayloadLogged || summary.SecretLogged {
		result = "failed"
	}
	return FixtureEntry{
		Name:           fmt.Sprintf("%s_seed_%d_%s", summary.Backend, summary.ProfileSeed, summary.Scenario),
		Kind:           FixtureBytePath,
		ProfileID:      summary.ProfileID,
		ProfileSeed:    summary.ProfileSeed,
		Scenario:       summary.Scenario,
		Backend:        summary.Backend,
		SummaryHash:    summaryHash,
		TraceHash:      traceHash,
		ByteShapeHash:  byteShapeHash,
		ExpectedResult: result,
		PayloadLogged:  summary.PayloadLogged,
		SecretLogged:   summary.SecretLogged,
	}, nil
}

func VerifyManifest(ctx context.Context, path string) (CompareReport, error) {
	current, err := LoadManifest(path)
	if err != nil {
		return CompareReport{}, err
	}
	if err := ValidateManifest(current); err != nil {
		return CompareReport{}, err
	}
	regenerated, err := GenerateBytePathManifest(ctx, ManifestOptions{
		FixtureSet:     current.FixtureSet,
		Backend:        BackendLab,
		GeneratedAt:    current.GeneratedAt,
		ProfileSeeds:   current.ProfileSeeds,
		ScenarioNames:  current.ScenarioNames,
		BackendVersion: current.BackendVersion,
	})
	if err != nil {
		return CompareReport{}, err
	}
	report := CompareManifests(current, regenerated)
	if !report.Passed {
		return report, ErrFixtureDrift
	}
	return report, nil
}
