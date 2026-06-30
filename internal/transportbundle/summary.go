// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import (
	"context"

	"kurdistan/internal/adaptivepath"
)

type TransportBundleFixtureSet struct {
	Version                string                       `json:"version"`
	Policies               []TransportBundlePolicy      `json:"policies"`
	SeedPlan               BundleSeedPlan               `json:"seed_plan"`
	Manifest               TransportBundleManifest      `json:"manifest"`
	ModeManifests          []TransportBundleManifest    `json:"mode_manifests"`
	Candidates             []TransportBundleCandidate   `json:"candidates"`
	AdaptivePathCandidates []adaptivepath.PathCandidate `json:"adaptivepath_candidates"`
	RelayBinding           BundleRelayBindingReport     `json:"relay_binding"`
	FallbackHints          []BundleFallbackHint         `json:"fallback_hints"`
	CollapseReport         BundleCollapseReport         `json:"collapse_report"`
	ControlCollapseReport  BundleCollapseReport         `json:"control_collapse_report"`
	Parity                 TransportBundleParityReport  `json:"parity"`
	PayloadLogged          bool                         `json:"payload_logged"`
	SecretLogged           bool                         `json:"secret_logged"`
	FixtureSetHash         string                       `json:"fixture_set_hash"`
}

func GenerateFixtureSet(ctx context.Context) (TransportBundleFixtureSet, error) {
	compiled, err := Compile(ctx, DefaultPolicy(12345, BundleModeBalancedAdaptive))
	if err != nil {
		return TransportBundleFixtureSet{}, err
	}
	policies := make([]TransportBundlePolicy, 0, len(RequiredBundleModes()))
	modeManifests := make([]TransportBundleManifest, 0, len(RequiredBundleModes()))
	for _, mode := range RequiredBundleModes() {
		policy := DefaultPolicy(12345, mode)
		modeBundle, err := Compile(ctx, policy)
		if err != nil {
			return TransportBundleFixtureSet{}, err
		}
		policies = append(policies, policy)
		modeManifests = append(modeManifests, modeBundle.Manifest)
	}
	set := TransportBundleFixtureSet{
		Version:                string(Version),
		Policies:               policies,
		SeedPlan:               compiled.SeedPlan,
		Manifest:               compiled.Manifest,
		ModeManifests:          modeManifests,
		Candidates:             compiled.Manifest.Candidates,
		AdaptivePathCandidates: compiled.AdaptivePathCandidates,
		RelayBinding:           compiled.RelayBinding,
		FallbackHints:          compiled.FallbackHints,
		CollapseReport:         compiled.CollapseReport,
		ControlCollapseReport:  compiled.ControlCollapseReport,
		Parity:                 compiled.Parity,
	}
	set.FixtureSetHash = HashValue(fixtureSetHashInput(set))
	return set, ValidateFixtureSet(set)
}

func fixtureSetHashInput(set TransportBundleFixtureSet) TransportBundleFixtureSet {
	set.FixtureSetHash = ""
	return set
}

func CompareFixtureSets(oldSet, newSet TransportBundleFixtureSet) TransportBundleComparisonReport {
	report := TransportBundleComparisonReport{
		Version:    string(Version),
		OldHash:    oldSet.FixtureSetHash,
		NewHash:    newSet.FixtureSetHash,
		Conclusion: "passed",
	}
	if err := ValidateFixtureSet(oldSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if err := ValidateFixtureSet(newSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if oldSet.FixtureSetHash != newSet.FixtureSetHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.PayloadLogged || newSet.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload_logged")
	}
	if oldSet.SecretLogged || newSet.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret_logged")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
}
