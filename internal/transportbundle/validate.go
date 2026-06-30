// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import (
	"encoding/json"
	"fmt"

	"kurdistan/internal/adaptivepath"
)

func ValidatePolicy(policy TransportBundlePolicy) error {
	if policy.Version != string(Version) || policy.PolicyID == "" || policy.BundleSeed == 0 || policy.CandidateCount <= 0 || len(policy.RequiredFamilies) == 0 {
		return ErrInvalidPolicy
	}
	for _, family := range append(append([]adaptivepath.CandidateFamily{}, policy.RequiredFamilies...), policy.OptionalFamilies...) {
		if _, ok := adaptivepath.FamilyDescriptor(family); !ok {
			return fmt.Errorf("%w: family %s", ErrInvalidPolicy, family)
		}
		if family == adaptivepath.CandidateDomesticMediaRisk && !policy.AllowHighRiskCandidates && policy.Mode != BundleModeControlCollapsed {
			return fmt.Errorf("%w: high risk not allowed", ErrInvalidPolicy)
		}
		if family == adaptivepath.CandidateExperimentalUDP && !policy.AllowExperimentalCandidates && policy.Mode != BundleModeControlCollapsed {
			return fmt.Errorf("%w: experimental not allowed", ErrInvalidPolicy)
		}
	}
	if policy.PolicyHash != "" && policy.PolicyHash != HashValue(policyHashInput(policy)) {
		return fmt.Errorf("%w: hash mismatch", ErrInvalidPolicy)
	}
	return ScanForLeak(policy)
}

func ValidateManifest(manifest TransportBundleManifest) error {
	if manifest.Version != string(Version) || manifest.BundleID == "" || len(manifest.Candidates) == 0 || manifest.BundleHash == "" {
		return ErrInvalidBundle
	}
	seen := map[string]bool{}
	for _, c := range manifest.Candidates {
		if c.CandidateID == "" || c.ProfileID == "" || c.ProfileSeed == 0 || c.WirePolicyHash == "" || c.RelayID == "" || c.SyntheticHostID == "" || c.FreshnessTTLClass == "" || c.CandidateHash == "" {
			return ErrInvalidBundle
		}
		if seen[c.CandidateID] {
			return fmt.Errorf("%w: duplicate candidate", ErrInvalidBundle)
		}
		seen[c.CandidateID] = true
		if _, ok := adaptivepath.FamilyDescriptor(c.Family); !ok {
			return fmt.Errorf("%w: invalid family", ErrInvalidBundle)
		}
		if c.HighRisk && c.Role == CandidateRolePrimaryEligible {
			return fmt.Errorf("%w: high risk primary", ErrInvalidBundle)
		}
		if c.Experimental && c.Role == CandidateRolePrimaryEligible {
			return fmt.Errorf("%w: experimental primary", ErrInvalidBundle)
		}
		if c.CandidateHash != HashValue(candidateHashInput(c)) {
			return fmt.Errorf("%w: candidate hash mismatch", ErrInvalidBundle)
		}
	}
	if manifest.FallbackPlan.FinalWinnerSelected || len(manifest.FallbackPlan.OrderedCandidateIDs) == 0 {
		return fmt.Errorf("%w: invalid fallback plan", ErrInvalidBundle)
	}
	if manifest.BundleHash != HashValue(manifestHashInput(manifest)) {
		return fmt.Errorf("%w: bundle hash mismatch", ErrInvalidBundle)
	}
	return ScanForLeak(manifest)
}

func ValidateFixtureSet(set TransportBundleFixtureSet) error {
	if set.Version != string(Version) || len(set.Policies) == 0 || len(set.Candidates) == 0 || set.PayloadLogged || set.SecretLogged {
		return ErrInvalidBundle
	}
	for _, policy := range set.Policies {
		if err := ValidatePolicy(policy); err != nil {
			return err
		}
	}
	if len(set.ModeManifests) < len(RequiredBundleModes()) {
		return fmt.Errorf("%w: missing mode manifests", ErrInvalidBundle)
	}
	for _, manifest := range set.ModeManifests {
		if err := ValidateManifest(manifest); err != nil {
			return err
		}
	}
	if err := ValidateManifest(set.Manifest); err != nil {
		return err
	}
	if set.CollapseReport.Conclusion != "passed" || set.ControlCollapseReport.Conclusion != "failed" || set.Parity.Conclusion != "passed" {
		return ErrInvalidBundle
	}
	if set.FixtureSetHash != "" && set.FixtureSetHash != HashValue(fixtureSetHashInput(set)) {
		return fmt.Errorf("%w: fixture hash mismatch", ErrInvalidBundle)
	}
	return ScanForLeak(set)
}

func ValidateFallbackHint(hint BundleFallbackHint) error {
	if hint.CandidateID == "" || hint.FallbackClass == "" || hint.AppliesAfterFailure == "" || hint.HintHash == "" {
		return ErrInvalidBundle
	}
	if hint.HighRisk && hint.FallbackClass != "manual_review_only" {
		return fmt.Errorf("%w: high risk fallback not gated", ErrInvalidBundle)
	}
	if hint.HintHash != HashValue(fallbackHintHashInput(hint)) {
		return fmt.Errorf("%w: fallback hash mismatch", ErrInvalidBundle)
	}
	return ScanForLeak(hint)
}

func ValidateJSON(raw []byte) error {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	return ScanForLeak(decoded)
}
