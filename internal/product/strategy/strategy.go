// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package strategy is the product-facing carrier-selection DESIGN CONTRACT
// (Stage 8).
//
// LOOM: contract. It is a thin, profile-scoped adapter over the EXISTING carrier
// design-review taxonomy (carrierreview.DefaultDescriptors); it deliberately
// does NOT define a new family list (Stage 5b WO-503 rejected unifying the three
// distinct taxonomies). It performs no probing, dialing, resolving, or network
// I/O — selection here is a modelled ranking of already-reviewed families for a
// profile. Nothing in the live runtime imports this package (enforced by
// internal/testkit/importrules).
package strategy

import (
	"errors"
	"sort"
	"strings"

	"kurdistan/internal/contracts/carrier/carrierreview"
)

const Version = "product-strategy-v1"

const (
	// RiskToleranceConservative admits only default-eligible, non-manual-review families.
	RiskToleranceConservative = "conservative"
	// RiskToleranceStandard additionally admits gated-but-eligible families.
	RiskToleranceStandard = "standard"
)

// Request is a profile-scoped selection request. It carries a profile reference
// (opaque, not the profile) and a risk tolerance; it never carries endpoints,
// destinations, payloads, or secrets.
type Request struct {
	ProfileRef    string `json:"profile_ref"`
	RiskTolerance string `json:"risk_tolerance"`
}

// Candidate is one selectable carrier family plus why it was admitted.
type Candidate struct {
	Family    string `json:"family"`
	RiskClass string `json:"risk_class"`
	Readiness string `json:"readiness"`
	Rationale string `json:"rationale"`
}

// Selection is the modelled selection result: an ordered candidate list plus the
// families that were excluded and why. It is a contract, not a live decision.
type Selection struct {
	ProfileRef    string      `json:"profile_ref"`
	RiskTolerance string      `json:"risk_tolerance"`
	Ordered       []Candidate `json:"ordered"`
	Excluded      []string    `json:"excluded"`
	Synthetic     bool        `json:"synthetic"` // always true: no live probing
}

// Select ranks the reviewed carrier families for a profile under a risk
// tolerance. Unsafe/blocked families and (for conservative) manual-review
// families are excluded. It is deterministic and performs no I/O.
func Select(req Request) (Selection, error) {
	if strings.TrimSpace(req.ProfileRef) == "" {
		return Selection{}, errors.New("strategy: profile_ref is required")
	}
	tolerance := req.RiskTolerance
	if tolerance == "" {
		tolerance = RiskToleranceConservative
	}
	if tolerance != RiskToleranceConservative && tolerance != RiskToleranceStandard {
		return Selection{}, errors.New("strategy: unknown risk_tolerance " + tolerance)
	}

	sel := Selection{ProfileRef: req.ProfileRef, RiskTolerance: tolerance, Synthetic: true}
	for _, d := range carrierreview.DefaultDescriptors() {
		admit, reason := admits(d, tolerance)
		if !admit {
			sel.Excluded = append(sel.Excluded, d.Family+": "+reason)
			continue
		}
		sel.Ordered = append(sel.Ordered, Candidate{
			Family:    d.Family,
			RiskClass: d.RiskClass,
			Readiness: d.Readiness,
			Rationale: reason,
		})
	}
	// Stable, deterministic ordering: eligible-first is already implied; sort by
	// family name so the contract output is reproducible.
	sort.SliceStable(sel.Ordered, func(i, j int) bool { return sel.Ordered[i].Family < sel.Ordered[j].Family })
	sort.Strings(sel.Excluded)
	return sel, nil
}

func admits(d carrierreview.CarrierFamilyDescriptor, tolerance string) (bool, string) {
	if d.Family == carrierreview.FamilyUnsafeControl {
		return false, "unsafe control family is never selectable"
	}
	if d.Readiness == carrierreview.ReadinessBlockedByRisk {
		return false, "blocked by risk"
	}
	if !d.DefaultEligible {
		return false, "not default eligible"
	}
	if d.ManualReviewRequired && tolerance == RiskToleranceConservative {
		return false, "requires manual review (conservative tolerance)"
	}
	return true, "default-eligible reviewed family"
}
