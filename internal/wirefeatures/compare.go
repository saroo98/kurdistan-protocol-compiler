// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

func SemanticEquivalent(a, b WireFeatureVector) bool {
	return a.ProfileSeed == b.ProfileSeed &&
		a.Scenario == b.Scenario &&
		a.PhaseShape == b.PhaseShape &&
		a.FieldLayoutClass == b.FieldLayoutClass &&
		a.SequenceBehavior == b.SequenceBehavior &&
		a.ResetClosePattern == b.ResetClosePattern &&
		a.ErrorMappingPattern == b.ErrorMappingPattern &&
		!a.PayloadLogged && !a.SecretLogged && !b.PayloadLogged && !b.SecretLogged
}
