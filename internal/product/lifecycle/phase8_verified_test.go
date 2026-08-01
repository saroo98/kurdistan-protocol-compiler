// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package lifecycle

import "testing"

func TestApplyVerifiedRequiresExactContentForEqualGeneration(t *testing.T) {
	receipt := VerifiedReceipt{ContentID: "content-1", ProviderID: "provider-1", LineageID: "lineage-1", AuthenticatedArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RootEpoch: 2, RevocationEpoch: 3}
	current := VerifiedState{State: State{Status: Admitted, ProfileID: "kurd/profile-1", Scope: "scope-1", EvidenceReference: "evidence-1", Generation: 7}, Receipt: receipt}
	idempotent, err := ApplyVerified(current, VerifiedDecision{Decision: Decision{Action: Admit, ProfileID: current.ProfileID, Scope: current.Scope, EvidenceReference: current.EvidenceReference, Generation: current.Generation}, Receipt: receipt})
	if err != nil || idempotent != current {
		t.Fatalf("equal-generation exact identity was not idempotent: state=%+v err=%v", idempotent, err)
	}
	conflict := receipt
	conflict.AuthenticatedArtifactSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if got, err := ApplyVerified(current, VerifiedDecision{Decision: Decision{Action: Admit, ProfileID: current.ProfileID, Scope: current.Scope, EvidenceReference: current.EvidenceReference, Generation: current.Generation}, Receipt: conflict}); err == nil || got != current {
		t.Fatalf("equal-generation content fork changed state: state=%+v err=%v", got, err)
	}
}

func TestApplyVerifiedAdmitsHigherGenerationReplacement(t *testing.T) {
	oldReceipt := VerifiedReceipt{ContentID: "content-1", ProviderID: "provider-1", LineageID: "lineage-1", AuthenticatedArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RootEpoch: 2, RevocationEpoch: 3}
	newReceipt := VerifiedReceipt{ContentID: "content-2", ProviderID: "provider-1", LineageID: "lineage-1", AuthenticatedArtifactSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RootEpoch: 2, RevocationEpoch: 4}
	current := VerifiedState{State: State{Status: Admitted, ProfileID: "kurd/profile-1", Scope: "scope-1", EvidenceReference: "evidence-1", Generation: 7}, Receipt: oldReceipt}
	got, err := ApplyVerified(current, VerifiedDecision{Decision: Decision{Action: Admit, ProfileID: current.ProfileID, Scope: current.Scope, EvidenceReference: "evidence-2", Generation: 8}, Receipt: newReceipt})
	if err != nil || got.Status != Admitted || got.Generation != 8 || got.Receipt != newReceipt {
		t.Fatalf("verified replacement failed: state=%+v err=%v", got, err)
	}
}

func TestApplyVerifiedRejectsHigherGenerationLineageRebind(t *testing.T) {
	oldReceipt := VerifiedReceipt{ContentID: "content-1", ProviderID: "provider-1", LineageID: "lineage-1", AuthenticatedArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RootEpoch: 2, RevocationEpoch: 3}
	rebound := VerifiedReceipt{ContentID: "content-2", ProviderID: "provider-1", LineageID: "lineage-other", AuthenticatedArtifactSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RootEpoch: 2, RevocationEpoch: 4}
	current := VerifiedState{State: State{Status: Admitted, ProfileID: "kurd/profile-1", Scope: "scope-1", EvidenceReference: "evidence-1", Generation: 7}, Receipt: oldReceipt}
	got, err := ApplyVerified(current, VerifiedDecision{Decision: Decision{Action: Admit, ProfileID: current.ProfileID, Scope: current.Scope, EvidenceReference: "evidence-2", Generation: 8}, Receipt: rebound})
	if err == nil || got != current {
		t.Fatalf("cross-lineage replacement changed state: state=%+v err=%v", got, err)
	}
}

func TestApplyVerifiedPreservesSameLineageProviderMigration(t *testing.T) {
	oldReceipt := VerifiedReceipt{ContentID: "content-1", ProviderID: "provider-1", LineageID: "lineage-1", AuthenticatedArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RootEpoch: 2, RevocationEpoch: 3}
	migrated := VerifiedReceipt{ContentID: "content-2", ProviderID: "provider-2", LineageID: "lineage-1", AuthenticatedArtifactSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RootEpoch: 2, RevocationEpoch: 4}
	current := VerifiedState{State: State{Status: Admitted, ProfileID: "kurd/profile-1", Scope: "scope-1", EvidenceReference: "evidence-1", Generation: 7}, Receipt: oldReceipt}
	got, err := ApplyVerified(current, VerifiedDecision{Decision: Decision{Action: Admit, ProfileID: current.ProfileID, Scope: current.Scope, EvidenceReference: "evidence-2", Generation: 8}, Receipt: migrated})
	if err != nil || got.Receipt != migrated {
		t.Fatalf("same-lineage provider migration rejected: state=%+v err=%v", got, err)
	}
}

func TestApplyVerifiedRejectsPartialReceiptWithoutMutation(t *testing.T) {
	current := VerifiedState{}
	decision := VerifiedDecision{Decision: Decision{Action: Admit, ProfileID: "kurd/profile-1", Scope: "scope-1", EvidenceReference: "evidence-1", Generation: 1}, Receipt: VerifiedReceipt{ContentID: "content-1"}}
	if got, err := ApplyVerified(current, decision); err == nil || got != current {
		t.Fatalf("partial verified receipt changed state: state=%+v err=%v", got, err)
	}
}
