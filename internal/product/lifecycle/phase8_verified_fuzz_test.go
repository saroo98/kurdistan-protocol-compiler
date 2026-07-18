// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package lifecycle

import "testing"

func FuzzApplyVerifiedStateMachine(f *testing.F) {
	f.Add(uint64(1), byte(0), false)
	f.Add(uint64(2), byte(0), false)
	f.Add(uint64(1), byte(0), true)
	f.Fuzz(func(t *testing.T, generation uint64, actionByte byte, fork bool) {
		receipt := VerifiedReceipt{ContentID: "content-1", ProviderID: "provider-1", LineageID: "lineage-1", AuthenticatedArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RootEpoch: 3, RevocationEpoch: 4}
		current := VerifiedState{State: State{Status: Admitted, ProfileID: "profiles.one", Scope: "revocation-1", EvidenceReference: receipt.AuthenticatedArtifactSHA256, Generation: 1}, Receipt: receipt}
		actions := []Action{Admit, Supersede, Revoke, Disable, Action("unknown")}
		decisionReceipt := receipt
		if fork {
			decisionReceipt.ContentID = "content-fork"
			decisionReceipt.AuthenticatedArtifactSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}
		decision := VerifiedDecision{Decision: Decision{Action: actions[int(actionByte)%len(actions)], ProfileID: current.ProfileID, Scope: current.Scope, EvidenceReference: decisionReceipt.AuthenticatedArtifactSHA256, Generation: generation}, Receipt: decisionReceipt}
		next, err := ApplyVerified(current, decision)
		if err != nil && next != current {
			t.Fatal("failed transition mutated verified state")
		}
		if err == nil && next.Generation < current.Generation {
			t.Fatal("successful transition rolled generation back")
		}
		if err == nil && generation == current.Generation && next.Receipt != current.Receipt {
			t.Fatal("equal-generation authenticated fork succeeded")
		}
	})
}
