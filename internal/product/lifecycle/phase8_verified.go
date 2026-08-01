// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package lifecycle

import (
	"errors"
	"strings"
)

type VerifiedReceipt struct {
	ContentID                   string
	ProviderID                  string
	LineageID                   string
	AuthenticatedArtifactSHA256 string
	RootEpoch                   uint64
	RevocationEpoch             uint64
	RecipientEpoch              uint64
}

type VerifiedState struct {
	State
	Receipt VerifiedReceipt
}

type VerifiedDecision struct {
	Decision
	Receipt VerifiedReceipt
}

func ApplyVerified(current VerifiedState, decision VerifiedDecision) (VerifiedState, error) {
	original := current
	if !validVerifiedReceipt(decision.Receipt) {
		return original, errors.New("lifecycle: invalid verified receipt")
	}
	if current.Status != "" && current.Status != Absent && !validVerifiedReceipt(current.Receipt) {
		return original, errors.New("lifecycle: invalid current verified receipt")
	}
	if decision.Generation == current.Generation && current.Status != "" && current.Status != Absent && decision.Receipt != current.Receipt {
		return original, errors.New("lifecycle: conflicting equal-generation authenticated content")
	}
	if decision.Action == Admit && current.Status == Admitted && decision.Generation > current.Generation {
		if decision.ProfileID != current.ProfileID || decision.Scope != current.Scope ||
			decision.Receipt.LineageID != current.Receipt.LineageID ||
			decision.EvidenceReference == "" {
			return original, errors.New("lifecycle: verified replacement binding mismatch")
		}
		return VerifiedState{State: State{Status: Admitted, ProfileID: decision.ProfileID, Scope: decision.Scope, EvidenceReference: decision.EvidenceReference, Generation: decision.Generation}, Receipt: decision.Receipt}, nil
	}
	next, err := Apply(current.State, decision.Decision)
	if err != nil {
		return original, err
	}
	if next == current.State {
		return current, nil
	}
	return VerifiedState{State: next, Receipt: decision.Receipt}, nil
}

func validVerifiedReceipt(receipt VerifiedReceipt) bool {
	if receipt.ContentID == "" || receipt.ProviderID == "" || receipt.LineageID == "" || len(receipt.ContentID) > 128 || len(receipt.ProviderID) > 128 || len(receipt.LineageID) > 128 || receipt.RootEpoch == 0 || receipt.RevocationEpoch == 0 || len(receipt.AuthenticatedArtifactSHA256) != 64 {
		return false
	}
	for _, r := range receipt.AuthenticatedArtifactSHA256 {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return receipt.ContentID == strings.TrimSpace(receipt.ContentID)
}
