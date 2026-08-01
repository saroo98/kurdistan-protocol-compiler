// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
)

// VerifiedActivationAdmission is an opaque result from the authoritative
// Phase 8 activation-policy validator. Callers can inspect defensive copies,
// but cannot construct or alter the proof itself.
type VerifiedActivationAdmission struct {
	record     ActivationRecord
	inspection RedactedInspection
}

// VerifyActivationAdmission runs the same trust, delegation, revocation,
// lifecycle, and policy validation used by the activation transaction without
// mutating the supplied persistence provider.
func VerifyActivationAdmission(request ActivationRequest) (VerifiedActivationAdmission, error) {
	candidate, err := verifyActivationCandidate(request, request.Artifact)
	if err != nil {
		return VerifiedActivationAdmission{}, err
	}
	digest := sha256.Sum256(candidate.record.SignedObject)
	return VerifiedActivationAdmission{
		record: cloneActivationRecord(candidate.record),
		inspection: RedactedInspection{
			Class:         string(request.Dispatch.Class),
			Audience:      request.Dispatch.AudienceClass,
			ContentSHA256: hex.EncodeToString(digest[:]),
			Suite:         envelope.SuiteClassicalV1,
			Generation:    candidate.record.Profile.Generation,
			ValidUntil:    candidate.record.Profile.ValidUntil,
			Sealed:        request.Dispatch.Class != envelope.ArtifactSignedPublic,
		},
	}, nil
}

// VerifyInitialActivationAdmission admits only an initial profile against an
// absent lifecycle state. It cannot be used as rotation authority.
func VerifyInitialActivationAdmission(request ActivationRequest) (VerifiedActivationAdmission, error) {
	verified, err := VerifyActivationAdmission(request)
	if err != nil {
		return VerifiedActivationAdmission{}, err
	}
	profileValue := verified.record.Profile
	empty := lifecycle.VerifiedState{}
	explicitAbsent := lifecycle.VerifiedState{State: lifecycle.State{Status: lifecycle.Absent}}
	if profileValue.UpdateKind != "initial" ||
		(request.Current != empty && request.Current != explicitAbsent) {
		return VerifiedActivationAdmission{}, fmt.Errorf("%w: initial admission requires absent state", ErrOfflineVerify)
	}
	return verified, nil
}

// VerifyReplacementActivationAdmission admits only a same-provider replacement
// whose exact current verified lifecycle state came from the opaque admission
// supplied by the caller. Provider migration remains a separate, unavailable
// control-plane transition.
func VerifyReplacementActivationAdmission(
	current VerifiedActivationAdmission,
	request ActivationRequest,
) (VerifiedActivationAdmission, error) {
	if len(current.record.Artifact) == 0 || request.Current != current.record.State {
		return VerifiedActivationAdmission{}, fmt.Errorf("%w: replacement current state is not the admitted artifact", ErrOfflineVerify)
	}
	verified, err := VerifyActivationAdmission(request)
	if err != nil {
		return VerifiedActivationAdmission{}, err
	}
	profileValue := verified.record.Profile
	if profileValue.UpdateKind != "replacement" ||
		profileValue.ProfileID != current.record.Profile.ProfileID ||
		profileValue.LineageID != current.record.Profile.LineageID ||
		profileValue.Generation != current.record.Profile.Generation+1 {
		return VerifiedActivationAdmission{}, fmt.Errorf("%w: replacement is not the next exact lifecycle record", ErrOfflineVerify)
	}
	return verified, nil
}

func (verified VerifiedActivationAdmission) Profile() envelope.CanonicalProfileV1 {
	return cloneCanonicalProfile(verified.record.Profile)
}

func (verified VerifiedActivationAdmission) ExactArtifact() []byte {
	return bytes.Clone(verified.record.Artifact)
}

func (verified VerifiedActivationAdmission) Inspection() RedactedInspection {
	return verified.inspection
}

// CurrentState returns the verified lifecycle state represented by this
// admission. It is descriptive only; replacement verification still requires
// the opaque admission and compares this state internally.
func (verified VerifiedActivationAdmission) CurrentState() lifecycle.VerifiedState {
	return verified.record.State
}
