// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"kurdistan/internal/operator/controlplane"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
)

const profileIntentSourceSchema = "phase16-profile-issuance-intent-source-v1"
const profileFinalizationSourceSchema = "phase16-profile-finalization-source-v1"
const profileRevocationSourceSchema = "phase16-profile-revocation-source-v1"
const emergencyDenySourceSchema = "phase16-emergency-deny-source-v1"

type profileIntentSource struct {
	Schema string                      `json:"schema"`
	Spec   profile.OfflineIssuanceSpec `json:"spec"`
}

type profileFinalizationSource struct {
	Schema            string                      `json:"schema"`
	ParentOperationID string                      `json:"parent_operation_id"`
	Spec              profile.OfflineIssuanceSpec `json:"spec"`
	Artifact          []byte                      `json:"artifact"`
}

type activationSource struct {
	Artifact           []byte                           `json:"artifact"`
	Dispatch           envelope.ArtifactMetadata        `json:"dispatch"`
	Root               profile.RootSetArtifact          `json:"root"`
	Delegation         profile.SignedIssuerDelegationV1 `json:"delegation"`
	Revocations        profile.SignedRevocationSetV1    `json:"revocations"`
	Current            lifecycle.VerifiedState          `json:"current"`
	ContractVersion    string                           `json:"contract_version"`
	MinSafetyFloor     uint64                           `json:"minimum_safety_floor"`
	MinRootEpoch       uint64                           `json:"minimum_root_epoch"`
	MinRevocationEpoch uint64                           `json:"minimum_revocation_epoch"`
}

type profileRevocationSource struct {
	Schema      string                        `json:"schema"`
	Current     activationSource              `json:"current_profile"`
	Root        profile.RootSetArtifact       `json:"root"`
	Revocations profile.SignedRevocationSetV1 `json:"revocations"`
}

type emergencyDenySource struct {
	Schema     string                                     `json:"schema"`
	Root       profile.RootSetArtifact                    `json:"root"`
	Delegation profile.SignedEmergencyAuthorityDelegation `json:"delegation"`
	Action     profile.SignedEmergencyAction              `json:"action"`
}

// VerifiedSourceAdmitter supports the profile pre-signing entry point. Other
// actions remain fail-closed until their complete Phase 8/11 source adapters
// are registered; they can never fall back to digest authority.
type VerifiedSourceAdmitter struct {
	Verifier         profile.Verifier
	Resolver         profile.RecipientResolver
	Opener           profile.OfflineRecipientOpener
	ActivationOpener profile.RecipientOpener
}

func (admitter VerifiedSourceAdmitter) Admit(_ context.Context, request MutationRequest, snapshot controlplane.State, trusted controlplane.TrustedInstant) (controlplane.RequestInput, error) {
	if request.PathTarget != "" || !uniqueJSONKeys(request.AuthoritySource) {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	var envelope struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(request.AuthoritySource, &envelope); err != nil {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	switch envelope.Schema {
	case profileIntentSourceSchema:
		if request.Action != "profile.issue" && request.Action != "profile.rotate" {
			return controlplane.RequestInput{}, controlplane.ErrInvalidInput
		}
		return admitProfileIntent(request, snapshot, trusted)
	case profileFinalizationSourceSchema:
		if request.Action != "profile.issue" && request.Action != "profile.rotate" {
			return controlplane.RequestInput{}, controlplane.ErrInvalidInput
		}
		return admitProfileFinalization(request, snapshot, trusted, admitter)
	case profileRevocationSourceSchema:
		if request.Action != "profile.revoke" {
			return controlplane.RequestInput{}, controlplane.ErrInvalidInput
		}
		return admitProfileRevocation(request, snapshot, trusted, admitter)
	case emergencyDenySourceSchema:
		if request.Action != "emergency.deny" {
			return controlplane.RequestInput{}, controlplane.ErrInvalidInput
		}
		return admitEmergencyDeny(request, snapshot, trusted, admitter)
	default:
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
}

func admitProfileRevocation(request MutationRequest, snapshot controlplane.State, trusted controlplane.TrustedInstant, admitter VerifiedSourceAdmitter) (controlplane.RequestInput, error) {
	if admitter.Verifier == nil {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	var source profileRevocationSource
	if err := strictDecode(request.AuthoritySource, &source); err != nil || source.Schema != profileRevocationSourceSchema {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	currentRequest := activationRequest(source.Current, trusted.UnixSeconds, admitter)
	current, err := profile.VerifyActivationAdmission(currentRequest)
	if err != nil {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	currentProfile := current.Profile()
	record, exists := snapshot.Profiles[currentProfile.ProfileID]
	if !exists || record.State != controlplane.ProfileIssued ||
		request.ExpectedEpoch != record.Generation || record.Generation != currentProfile.Generation {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	input, err := controlplane.NewVerifiedProfileRevocationRequest(
		request.OperationID, current, source.Root, source.Revocations,
		admitter.Verifier, request.ExpectedRevision, request.IdempotencyKey, trusted.UnixSeconds,
	)
	if err != nil || input.ExpectedArtifactDigest != record.ArtifactDigest || input.ScopeDigest != record.ScopeDigest {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	return input, nil
}

func activationRequest(source activationSource, now int64, admitter VerifiedSourceAdmitter) profile.ActivationRequest {
	return profile.ActivationRequest{
		Artifact: source.Artifact, Dispatch: source.Dispatch, Now: now,
		Root: source.Root, Delegation: source.Delegation, Revocations: source.Revocations,
		Current: source.Current, Verifier: admitter.Verifier, Resolver: admitter.Resolver,
		Opener: admitter.ActivationOpener, ContractVersion: source.ContractVersion,
		MinSafetyFloor: source.MinSafetyFloor, MinRootEpoch: source.MinRootEpoch,
		MinRevocationEpoch: source.MinRevocationEpoch,
	}
}

func admitEmergencyDeny(request MutationRequest, snapshot controlplane.State, trusted controlplane.TrustedInstant, admitter VerifiedSourceAdmitter) (controlplane.RequestInput, error) {
	if admitter.Verifier == nil {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	var source emergencyDenySource
	if err := strictDecode(request.AuthoritySource, &source); err != nil || source.Schema != emergencyDenySourceSchema {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	authority, err := profile.VerifyEmergencyAuthorityDelegation(source.Root, source.Delegation, admitter.Verifier, trusted.UnixSeconds)
	if err != nil {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	return controlplane.NewVerifiedEmergencyRequestFromState(
		snapshot, request.OperationID, authority, source.Action, admitter.Verifier,
		request.ExpectedRevision, request.ExpectedEpoch, request.IdempotencyKey, trusted.UnixSeconds,
	)
}

func admitProfileIntent(request MutationRequest, snapshot controlplane.State, trusted controlplane.TrustedInstant) (controlplane.RequestInput, error) {
	var source profileIntentSource
	if err := strictDecode(request.AuthoritySource, &source); err != nil || source.Schema != profileIntentSourceSchema {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	source.Spec.Now = trusted.UnixSeconds
	intent, err := profile.VerifyIssuanceIntent(source.Spec)
	if err != nil {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	if request.Action == "profile.issue" {
		if request.ExpectedEpoch != 0 || source.Spec.Profile.UpdateKind != "initial" {
			return controlplane.RequestInput{}, controlplane.ErrInvalidInput
		}
		input, _, err := controlplane.NewVerifiedProfileIssuanceIntentRequest(
			request.OperationID, intent, request.ExpectedRevision, request.IdempotencyKey,
		)
		return input, err
	}
	current, exists := snapshot.Profiles[source.Spec.Profile.ProfileID]
	if !exists || request.ExpectedEpoch != current.Generation {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	input, _, err := controlplane.NewVerifiedProfileRotationIntentRequest(
		request.OperationID, current, intent, request.ExpectedRevision, request.IdempotencyKey,
	)
	return input, err
}

func admitProfileFinalization(request MutationRequest, snapshot controlplane.State, trusted controlplane.TrustedInstant, admitter VerifiedSourceAdmitter) (controlplane.RequestInput, error) {
	if admitter.Verifier == nil {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	var source profileFinalizationSource
	if err := strictDecode(request.AuthoritySource, &source); err != nil || source.Schema != profileFinalizationSourceSchema || len(source.Artifact) == 0 {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	parent, exists := snapshot.Operations[source.ParentOperationID]
	if !exists {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	source.Spec.Now = trusted.UnixSeconds
	intent, err := profile.VerifyIssuanceIntent(source.Spec)
	if err != nil || intent.SigningInputSHA256() != parent.SubjectDigest {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	verified, err := profile.VerifyIssuedArtifact(intent, source.Artifact, admitter.Verifier, admitter.Resolver, admitter.Opener)
	if err != nil {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	input, _, err := controlplane.NewVerifiedProfileFinalizationRequest(
		request.OperationID, parent, verified, request.ExpectedRevision, request.IdempotencyKey, trusted.UnixSeconds,
	)
	if err == nil && ((request.Action == "profile.issue" && input.Action != controlplane.ActionIssueProfile) ||
		(request.Action == "profile.rotate" && input.Action != controlplane.ActionRotateProfile)) {
		return controlplane.RequestInput{}, controlplane.ErrInvalidInput
	}
	return input, err
}

func strictDecode(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return controlplane.ErrInvalidInput
	}
	return nil
}

var _ AuthorityAdmitter = VerifiedSourceAdmitter{}
