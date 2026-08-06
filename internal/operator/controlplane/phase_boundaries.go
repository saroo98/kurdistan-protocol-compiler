// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/sessionplan"
)

type requestProofKind string

const (
	requestProofIssuanceIntent requestProofKind = "phase8-issuance-intent"
	requestProofProfile        requestProofKind = "phase8-profile"
	requestProofRevocation     requestProofKind = "phase8-revocation"
	requestProofRelay          requestProofKind = "phase11-relay"
	requestProofEmergency      requestProofKind = "phase8-emergency"
)

// NewVerifiedProfileIssuanceIntentRequest admits an exact Phase 8 pre-signing
// intent for approval before an HSM produces randomized signature or sealing
// output. Executing this request creates only a durable signing obligation. A
// profile is not issued until a separately verified exact artifact is
// finalized.
func NewVerifiedProfileIssuanceIntentRequest(
	id string,
	verified profile.VerifiedIssuanceIntent,
	expectedRevision uint64,
	idempotencyKey string,
) (RequestInput, profile.RedactedInspection, error) {
	spec := verified.Specification()
	if !validID(spec.Profile.ProfileID) || spec.Profile.Generation == 0 ||
		!validDigest(verified.SigningInputSHA256()) {
		return RequestInput{}, profile.RedactedInspection{}, ErrInvalidInput
	}
	input := RequestInput{
		ID: id, Action: ActionPrepareProfileIssue, TargetID: spec.Profile.ProfileID,
		SubjectDigest:    verified.SigningInputSHA256(),
		ScopeDigest:      DigestLabel(spec.Profile.ProviderID + "|" + spec.Profile.LineageID + "|" + spec.Profile.RevocationScope),
		ExpectedRevision: expectedRevision,
		ExpectedEpoch:    0,
		ResultEpoch:      spec.Profile.Generation,
		CreatedAt:        spec.Now,
		ExpiresAt:        spec.Profile.ValidUntil,
		IdempotencyKey:   idempotencyKey,
	}
	if input.ExpiresAt <= input.CreatedAt {
		return RequestInput{}, profile.RedactedInspection{}, ErrExpired
	}
	return sealRequestInput(input, requestProofIssuanceIntent), verified.Inspection(), nil
}

// NewVerifiedProfileRotationIntentRequest binds a replacement signing input
// to the exact current durable profile before any randomized HSM output is
// produced. The replacement still requires a separately verified artifact
// and a second dual-control operation before it becomes current.
func NewVerifiedProfileRotationIntentRequest(
	id string,
	current ProfileRecord,
	verified profile.VerifiedIssuanceIntent,
	expectedRevision uint64,
	idempotencyKey string,
) (RequestInput, profile.RedactedInspection, error) {
	spec := verified.Specification()
	scopeDigest := DigestLabel(spec.Profile.ProviderID + "|" + spec.Profile.LineageID + "|" + spec.Profile.RevocationScope)
	if current.State != ProfileIssued || !validID(spec.Profile.ProfileID) ||
		spec.Profile.ProfileID != current.ID || spec.Profile.UpdateKind != "replacement" ||
		spec.Profile.Generation != current.Generation+1 || scopeDigest != current.ScopeDigest ||
		!validDigest(current.ArtifactDigest) || !validDigest(verified.SigningInputSHA256()) {
		return RequestInput{}, profile.RedactedInspection{}, ErrInvalidInput
	}
	input := RequestInput{
		ID: id, Action: ActionPrepareProfileRotate, TargetID: spec.Profile.ProfileID,
		SubjectDigest:          verified.SigningInputSHA256(),
		ScopeDigest:            scopeDigest,
		ExpectedArtifactDigest: current.ArtifactDigest,
		ExpectedRevision:       expectedRevision,
		ExpectedEpoch:          current.Generation,
		ResultEpoch:            spec.Profile.Generation,
		CreatedAt:              spec.Now,
		ExpiresAt:              spec.Profile.ValidUntil,
		IdempotencyKey:         idempotencyKey,
	}
	if input.ExpiresAt <= input.CreatedAt {
		return RequestInput{}, profile.RedactedInspection{}, ErrExpired
	}
	return sealRequestInput(input, requestProofIssuanceIntent), verified.Inspection(), nil
}

type requestProof struct {
	kind   requestProofKind
	digest [sha256.Size]byte
}

type requestProofMaterial struct {
	Kind                   requestProofKind  `json:"kind"`
	ID                     string            `json:"id"`
	Action                 Action            `json:"action"`
	TargetID               string            `json:"target_id"`
	ParentOperationID      string            `json:"parent_operation_id"`
	SubjectDigest          string            `json:"subject_digest"`
	ScopeDigest            string            `json:"scope_digest"`
	AuthorityScopeDigest   string            `json:"authority_scope_digest"`
	AuthorityRootDigest    string            `json:"authority_root_digest"`
	ExpectedArtifactDigest string            `json:"expected_artifact_digest"`
	ExpectedRevision       uint64            `json:"expected_revision"`
	ExpectedEpoch          uint64            `json:"expected_epoch"`
	ResultEpoch            uint64            `json:"result_epoch"`
	CreatedAt              int64             `json:"created_at"`
	ExpiresAt              int64             `json:"expires_at"`
	IdempotencyKey         string            `json:"idempotency_key"`
	Publication            *PublicationInput `json:"publication"`
}

// NewVerifiedProfileFinalizationRequest binds exact independently verified
// artifact bytes to a delivered pre-signing operation. It deliberately creates
// a second dual-control operation over the final randomized bytes before the
// profile can become issued.
func NewVerifiedProfileFinalizationRequest(
	id string,
	parent Operation,
	verified profile.VerifiedIssuedArtifact,
	expectedRevision uint64,
	idempotencyKey string,
	now int64,
) (RequestInput, profile.RedactedInspection, error) {
	if (parent.Action != ActionPrepareProfileIssue && parent.Action != ActionPrepareProfileRotate) || parent.State != OperationExecuted ||
		parent.SubjectDigest != verified.SigningInputSHA256() ||
		parent.TargetID != verified.ProfileID() ||
		parent.ScopeDigest != DigestLabel(verified.ScopeDigestInput()) ||
		parent.ResultEpoch != verified.Generation() ||
		!validDigest(verified.ArtifactSHA256()) || now <= 0 {
		return RequestInput{}, profile.RedactedInspection{}, ErrInvalidInput
	}
	expiresAt := parent.ExpiresAt
	if verified.ValidUntil() < expiresAt {
		expiresAt = verified.ValidUntil()
	}
	action := ActionIssueProfile
	if parent.Action == ActionPrepareProfileRotate {
		action = ActionRotateProfile
	}
	input := RequestInput{
		ID: id, Action: action, TargetID: verified.ProfileID(),
		ParentOperationID:      parent.ID,
		SubjectDigest:          verified.ArtifactSHA256(),
		ScopeDigest:            parent.ScopeDigest,
		ExpectedArtifactDigest: parent.ExpectedArtifactDigest,
		ExpectedRevision:       expectedRevision,
		ExpectedEpoch:          parent.ExpectedEpoch,
		ResultEpoch:            verified.Generation(),
		CreatedAt:              now,
		ExpiresAt:              expiresAt,
		IdempotencyKey:         idempotencyKey,
	}
	if input.ExpiresAt <= input.CreatedAt {
		return RequestInput{}, profile.RedactedInspection{}, ErrExpired
	}
	return sealRequestInput(input, requestProofProfile), verified.Inspection(), nil
}

// NewVerifiedProfileIssueRequest admits only an initial Phase 8 artifact
// against an absent lifecycle state.
func NewVerifiedProfileIssueRequest(
	id string,
	request profile.ActivationRequest,
	expectedRevision uint64,
	idempotencyKey string,
) (RequestInput, profile.RedactedInspection, error) {
	verified, err := profile.VerifyInitialActivationAdmission(request)
	if err != nil {
		return RequestInput{}, profile.RedactedInspection{}, fmt.Errorf("%w: Phase 8 verification failed", ErrInvalidInput)
	}
	profileValue := verified.Profile()
	if !validID(profileValue.ProfileID) || profileValue.Generation == 0 {
		return RequestInput{}, profile.RedactedInspection{}, ErrInvalidInput
	}
	expiresAt := profileAdmissionExpiry(request, profileValue.ValidUntil)
	artifactDigest := sha256.Sum256(verified.ExactArtifact())
	input := RequestInput{
		ID: id, Action: ActionIssueProfile, TargetID: profileValue.ProfileID,
		SubjectDigest:    hex.EncodeToString(artifactDigest[:]),
		ScopeDigest:      DigestLabel(profileValue.ProviderID + "|" + profileValue.LineageID + "|" + profileValue.RevocationScope),
		ExpectedRevision: expectedRevision,
		ExpectedEpoch:    0,
		ResultEpoch:      profileValue.Generation,
		CreatedAt:        request.Now,
		ExpiresAt:        expiresAt,
		IdempotencyKey:   idempotencyKey,
	}
	if input.ExpiresAt <= input.CreatedAt {
		return RequestInput{}, profile.RedactedInspection{}, ErrExpired
	}
	return sealRequestInput(input, requestProofProfile), verified.Inspection(), nil
}

// NewVerifiedProfileRotationRequest admits only the next replacement bound to
// the exact opaque current admission and retains its artifact digest as an
// execution precondition.
func NewVerifiedProfileRotationRequest(
	id string,
	current profile.VerifiedActivationAdmission,
	request profile.ActivationRequest,
	expectedRevision uint64,
	idempotencyKey string,
) (RequestInput, profile.RedactedInspection, error) {
	verified, err := profile.VerifyReplacementActivationAdmission(current, request)
	if err != nil {
		return RequestInput{}, profile.RedactedInspection{}, fmt.Errorf("%w: Phase 8 replacement verification failed", ErrInvalidInput)
	}
	profileValue := verified.Profile()
	if !validID(profileValue.ProfileID) || profileValue.Generation < 2 {
		return RequestInput{}, profile.RedactedInspection{}, ErrInvalidInput
	}
	expiresAt := profileAdmissionExpiry(request, profileValue.ValidUntil)
	artifactDigest := sha256.Sum256(verified.ExactArtifact())
	currentDigest := sha256.Sum256(current.ExactArtifact())
	input := RequestInput{
		ID: id, Action: ActionRotateProfile, TargetID: profileValue.ProfileID,
		SubjectDigest:          hex.EncodeToString(artifactDigest[:]),
		ScopeDigest:            DigestLabel(profileValue.ProviderID + "|" + profileValue.LineageID + "|" + profileValue.RevocationScope),
		ExpectedArtifactDigest: hex.EncodeToString(currentDigest[:]),
		ExpectedRevision:       expectedRevision,
		ExpectedEpoch:          profileValue.Generation - 1,
		ResultEpoch:            profileValue.Generation,
		CreatedAt:              request.Now,
		ExpiresAt:              expiresAt,
		IdempotencyKey:         idempotencyKey,
	}
	if input.ExpiresAt <= input.CreatedAt {
		return RequestInput{}, profile.RedactedInspection{}, ErrExpired
	}
	return sealRequestInput(input, requestProofProfile), verified.Inspection(), nil
}

func profileAdmissionExpiry(request profile.ActivationRequest, profileExpiry int64) int64 {
	expiresAt := profileExpiry
	for _, candidate := range []int64{
		request.Root.ValidUntil,
		request.Delegation.Artifact.ValidUntil,
		request.Revocations.Set.ExpiresAt,
	} {
		if candidate < expiresAt {
			expiresAt = candidate
		}
	}
	return expiresAt
}

// NewVerifiedProfileRevocationRequest accepts only a root-bound, fresh signed
// revocation set that revokes the exact content from an opaque Phase 8
// admission.
func NewVerifiedProfileRevocationRequest(
	id string,
	current profile.VerifiedActivationAdmission,
	root profile.RootSetArtifact,
	signed profile.SignedRevocationSetV1,
	verifier profile.Verifier,
	expectedRevision uint64,
	idempotencyKey string,
	now int64,
) (RequestInput, error) {
	profileValue := current.Profile()
	if !validID(profileValue.ProfileID) || profileValue.Generation == 0 {
		return RequestInput{}, ErrInvalidInput
	}
	verified, err := profile.VerifySignedRevocationSet(root, signed, verifier, now)
	if err != nil {
		return RequestInput{}, fmt.Errorf("%w: signed revocation verification failed", ErrInvalidInput)
	}
	set := verified.Set()
	if set.Scope != profileValue.RevocationScope ||
		set.Epoch != profileValue.RevocationEpoch+1 ||
		!verified.RevokesContent(profileValue.ContentID) {
		return RequestInput{}, fmt.Errorf("%w: revocation does not bind current profile content", ErrInvalidInput)
	}
	payloadDigest := sha256.Sum256(verified.Payload())
	currentDigest := sha256.Sum256(current.ExactArtifact())
	expiresAt := set.ExpiresAt
	for _, candidate := range []int64{root.ValidUntil, profileValue.ValidUntil} {
		if candidate < expiresAt {
			expiresAt = candidate
		}
	}
	input := RequestInput{
		ID: id, Action: ActionRevokeProfile, TargetID: profileValue.ProfileID,
		SubjectDigest:          hex.EncodeToString(payloadDigest[:]),
		ScopeDigest:            DigestLabel(profileValue.ProviderID + "|" + profileValue.LineageID + "|" + profileValue.RevocationScope),
		ExpectedArtifactDigest: hex.EncodeToString(currentDigest[:]),
		ExpectedRevision:       expectedRevision,
		ExpectedEpoch:          profileValue.Generation,
		ResultEpoch:            profileValue.Generation + 1,
		CreatedAt:              now,
		ExpiresAt:              expiresAt,
		IdempotencyKey:         idempotencyKey,
	}
	if input.ExpiresAt <= input.CreatedAt {
		return RequestInput{}, ErrExpired
	}
	return sealRequestInput(input, requestProofRevocation), nil
}

// NewVerifiedRelayRequest reruns the authoritative Phase 11 Build and Admit
// path from the complete request before reducing the result to control-plane
// digests.
func NewVerifiedRelayRequest(
	id string,
	action Action,
	request sessionplan.Request,
	expectedRevision, expectedEpoch uint64,
	idempotencyKey string,
) (RequestInput, error) {
	plan, err := sessionplan.Build(request)
	if err != nil {
		return RequestInput{}, fmt.Errorf("%w: Phase 11 session plan failed validation", ErrInvalidInput)
	}
	return newRelayRequestFromVerifiedPlan(
		id, action, plan, expectedRevision, expectedEpoch,
		idempotencyKey, request.RelayRequest.EvaluationTime,
		relayDescriptorExpiry(request),
	)
}

func relayDescriptorExpiry(request sessionplan.Request) int64 {
	for _, descriptor := range request.RelayRequest.Descriptors {
		if descriptor.DescriptorID == request.DescriptorID {
			return descriptor.ExpiresAt
		}
	}
	return 0
}

// NewRelayRequestFromPlan fails closed because Plan contains exported fields and
// a reproducible checksum, not authoritative Phase 11 provenance.
func NewRelayRequestFromPlan(
	id string,
	action Action,
	plan sessionplan.Plan,
	expectedRevision, expectedEpoch uint64,
	idempotencyKey string,
	createdAt, expiresAt int64,
) (RequestInput, error) {
	return RequestInput{}, fmt.Errorf("%w: caller-provided Phase 11 plans are not authoritative", ErrInvalidInput)
}

func newRelayRequestFromVerifiedPlan(
	id string,
	action Action,
	plan sessionplan.Plan,
	expectedRevision, expectedEpoch uint64,
	idempotencyKey string,
	createdAt, expiresAt int64,
) (RequestInput, error) {
	switch action {
	case ActionEnrollRelay, ActionPromoteRelay, ActionDrainRelay,
		ActionRetireRelay, ActionQuarantineRelay, ActionRevokeRelay:
	default:
		return RequestInput{}, ErrInvalidInput
	}
	if !validID(plan.DescriptorID) {
		return RequestInput{}, fmt.Errorf("%w: Phase 11 session plan failed validation", ErrInvalidInput)
	}
	input := RequestInput{
		ID: id, Action: action, TargetID: plan.DescriptorID,
		SubjectDigest:    DigestLabel(plan.DescriptorID + "|" + plan.EndpointReference),
		ScopeDigest:      hex.EncodeToString(plan.Digest[:]),
		ExpectedRevision: expectedRevision,
		ExpectedEpoch:    expectedEpoch,
		ResultEpoch:      expectedEpoch + 1,
		CreatedAt:        createdAt,
		ExpiresAt:        expiresAt,
		IdempotencyKey:   idempotencyKey,
	}
	if input.ExpiresAt <= input.CreatedAt {
		return RequestInput{}, ErrExpired
	}
	return sealRequestInput(input, requestProofRelay), nil
}

// NewVerifiedEmergencyRequest accepts only a canonically encoded and signed
// Phase 8 emergency deny under the exact durable current authority. The action
// scope and authority scope are sealed separately so a strictly narrower deny
// remains executable without confusing restriction identity with authority
// lookup identity.
func (service *Service) NewVerifiedEmergencyRequest(
	id string,
	trusted profile.VerifiedEmergencyAuthority,
	signed profile.SignedEmergencyAction,
	verifier profile.Verifier,
	expectedRevision, currentEpoch uint64,
	idempotencyKey string,
	now int64,
) (RequestInput, error) {
	if service == nil {
		return RequestInput{}, ErrInvalidInput
	}
	return NewVerifiedEmergencyRequestFromState(
		service.store.Snapshot(), id, trusted, signed, verifier,
		expectedRevision, currentEpoch, idempotencyKey, now,
	)
}

// NewVerifiedEmergencyRequestFromState is the production transaction-store
// boundary for an exact root-bound emergency deny. The caller must supply the
// strongly read durable state; this function reruns the complete signed-action
// verification and binds it to the currently installed delegation.
func NewVerifiedEmergencyRequestFromState(
	current State,
	id string,
	trusted profile.VerifiedEmergencyAuthority,
	signed profile.SignedEmergencyAction,
	verifier profile.Verifier,
	expectedRevision, currentEpoch uint64,
	idempotencyKey string,
	now int64,
) (RequestInput, error) {
	if err := current.Validate(); err != nil {
		return RequestInput{}, ErrInvalidInput
	}
	binding, err := trusted.CurrentBinding(now)
	if err != nil {
		return RequestInput{}, fmt.Errorf("%w: emergency authority is not current", ErrInvalidInput)
	}
	authority, exists := current.EmergencyAuthorities[emergencyScopeDigest(binding.Scope)]
	if expectedRevision != current.Revision || !exists || !recordMatchesBinding(authority, binding) {
		return RequestInput{}, fmt.Errorf("%w: emergency authority is not the durable current authority", ErrInvalidInput)
	}
	verified, err := profile.VerifySignedEmergencyAction(trusted, signed, currentEpoch, now, verifier)
	if err != nil {
		return RequestInput{}, fmt.Errorf("%w: signed emergency verification failed", ErrInvalidInput)
	}
	action := verified.Action()
	if action.Kind != profile.EmergencyDeny {
		return RequestInput{}, fmt.Errorf("%w: emergency narrowing requires parent-scope state", ErrInvalidInput)
	}
	delegationDigest := sha256.Sum256(trusted.DelegationPayload())
	actionDigest := sha256.Sum256(signed.Payload)
	authorityAndAction := append(delegationDigest[:], actionDigest[:]...)
	payloadDigest := sha256.Sum256(authorityAndAction)
	input := RequestInput{
		ID: id, Action: ActionEmergencyDeny, TargetID: id,
		SubjectDigest:          hex.EncodeToString(payloadDigest[:]),
		ScopeDigest:            DigestLabel(action.Scope.ProviderID + "|" + action.Scope.LineageID + "|" + action.Scope.ProfileNamespace),
		AuthorityScopeDigest:   authority.ScopeDigest,
		AuthorityRootDigest:    authority.RootSetDigest,
		ExpectedArtifactDigest: authority.DelegationDigest,
		ExpectedRevision:       expectedRevision,
		ExpectedEpoch:          currentEpoch,
		ResultEpoch:            action.Epoch,
		CreatedAt:              now,
		ExpiresAt:              action.ValidUntil,
		IdempotencyKey:         idempotencyKey,
	}
	return sealRequestInput(input, requestProofEmergency), nil
}

func sealRequestInput(input RequestInput, kind requestProofKind) RequestInput {
	input.proof = requestProof{kind: kind, digest: requestProofDigest(input, kind)}
	return input
}

func validateRequestProof(input RequestInput) error {
	expectedKind, required := requiredRequestProof(input.Action)
	if !required {
		return nil
	}
	if input.proof.kind != expectedKind ||
		input.proof.digest != requestProofDigest(input, expectedKind) {
		return ErrInvalidInput
	}
	return nil
}

func requiredRequestProof(action Action) (requestProofKind, bool) {
	switch action {
	case ActionPrepareProfileIssue, ActionPrepareProfileRotate:
		return requestProofIssuanceIntent, true
	case ActionIssueProfile, ActionRotateProfile:
		return requestProofProfile, true
	case ActionRevokeProfile:
		return requestProofRevocation, true
	case ActionEnrollRelay, ActionPromoteRelay, ActionDrainRelay,
		ActionRetireRelay, ActionQuarantineRelay, ActionRevokeRelay:
		return requestProofRelay, true
	case ActionEmergencyDeny, ActionEmergencyNarrow:
		return requestProofEmergency, true
	default:
		return "", false
	}
}

func requestProofDigest(input RequestInput, kind requestProofKind) [sha256.Size]byte {
	raw, err := json.Marshal(requestProofMaterial{
		Kind:                   kind,
		ID:                     input.ID,
		Action:                 input.Action,
		TargetID:               input.TargetID,
		ParentOperationID:      input.ParentOperationID,
		SubjectDigest:          input.SubjectDigest,
		ScopeDigest:            input.ScopeDigest,
		AuthorityScopeDigest:   input.AuthorityScopeDigest,
		AuthorityRootDigest:    input.AuthorityRootDigest,
		ExpectedArtifactDigest: input.ExpectedArtifactDigest,
		ExpectedRevision:       input.ExpectedRevision,
		ExpectedEpoch:          input.ExpectedEpoch,
		ResultEpoch:            input.ResultEpoch,
		CreatedAt:              input.CreatedAt,
		ExpiresAt:              input.ExpiresAt,
		IdempotencyKey:         input.IdempotencyKey,
		Publication:            input.Publication,
	})
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(raw)
}
