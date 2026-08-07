// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"

	"github.com/fxamacker/cbor/v2"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
)

// ActivationStage names the observable, fixed-order verification and commit
// checkpoints. It contains no profile data and is safe to expose in tests and
// redacted diagnostics.
type ActivationStage string

const (
	StageOuterParsed              ActivationStage = "outer-parsed"
	StageRecipientOpened          ActivationStage = "recipient-opened"
	StageSignedObjectParsed       ActivationStage = "signed-object-parsed"
	StageDelegationVerified       ActivationStage = "delegation-verified"
	StageRevocationsVerified      ActivationStage = "revocations-verified"
	StageProfileSignatureVerified ActivationStage = "profile-signature-verified"
	StageDispatchMatched          ActivationStage = "dispatch-matched"
	StageProfileSemanticsDecoded  ActivationStage = "profile-semantics-decoded"
	StagePolicyValidated          ActivationStage = "policy-validated"
	StageCandidateStored          ActivationStage = "candidate-stored"
	StageCandidateReopened        ActivationStage = "candidate-reopened"
	StageActivationMarked         ActivationStage = "activation-marked"
	StageActivationCommitted      ActivationStage = "activation-committed"
	StageActivationFinalized      ActivationStage = "activation-finalized"
)

type ActivationReasonCode string

const (
	ActivationInvalidArtifact   ActivationReasonCode = "P8-ACT-INVALID-ARTIFACT"
	ActivationTrustRejected     ActivationReasonCode = "P8-ACT-TRUST-REJECTED"
	ActivationPolicyRejected    ActivationReasonCode = "P8-ACT-POLICY-REJECTED"
	ActivationStorageFailure    ActivationReasonCode = "P8-ACT-STORAGE-FAILURE"
	ActivationRecoveryFailure   ActivationReasonCode = "P8-ACT-RECOVERY-FAILED"
	ActivationQuarantineFailure ActivationReasonCode = "P8-ACT-QUARANTINE-FAILED"
)

type ActivationError struct{ Code ActivationReasonCode }

func (e *ActivationError) Error() string { return string(e.Code) }

type SignedIssuerDelegationV1 struct {
	Artifact  IssuerDelegationArtifact
	RootKey   KeyReference
	Payload   []byte
	Signature []byte
}

type RevocationSetV1 struct {
	Version                 uint64
	Scope                   string
	RootEpoch, Epoch        uint64
	IssuedAt, ExpiresAt     int64
	MaxOfflineStalenessSecs uint64
	RevokedIssuerKeyIDs     []string
	RevokedContentIDs       []string
	EmergencyDenied         bool
}

type SignedRevocationSetV1 struct {
	Set       RevocationSetV1
	RootKey   KeyReference
	Payload   []byte
	Signature []byte
}

type ActivationRecord struct {
	Artifact     []byte
	SignedObject []byte
	Profile      envelope.CanonicalProfileV1
	State        lifecycle.VerifiedState
}

type TransactionalActivationProvider interface {
	Snapshot() (active, lastKnownGood ActivationRecord, err error)
	StageCandidate(ActivationRecord) error
	ReopenCandidate() (ActivationRecord, error)
	MarkActivation() error
	CommitMarked() error
	FinalizeActivation() error
	Recover() error
	Quarantine() error
}

type ActivationRequest struct {
	Artifact []byte
	// UnwrapArtifact verifies an application-owned outer envelope and returns
	// the exact native signed or recipient-sealed profile artifact. The
	// activation record remains bound to Artifact, so durable reopen repeats
	// this callback over the exact outer bytes.
	UnwrapArtifact func([]byte) ([]byte, error)
	// UnwrapSignedObject verifies an application-owned outer envelope and
	// returns its exact signed profile object. The persisted activation record
	// remains bound to Artifact, so reopen verification repeats this callback
	// over the exact outer bytes. Nil preserves the native Phase 8 envelope path.
	UnwrapSignedObject func([]byte) ([]byte, error)
	Dispatch           envelope.ArtifactMetadata
	Now                int64
	Root               RootSetArtifact
	Delegation         SignedIssuerDelegationV1
	Revocations        SignedRevocationSetV1
	Current            lifecycle.VerifiedState
	Verifier           Verifier
	Resolver           RecipientResolver
	Opener             RecipientOpener
	OfflineOpener      OfflineRecipientOpener
	Storage            TransactionalActivationProvider
	ContractVersion    string
	MinSafetyFloor     uint64
	MinRootEpoch       uint64
	MinRevocationEpoch uint64
	Observe            func(ActivationStage)
}

type verifiedCandidate struct {
	record  ActivationRecord
	profile envelope.CanonicalProfileV1
}

// ActivateVerifiedProfile verifies twice around persistence and exposes the
// candidate only after exact-byte reopen verification has succeeded.
func ActivateVerifiedProfile(request ActivationRequest) (ActivationRecord, error) {
	if request.Storage == nil {
		return ActivationRecord{}, activationFailure(ActivationStorageFailure)
	}
	session := NewActivationSession(request)
	for {
		command, ok := session.Next()
		if !ok {
			return session.Result()
		}
		result := ActivationCommandResult{}
		switch command.Kind {
		case ActivationCommandSnapshot:
			result.Active, result.LastKnownGood, result.Err = request.Storage.Snapshot()
		case ActivationCommandStageCandidate:
			result.Err = request.Storage.StageCandidate(cloneActivationRecord(command.Record))
		case ActivationCommandReopenCandidate:
			result.Record, result.Err = request.Storage.ReopenCandidate()
		case ActivationCommandMarkActivation:
			result.Err = request.Storage.MarkActivation()
		case ActivationCommandCommitMarked:
			result.Err = request.Storage.CommitMarked()
		case ActivationCommandFinalizeActivation:
			result.Err = request.Storage.FinalizeActivation()
		case ActivationCommandRecover:
			result.Err = request.Storage.Recover()
		case ActivationCommandQuarantine:
			result.Err = request.Storage.Quarantine()
		default:
			return ActivationRecord{}, activationFailure(ActivationPolicyRejected)
		}
		if err := session.Submit(command, result); err != nil {
			return ActivationRecord{}, err
		}
	}
}

func verifyActivationCandidate(request ActivationRequest, artifact []byte) (verifiedCandidate, error) {
	if len(artifact) == 0 || len(artifact) > envelope.MaxTotalInputBytes || request.Verifier == nil {
		return verifiedCandidate{}, activationFailure(ActivationInvalidArtifact)
	}
	if err := envelope.ValidateArtifactMetadata(request.Dispatch); err != nil {
		return verifiedCandidate{}, activationFailure(ActivationInvalidArtifact)
	}
	var signedObject []byte
	var err error
	var outer *envelope.SealProtectedContextV1
	var recipient *RecipientBinding
	nativeArtifact := bytes.Clone(artifact)
	if request.UnwrapArtifact != nil {
		if request.UnwrapSignedObject != nil {
			return verifiedCandidate{}, activationFailure(ActivationInvalidArtifact)
		}
		nativeArtifact, err = request.UnwrapArtifact(bytes.Clone(artifact))
		if err != nil || len(nativeArtifact) == 0 || len(nativeArtifact) > envelope.MaxTotalInputBytes {
			return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
		}
	}
	if request.UnwrapSignedObject != nil {
		if request.Dispatch.Class != envelope.ArtifactSignedPublic || request.Resolver != nil || request.Opener != nil || request.OfflineOpener != nil {
			return verifiedCandidate{}, activationFailure(ActivationInvalidArtifact)
		}
		signedObject, err = request.UnwrapSignedObject(bytes.Clone(artifact))
		if err != nil || len(signedObject) == 0 || len(signedObject) > envelope.MaxTotalInputBytes {
			return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
		}
		observe(request, StageOuterParsed)
	} else if request.Dispatch.Class == envelope.ArtifactSignedPublic {
		if request.Resolver != nil || request.Opener != nil || request.OfflineOpener != nil {
			return verifiedCandidate{}, activationFailure(ActivationInvalidArtifact)
		}
		signedObject = bytes.Clone(nativeArtifact)
		observe(request, StageOuterParsed)
	} else {
		sealed, err := envelope.ParseSealedProfileOpaque(nativeArtifact)
		if err != nil || request.Resolver == nil || (request.Opener == nil) == (request.OfflineOpener == nil) {
			return verifiedCandidate{}, activationFailure(ActivationInvalidArtifact)
		}
		context, err := envelope.DecodeSealProtectedContextV1(sealed.Protected)
		if err != nil || context.Metadata != request.Dispatch || context.SuiteID != envelope.SuiteClassicalV1 || context.ContentType != envelope.SignedObjectContentType {
			return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
		}
		outer = &context
		observe(request, StageOuterParsed)
		resolved, err := ResolveRecipientForMetadata(request.Resolver, context.Metadata)
		if err != nil {
			return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
		}
		if request.OfflineOpener != nil {
			signedObject, err = request.OfflineOpener.OpenOffline(resolved, sealed.Protected, sealed.Encapsulation, sealed.Ciphertext)
		} else {
			signedObject, err = request.Opener.Open(resolved, sealed.Encapsulation, sealed.Ciphertext)
		}
		if err != nil || len(signedObject) == 0 || len(signedObject) > envelope.MaxSignedObjectBytes {
			return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
		}
		recipient = &resolved
		observe(request, StageRecipientOpened)
	}
	parsed, err := envelope.ParseSignedProfileOpaque(signedObject)
	if err != nil {
		return verifiedCandidate{}, activationFailure(ActivationInvalidArtifact)
	}
	observe(request, StageSignedObjectParsed)
	signedContext, err := envelope.DecodeSignedProtectedContextV1(parsed.Protected)
	if err != nil || signedContext.SuiteID != envelope.SuiteClassicalV1 || signedContext.ContentType != envelope.SignedPayloadContentType {
		return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
	}
	if err := verifyDelegation(request); err != nil {
		return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
	}
	observe(request, StageDelegationVerified)
	if err := verifyRevocations(request); err != nil {
		return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
	}
	observe(request, StageRevocationsVerified)
	if string(signedContext.KeyID) != request.Delegation.Artifact.IssuerKey.KeyID {
		return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
	}
	sigStructure, err := envelope.BuildCOSESigStructure(parsed.Protected, parsed.Payload)
	if err != nil || request.Verifier.Verify(request.Delegation.Artifact.IssuerKey, sigStructure, parsed.Signature) != nil {
		return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
	}
	observe(request, StageProfileSignatureVerified)
	if outer != nil && signedContext.Metadata != outer.Metadata {
		return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
	}
	if signedContext.Metadata != request.Dispatch {
		return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
	}
	observe(request, StageDispatchMatched)
	profileValue, err := envelope.DecodeCanonicalProfileV1(parsed.Payload)
	if err != nil {
		return verifiedCandidate{}, activationFailure(ActivationInvalidArtifact)
	}
	if recipient != nil && !RecipientBindingContainsProfile(*recipient, profileValue) {
		return verifiedCandidate{}, activationFailure(ActivationTrustRejected)
	}
	observe(request, StageProfileSemanticsDecoded)
	digest := sha256.Sum256(parsed.ExactObject)
	authenticatedDigest := hex.EncodeToString(digest[:])
	if err := validateActivationPolicy(request, profileValue, authenticatedDigest); err != nil {
		return verifiedCandidate{}, activationFailure(ActivationPolicyRejected)
	}
	observe(request, StagePolicyValidated)
	receipt := lifecycle.VerifiedReceipt{ContentID: profileValue.ContentID, ProviderID: profileValue.ProviderID, LineageID: profileValue.LineageID, AuthenticatedArtifactSHA256: authenticatedDigest, RootEpoch: profileValue.RootEpoch, RevocationEpoch: profileValue.RevocationEpoch, RecipientEpoch: signedContext.Metadata.RecipientEpoch}
	decision := lifecycle.VerifiedDecision{Decision: lifecycle.Decision{Action: lifecycle.Admit, ProfileID: profileValue.ProfileID, Scope: profileValue.RevocationScope, EvidenceReference: receipt.AuthenticatedArtifactSHA256, Generation: profileValue.Generation}, Receipt: receipt}
	next, err := lifecycle.ApplyVerified(request.Current, decision)
	if err != nil {
		return verifiedCandidate{}, activationFailure(ActivationPolicyRejected)
	}
	record := ActivationRecord{Artifact: bytes.Clone(artifact), SignedObject: bytes.Clone(parsed.ExactObject), Profile: cloneCanonicalProfile(profileValue), State: next}
	return verifiedCandidate{record: record, profile: profileValue}, nil
}

func verifyDelegation(request ActivationRequest) error {
	d := request.Delegation
	if err := validateActiveRootSet(request.Root, request.Now); err != nil || d.RootKey.validate() != nil || !rootContainsReference(request.Root, d.RootKey) || d.RootKey.KeyID != d.Artifact.RootKeyID || d.Artifact.RootEpoch != request.Root.Epoch {
		return errors.New("invalid delegation root")
	}
	canonical, err := EncodeIssuerDelegationV1(d.Artifact)
	if err != nil || !bytes.Equal(canonical, d.Payload) {
		return errors.New("non-canonical delegation")
	}
	return request.Verifier.Verify(d.RootKey, d.Payload, d.Signature)
}

func verifyRevocations(request ActivationRequest) error {
	r := request.Revocations
	if r.RootKey.validate() != nil || !rootContainsReference(request.Root, r.RootKey) || r.RootKey.KeyID != request.Delegation.Artifact.RootKeyID || r.Set.RootEpoch != request.Root.Epoch {
		return errors.New("invalid revocation root")
	}
	canonical, err := EncodeRevocationSetV1(r.Set)
	if err != nil || !bytes.Equal(canonical, r.Payload) || request.Verifier.Verify(r.RootKey, r.Payload, r.Signature) != nil {
		return errors.New("invalid revocation signature")
	}
	if request.Now < r.Set.IssuedAt || request.Now >= r.Set.ExpiresAt || uint64(request.Now-r.Set.IssuedAt) > r.Set.MaxOfflineStalenessSecs {
		return errors.New("stale revocations")
	}
	return nil
}

func validateActivationPolicy(request ActivationRequest, p envelope.CanonicalProfileV1, authenticatedDigest string) error {
	if p.ContractVersion != request.ContractVersion || p.SnapshotMode != "full-snapshot" || p.RequiredSafetyFloor < request.MinSafetyFloor || p.RootEpoch < request.MinRootEpoch || p.RootEpoch != request.Root.Epoch || p.RevocationEpoch < request.MinRevocationEpoch || p.RevocationEpoch != request.Revocations.Set.Epoch || p.RevocationScope != request.Revocations.Set.Scope || request.Now < p.ValidFrom || request.Now >= p.ValidUntil || uint64(p.ValidUntil-p.ValidFrom) > request.Delegation.Artifact.MaxProfileValiditySecs {
		return errors.New("profile floor or validity")
	}
	if err := ValidateIssuerDelegation(request.Root, request.Delegation.Artifact, request.Now, p.ProviderID, p.LineageID, p.ProfileID); err != nil {
		return err
	}
	if request.Revocations.Set.EmergencyDenied || containsSorted(request.Revocations.Set.RevokedIssuerKeyIDs, request.Delegation.Artifact.IssuerKey.KeyID) || containsSorted(request.Revocations.Set.RevokedContentIDs, p.ContentID) {
		return errors.New("revoked")
	}
	current := request.Current
	if current.Status == lifecycle.Admitted && p.Generation == current.Generation {
		if p.ContentID == current.Receipt.ContentID && p.ProviderID == current.Receipt.ProviderID && p.LineageID == current.Receipt.LineageID && p.RootEpoch == current.Receipt.RootEpoch && p.RevocationEpoch == current.Receipt.RevocationEpoch && authenticatedDigest == current.Receipt.AuthenticatedArtifactSHA256 {
			return nil
		}
		return errors.New("conflicting equal generation")
	}
	if current.Status == lifecycle.Admitted && p.Generation > current.Generation && (p.RootEpoch < current.Receipt.RootEpoch || p.RevocationEpoch < current.Receipt.RevocationEpoch) {
		return errors.New("authenticated epoch rollback")
	}
	switch p.UpdateKind {
	case "initial":
		if current.Status != "" && current.Status != lifecycle.Absent || p.PreviousContentID != "" || p.PreviousProviderID != "" {
			return errors.New("invalid initial")
		}
	case "replacement":
		if current.Status != lifecycle.Admitted || p.PreviousContentID != current.Receipt.ContentID || p.ProviderID != current.Receipt.ProviderID || p.LineageID != current.Receipt.LineageID || p.PreviousProviderID != "" {
			return errors.New("invalid replacement")
		}
	case "provider-migration":
		if current.Status != lifecycle.Admitted || p.PreviousContentID != current.Receipt.ContentID || p.PreviousProviderID != current.Receipt.ProviderID || p.ProviderID == current.Receipt.ProviderID || p.LineageID != current.Receipt.LineageID {
			return errors.New("invalid migration")
		}
	default:
		return errors.New("unknown update kind")
	}
	return nil
}

func EncodeIssuerDelegationV1(d IssuerDelegationArtifact) ([]byte, error) {
	if d.RootEpoch == 0 || d.DelegationEpoch == 0 || d.MaxProfileValiditySecs == 0 || d.ValidFrom <= 0 || d.ValidUntil <= d.ValidFrom || d.RootKeyID == "" || d.IssuerKey.validate() != nil || d.Scope.validate() != nil {
		return nil, errors.New("profile: invalid issuer delegation encoding")
	}
	return canonicalCBOR(map[uint64]any{1: uint64(1), 2: d.RootEpoch, 3: d.RootKeyID, 4: d.IssuerKey.KeyID, 5: uint64(d.IssuerKey.SuiteID), 6: d.Scope.ProviderID, 7: d.Scope.LineageID, 8: d.Scope.ProfileNamespace, 9: d.ValidFrom, 10: d.ValidUntil, 11: d.DelegationEpoch, 12: d.MaxProfileValiditySecs, 13: d.Revoked})
}

// EncodeScopedAuthorityV1 returns the canonical root-signing payload for one
// provider or recipient-registrar capability. Issuer authority is deliberately
// excluded because it has a separate, narrower encoding and validation path.
func EncodeScopedAuthorityV1(authority ScopedAuthorityArtifact) ([]byte, error) {
	if authority.Role != RoleProvider && authority.Role != RoleRecipientRegistrar ||
		authority.RootEpoch == 0 || !boundedID(authority.RootKeyID) ||
		authority.SubjectKey.validate() != nil || authority.Scope.validate() != nil ||
		authority.ValidFrom <= 0 || authority.ValidUntil <= authority.ValidFrom ||
		authority.AuthorizationEpoch == 0 {
		return nil, errors.New("profile: invalid scoped authority encoding")
	}
	return canonicalCBOR(map[uint64]any{
		1: uint64(1), 2: string(authority.Role), 3: authority.RootEpoch,
		4: authority.RootKeyID, 5: authority.SubjectKey.KeyID,
		6: uint64(authority.SubjectKey.SuiteID), 7: authority.Scope.ProviderID,
		8: authority.Scope.LineageID, 9: authority.Scope.ProfileNamespace,
		10: authority.ValidFrom, 11: authority.ValidUntil,
		12: authority.AuthorizationEpoch, 13: authority.Revoked,
	})
}

func EncodeRevocationSetV1(r RevocationSetV1) ([]byte, error) {
	if r.Version != 1 || !boundedID(r.Scope) || r.RootEpoch == 0 || r.Epoch == 0 || r.IssuedAt <= 0 || r.ExpiresAt <= r.IssuedAt || r.MaxOfflineStalenessSecs == 0 || len(r.RevokedIssuerKeyIDs) > envelope.MaxCanonicalMembers || len(r.RevokedContentIDs) > envelope.MaxCanonicalMembers || !strictSorted(r.RevokedIssuerKeyIDs) || !strictSorted(r.RevokedContentIDs) {
		return nil, errors.New("profile: invalid revocation set encoding")
	}
	return canonicalCBOR(map[uint64]any{1: r.Version, 2: r.Scope, 3: r.RootEpoch, 4: r.Epoch, 5: r.IssuedAt, 6: r.ExpiresAt, 7: r.MaxOfflineStalenessSecs, 8: r.RevokedIssuerKeyIDs, 9: r.RevokedContentIDs, 10: r.EmergencyDenied})
}

func canonicalCBOR(value any) ([]byte, error) {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(value)
}

func strictSorted(values []string) bool {
	for i, value := range values {
		if !boundedID(value) || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return sort.StringsAreSorted(values)
}

func containsSorted(values []string, target string) bool {
	i := sort.SearchStrings(values, target)
	return i < len(values) && values[i] == target
}

func activationRecordEqual(a, b ActivationRecord) bool {
	return bytes.Equal(a.Artifact, b.Artifact) && bytes.Equal(a.SignedObject, b.SignedObject) && reflect.DeepEqual(a.Profile, b.Profile) && a.State == b.State
}

func cloneCanonicalProfile(profile envelope.CanonicalProfileV1) envelope.CanonicalProfileV1 {
	profile.RelayIDs = append([]string(nil), profile.RelayIDs...)
	profile.StrategyIDs = append([]string(nil), profile.StrategyIDs...)
	profile.Policy = bytes.Clone(profile.Policy)
	return profile
}

func cloneActivationRecord(record ActivationRecord) ActivationRecord {
	record.Artifact = bytes.Clone(record.Artifact)
	record.SignedObject = bytes.Clone(record.SignedObject)
	record.Profile = cloneCanonicalProfile(record.Profile)
	return record
}

// recoverAfterStorageFailure distinguishes a recovered transaction from a
// provider that could not prove a safe state. Callers must stop activation on
// P8-ACT-RECOVERY-FAILED and must not use either candidate or cached state until
// the provider is repaired and a successful Snapshot is obtained.
func recoverAfterStorageFailure(storage TransactionalActivationProvider, priorActive, priorLKG, verifiedCandidate ActivationRecord, committedCandidateAllowed bool) error {
	if err := storage.Recover(); err != nil {
		return quarantineTerminalFailure(storage)
	}
	active, lkg, err := storage.Snapshot()
	if err != nil {
		return quarantineTerminalFailure(storage)
	}
	active, lkg = cloneActivationRecord(active), cloneActivationRecord(lkg)
	restoredPrior := activationRecordEqual(active, priorActive) && activationRecordEqual(lkg, priorLKG)
	committedCandidate := committedCandidateAllowed && activationRecordEqual(active, verifiedCandidate) && activationRecordEqual(lkg, priorActive)
	if !restoredPrior && !committedCandidate {
		return quarantineTerminalFailure(storage)
	}
	return activationFailure(ActivationStorageFailure)
}

// quarantineTerminalFailure is terminal whether quarantine succeeds or not.
// Callers must treat provider and cached state as unusable in both cases. The
// distinct code tells operators whether quarantine itself was confirmed.
func quarantineTerminalFailure(storage TransactionalActivationProvider) error {
	if err := storage.Quarantine(); err != nil {
		return activationFailure(ActivationQuarantineFailure)
	}
	return activationFailure(ActivationRecoveryFailure)
}

func observe(request ActivationRequest, stage ActivationStage) {
	if request.Observe != nil {
		request.Observe(stage)
	}
}

func activationFailure(code ActivationReasonCode) error { return &ActivationError{Code: code} }
