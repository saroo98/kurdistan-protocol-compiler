// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
)

type exactVerifier struct{}

type permissiveVerifier struct{}

type fixedActivationResolver struct {
	binding RecipientBinding
	err     error
}

func (r fixedActivationResolver) ResolveRecipient(envelope.ArtifactClass, string) (RecipientBinding, error) {
	return r.binding, r.err
}

type hpkeActivationOpener struct {
	key       hpke.PrivateKey
	protected []byte
	want      RecipientBinding
}

type hpkeOfflineActivationOpener struct {
	key  hpke.PrivateKey
	want RecipientBinding
}

func (o hpkeOfflineActivationOpener) OpenOffline(binding RecipientBinding, protected, enc, ciphertext []byte) ([]byte, error) {
	return hpkeActivationOpener{key: o.key, protected: protected, want: o.want}.Open(binding, enc, ciphertext)
}

func (o hpkeActivationOpener) Open(binding RecipientBinding, enc, ciphertext []byte) ([]byte, error) {
	if binding != o.want {
		return nil, errors.New("binding mismatch")
	}
	info, err := envelope.BuildHPKEInfo(o.protected)
	if err != nil {
		return nil, err
	}
	aad, err := envelope.BuildHPKEAAD(o.protected)
	if err != nil {
		return nil, err
	}
	recipient, err := hpke.NewRecipient(enc, o.key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, err
	}
	return recipient.Open(aad, ciphertext)
}

var wo805CategoricalCaseNames = []string{
	"empty-artifact", "oversized-artifact", "malformed-cbor", "profile-signature",
	"delegation-signature", "delegation-payload", "delegation-expired", "delegation-revoked",
	"issuer-key-hint", "provider-scope", "lineage-scope", "profile-namespace",
	"contract-compatibility", "validity-not-yet-valid", "validity-expired", "validity-duration",
	"safety-floor", "root-floor", "root-epoch-mismatch", "revocation-floor",
	"revocation-epoch-mismatch", "revocation-scope-mismatch", "revocation-root-stale", "revocation-expired",
	"offline-staleness", "emergency-deny", "revoked-issuer", "revoked-content",
	"partial-snapshot", "replacement-without-current", "migration-without-current", "initial-with-predecessor",
	"restore-reinstall-state-mismatch", "storage-snapshot", "storage-stage", "storage-recovery",
}

var wo805DispatchMismatchCaseNames = []string{"sealed-happy", "class", "audience", "hint", "epoch", "tampered-encapsulation", "tampered-ciphertext", "wrong-resolver-binding"}

var wo805PersistenceFaultCaseNames = []string{
	"before/candidate-stored", "after/candidate-stored",
	"before/candidate-reopened", "after/candidate-reopened",
	"before/activation-marked", "after/activation-marked",
	"before/activation-committed", "after/activation-committed",
	"before/activation-finalized", "after/activation-finalized",
}

var wo805RevocationGenerationCaseNames = []string{
	"exact-authenticated-replay", "conflicting-equal-generation", "higher-generation-full-replacement",
	"revocation-root-stale", "revocation-floor", "revocation-epoch-mismatch", "revocation-scope-mismatch",
	"offline-staleness", "emergency-deny", "revoked-issuer", "revoked-content",
}

var wo805VerificationOrderCaseNames = []string{
	"outer-parsed", "signed-object-parsed", "delegation-verified", "revocations-verified", "profile-signature-verified", "dispatch-matched", "profile-semantics-decoded", "policy-validated",
	"candidate-stored", "candidate-reopened",
	"outer-parsed", "signed-object-parsed", "delegation-verified", "revocations-verified", "profile-signature-verified", "dispatch-matched", "profile-semantics-decoded", "policy-validated",
	"activation-marked", "activation-committed", "activation-finalized",
}

func (exactVerifier) Verify(key KeyReference, message, signature []byte) error {
	if !bytes.Equal(signature, testSignature(key, message)) {
		return errors.New("bad signature")
	}
	return nil
}

func (permissiveVerifier) Verify(KeyReference, []byte, []byte) error { return nil }

func testSignature(key KeyReference, message []byte) []byte {
	r := sha256.Sum256(append(append([]byte("r/"+key.KeyID+"/"), message...), byte(key.SuiteID)))
	s := sha256.Sum256(append(append([]byte("s/"+key.KeyID+"/"), message...), byte(key.SuiteID)))
	r[0] &= 0x7f
	s[0] &= 0x7f
	if bytes.Equal(r[:], make([]byte, 32)) {
		r[31] = 1
	}
	if bytes.Equal(s[:], make([]byte, 32)) {
		s[31] = 1
	}
	return append(r[:], s[:]...)
}

type memoryActivationStore struct {
	active, lkg, candidate                    ActivationRecord
	marked                                    bool
	failAt, failAfter                         ActivationStage
	failSnapshot, failRecover, failQuarantine bool
	corruptRecovery, quarantined              bool
}

// mutatingStageArgumentStore simulates a provider that snapshots its input and
// then reuses the caller-owned buffer. The activation boundary must retain an
// independent expected record for the reopen comparison.
type mutatingStageArgumentStore struct{ *memoryActivationStore }

func (s mutatingStageArgumentStore) StageCandidate(record ActivationRecord) error {
	if err := s.memoryActivationStore.StageCandidate(cloneActivationRecord(record)); err != nil {
		return err
	}
	if len(record.Artifact) == 0 {
		return errors.New("missing staged artifact")
	}
	record.Artifact[0] ^= 0xff
	return nil
}

func (s *memoryActivationStore) Snapshot() (ActivationRecord, ActivationRecord, error) {
	if s.quarantined {
		return ActivationRecord{}, ActivationRecord{}, errors.New("quarantined")
	}
	if s.failSnapshot {
		return ActivationRecord{}, ActivationRecord{}, errors.New("injected snapshot")
	}
	return s.active, s.lkg, nil
}
func (s *memoryActivationStore) StageCandidate(record ActivationRecord) error {
	if s.failAt == StageCandidateStored {
		return errors.New("injected")
	}
	s.candidate = record
	if s.failAfter == StageCandidateStored {
		return errors.New("injected after write")
	}
	return nil
}
func (s *memoryActivationStore) ReopenCandidate() (ActivationRecord, error) {
	if s.failAt == StageCandidateReopened {
		return ActivationRecord{}, errors.New("injected")
	}
	if s.failAfter == StageCandidateReopened {
		return s.candidate, errors.New("injected after read")
	}
	return s.candidate, nil
}
func (s *memoryActivationStore) MarkActivation() error {
	if s.failAt == StageActivationMarked {
		return errors.New("injected")
	}
	s.marked = true
	if s.failAfter == StageActivationMarked {
		return errors.New("injected after write")
	}
	return nil
}
func (s *memoryActivationStore) CommitMarked() error {
	if s.failAt == StageActivationCommitted {
		return errors.New("injected")
	}
	if !s.marked {
		return errors.New("unmarked")
	}
	s.lkg, s.active = s.active, s.candidate
	if s.failAfter == StageActivationCommitted {
		return errors.New("injected after write")
	}
	return nil
}
func (s *memoryActivationStore) FinalizeActivation() error {
	if s.failAt == StageActivationFinalized {
		return errors.New("injected")
	}
	s.candidate, s.marked = ActivationRecord{}, false
	if s.failAfter == StageActivationFinalized {
		return errors.New("injected after write")
	}
	return nil
}
func (s *memoryActivationStore) Recover() error {
	if s.failRecover {
		return errors.New("injected recovery")
	}
	if s.marked && s.active.State.Status == lifecycle.Admitted && s.active.State.Generation == s.candidate.State.Generation {
		s.candidate, s.marked = ActivationRecord{}, false
		if s.corruptRecovery {
			s.active.State.EvidenceReference = "corrupted"
		}
		return nil
	}
	s.candidate, s.marked = ActivationRecord{}, false
	if s.corruptRecovery {
		s.active.State.EvidenceReference = "corrupted"
	}
	return nil
}

func (s *memoryActivationStore) Quarantine() error {
	if s.failQuarantine {
		return errors.New("injected quarantine")
	}
	s.candidate, s.marked, s.quarantined = ActivationRecord{}, false, true
	return nil
}

func TestActivateVerifiedProfileOrdersVerificationBeforeSemantics(t *testing.T) {
	req, store := validActivationRequest(t)
	var stages []ActivationStage
	req.Observe = func(stage ActivationStage) { stages = append(stages, stage) }
	record, err := ActivateVerifiedProfile(req)
	if err != nil {
		t.Fatal(err)
	}
	if record.State.Status != lifecycle.Admitted || store.active.State.Generation != 1 {
		t.Fatalf("not activated: %#v", record)
	}
	assertStageBefore(t, stages, StageProfileSignatureVerified, StageProfileSemanticsDecoded)
	assertStageBefore(t, stages, StageCandidateReopened, StageActivationCommitted)
	if len(stages) != len(wo805VerificationOrderCaseNames) {
		t.Fatalf("stage count=%d: %v", len(stages), stages)
	}
	for i := range stages {
		if string(stages[i]) != wo805VerificationOrderCaseNames[i] {
			t.Fatalf("stage[%d]=%s want=%s", i, stages[i], wo805VerificationOrderCaseNames[i])
		}
	}
	assertEvidenceObservation(t, "verify-before-semantics-report.json", wo805VerificationOrderCaseNames)
}

func TestActivateVerifiedProfileRejectsHighSSignatureWithPermissiveVerifier(t *testing.T) {
	request, store := validActivationRequest(t)
	parsed, err := envelope.ParseSignedProfileOpaque(request.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	lowS := new(big.Int).SetBytes(parsed.Signature[32:])
	highS := new(big.Int).Sub(elliptic.P256().Params().N, lowS)
	if highS.Cmp(lowS) <= 0 {
		t.Fatal("fixture signature is not low-S")
	}
	request.Artifact = bytes.Clone(request.Artifact)
	if !bytes.Equal(request.Artifact[len(request.Artifact)-32:], parsed.Signature[32:]) {
		t.Fatal("fixture signature is not the final signed-object field")
	}
	highS.FillBytes(request.Artifact[len(request.Artifact)-32:])
	request.Verifier = permissiveVerifier{}

	if _, err := ActivateVerifiedProfile(request); activationCode(err) != ActivationInvalidArtifact {
		t.Fatalf("activation error = %v, want %s", err, ActivationInvalidArtifact)
	}
	if store.active.State.Status != "" || store.candidate.State.Status != "" {
		t.Fatalf("high-S artifact changed activation state: active=%#v candidate=%#v", store.active, store.candidate)
	}
}

func TestActivateVerifiedProfileIsIdempotentOnlyForExactAuthenticatedContent(t *testing.T) {
	req, store := validActivationRequest(t)
	first, err := ActivateVerifiedProfile(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Current = first.State
	if _, err := ActivateVerifiedProfile(req); err != nil {
		t.Fatalf("exact authenticated replay rejected: %v", err)
	}
	req.Artifact = append([]byte(nil), req.Artifact...)
	req.Artifact[len(req.Artifact)-1] ^= 1
	before, beforeLKG, _ := store.Snapshot()
	if _, err := ActivateVerifiedProfile(req); err == nil {
		t.Fatal("conflicting authenticated replay accepted")
	}
	after, afterLKG, _ := store.Snapshot()
	if !activationRecordsEqual(before, after) || !activationRecordsEqual(beforeLKG, afterLKG) {
		t.Fatal("conflicting replay changed state")
	}
}

func TestActivateVerifiedProfileRejectsValidlySignedEqualGenerationFork(t *testing.T) {
	req, store := validActivationRequest(t)
	first, err := ActivateVerifiedProfile(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Current = first.State
	resignProfile(t, &req, func(p *envelope.CanonicalProfileV1) { p.ContentID = "content-fork" }, req.Dispatch, req.Delegation.Artifact.IssuerKey.KeyID)
	priorActive, priorLKG := cloneActivationRecord(store.active), cloneActivationRecord(store.lkg)
	if _, err := ActivateVerifiedProfile(req); activationCode(err) != ActivationPolicyRejected {
		t.Fatalf("valid signed fork code=%v", err)
	}
	if !activationRecordEqual(store.active, priorActive) || !activationRecordEqual(store.lkg, priorLKG) {
		t.Fatal("signed fork changed state")
	}
}

func TestActivateVerifiedProfileRejectsHigherGenerationEpochRollback(t *testing.T) {
	for _, field := range []string{"root", "revocation"} {
		t.Run(field, func(t *testing.T) {
			req, store := replacementActivationRequest(t)
			if field == "root" {
				req.Current.Receipt.RootEpoch++
				store.active.State.Receipt.RootEpoch++
			} else {
				req.Current.Receipt.RevocationEpoch++
				store.active.State.Receipt.RevocationEpoch++
			}
			if _, err := ActivateVerifiedProfile(req); activationCode(err) != ActivationPolicyRejected {
				t.Fatalf("rollback code=%v", err)
			}
		})
	}
}

func TestActivateVerifiedProfileCategoricalFailuresLeaveStateUnchanged(t *testing.T) {
	type failureCase struct {
		name   string
		mutate func(*testing.T, *ActivationRequest, *memoryActivationStore)
	}
	cases := []failureCase{
		{"empty-artifact", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) { r.Artifact = nil }},
		{"oversized-artifact", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Artifact = make([]byte, envelope.MaxTotalInputBytes+1)
		}},
		{"malformed-cbor", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) { r.Artifact = []byte{0xff} }},
		{"profile-signature", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Artifact = append([]byte(nil), r.Artifact...)
			r.Artifact[len(r.Artifact)-1] ^= 1
		}},
		{"delegation-signature", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) { r.Delegation.Signature[0] ^= 1 }},
		{"delegation-payload", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Delegation.Payload = append(r.Delegation.Payload, 0)
		}},
		{"delegation-expired", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Delegation.Artifact.ValidUntil = r.Now
			resignDelegation(t, r)
		}},
		{"delegation-revoked", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Delegation.Artifact.Revoked = true
			resignDelegation(t, r)
		}},
		{"issuer-key-hint", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, nil, envelope.ArtifactMetadata{Class: envelope.ArtifactSignedPublic, AudienceClass: envelope.AudiencePublic}, "issuer-key-other")
		}},
		{"provider-scope", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.ProviderID = "provider-other" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"lineage-scope", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.LineageID = "lineage-other" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"profile-namespace", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.ProfileID = "outside.one" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"contract-compatibility", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.ContractVersion = "future-v2" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"validity-not-yet-valid", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.ValidFrom = r.Now + 1; p.ValidUntil = r.Now + 100 }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"validity-expired", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.ValidUntil = r.Now }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"validity-duration", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.ValidUntil = p.ValidFrom + 2000 }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"safety-floor", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) { r.MinSafetyFloor = 3 }},
		{"root-floor", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) { r.MinRootEpoch = 4 }},
		{"root-epoch-mismatch", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.RootEpoch = 2 }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"revocation-floor", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) { r.MinRevocationEpoch = 5 }},
		{"revocation-epoch-mismatch", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.RevocationEpoch = 3 }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"revocation-scope-mismatch", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.RevocationScope = "revocation-other" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"revocation-root-stale", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Revocations.Set.RootEpoch = 2
			resignRevocations(t, r)
		}},
		{"revocation-expired", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Revocations.Set.ExpiresAt = r.Now
			resignRevocations(t, r)
		}},
		{"offline-staleness", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Revocations.Set.MaxOfflineStalenessSecs = 1
			resignRevocations(t, r)
		}},
		{"emergency-deny", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Revocations.Set.EmergencyDenied = true
			resignRevocations(t, r)
		}},
		{"revoked-issuer", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Revocations.Set.RevokedIssuerKeyIDs = []string{r.Delegation.Artifact.IssuerKey.KeyID}
			resignRevocations(t, r)
		}},
		{"revoked-content", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Revocations.Set.RevokedContentIDs = []string{"content-1"}
			resignRevocations(t, r)
		}},
		{"partial-snapshot", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.SnapshotMode = "delta" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"replacement-without-current", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.UpdateKind = "replacement"; p.PreviousContentID = "content-0" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"migration-without-current", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) {
				p.UpdateKind = "provider-migration"
				p.PreviousContentID = "content-0"
				p.PreviousProviderID = "provider-0"
			}, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"initial-with-predecessor", func(t *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			resignProfile(t, r, func(p *envelope.CanonicalProfileV1) { p.PreviousContentID = "content-0" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
		}},
		{"restore-reinstall-state-mismatch", func(_ *testing.T, r *ActivationRequest, _ *memoryActivationStore) {
			r.Current = lifecycle.VerifiedState{State: lifecycle.State{Status: lifecycle.Admitted, ProfileID: "profiles.one", Scope: "revocation-1", EvidenceReference: string(make([]byte, 64)), Generation: 1}, Receipt: lifecycle.VerifiedReceipt{ContentID: "content-1", ProviderID: "provider-1", LineageID: "lineage-1", AuthenticatedArtifactSHA256: string(make([]byte, 64)), RootEpoch: 3, RevocationEpoch: 4}}
		}},
		{"storage-snapshot", func(_ *testing.T, _ *ActivationRequest, s *memoryActivationStore) { s.failSnapshot = true }},
		{"storage-stage", func(_ *testing.T, _ *ActivationRequest, s *memoryActivationStore) { s.failAt = StageCandidateStored }},
		{"storage-recovery", func(_ *testing.T, _ *ActivationRequest, s *memoryActivationStore) {
			s.failAfter = StageCandidateStored
			s.failRecover = true
		}},
	}
	if len(cases) < 30 {
		t.Fatalf("categorical matrix too small: %d", len(cases))
	}
	for i := range cases {
		if cases[i].name != wo805CategoricalCaseNames[i] {
			t.Fatalf("evidence case order mismatch at %d", i)
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, store := validActivationRequest(t)
			beforeActive, beforeLKG := store.active, store.lkg
			tc.mutate(t, &req, store)
			if _, err := ActivateVerifiedProfile(req); err == nil {
				t.Fatal("failure category accepted")
			}
			if !activationRecordsEqual(beforeActive, store.active) || !activationRecordsEqual(beforeLKG, store.lkg) {
				t.Fatal("failure changed committed state")
			}
		})
	}
	assertEvidenceObservation(t, "policy-bypass-report.json", wo805CategoricalCaseNames)
}

func TestActivateVerifiedProfileRecoversEachPersistenceFault(t *testing.T) {
	for _, mode := range []string{"before", "after"} {
		for _, stage := range []ActivationStage{StageCandidateStored, StageCandidateReopened, StageActivationMarked, StageActivationCommitted, StageActivationFinalized} {
			t.Run(mode+"/"+string(stage), func(t *testing.T) {
				req, store := replacementActivationRequest(t)
				priorActive, priorLKG := cloneActivationRecord(store.active), cloneActivationRecord(store.lkg)
				if mode == "before" {
					store.failAt = stage
				} else {
					store.failAfter = stage
				}
				_, err := ActivateVerifiedProfile(req)
				if err == nil {
					t.Fatal("fault accepted")
				}
				committedAllowed := stage == StageActivationFinalized || stage == StageActivationCommitted && mode == "after"
				if committedAllowed {
					if store.active.Profile.ContentID != "content-2" || !activationRecordEqual(store.lkg, priorActive) {
						t.Fatalf("committed recovery mismatch: active=%#v lkg=%#v", store.active, store.lkg)
					}
				} else if !activationRecordEqual(store.active, priorActive) || !activationRecordEqual(store.lkg, priorLKG) {
					t.Fatalf("prior state not restored: active=%#v lkg=%#v", store.active, store.lkg)
				}
				if store.candidate.State.Status != "" || store.marked {
					t.Fatalf("recovery left transaction residue: %#v marked=%v", store.candidate, store.marked)
				}
				if _, _, snapshotErr := store.Snapshot(); snapshotErr != nil {
					t.Fatalf("post-recovery snapshot: %v", snapshotErr)
				}
			})
		}
	}
	assertEvidenceObservation(t, "activation-crash-report.json", wo805PersistenceFaultCaseNames)
	assertEvidenceObservation(t, "last-known-good-negative-report.json", wo805PersistenceFaultCaseNames)
}

func TestActivateVerifiedProfileFailsClosedWhenSnapshotOrRecoveryFails(t *testing.T) {
	req, store := validActivationRequest(t)
	store.failSnapshot = true
	if _, err := ActivateVerifiedProfile(req); activationCode(err) != ActivationStorageFailure {
		t.Fatalf("snapshot code=%v", err)
	}
	store.failSnapshot = false
	store.failAfter, store.failRecover = StageCandidateStored, true
	if _, err := ActivateVerifiedProfile(req); activationCode(err) != ActivationRecoveryFailure {
		t.Fatalf("recovery code=%v", err)
	}
	if store.active.State.Status != "" {
		t.Fatal("recovery failure promoted candidate")
	}
	if !store.quarantined || store.candidate.State.Status != "" || store.marked {
		t.Fatal("recovery failure did not quarantine and clear residue")
	}
	if _, _, err := store.Snapshot(); err == nil {
		t.Fatal("quarantined provider remained usable")
	}

	req, store = replacementActivationRequest(t)
	store.failAfter, store.corruptRecovery = StageCandidateStored, true
	if _, err := ActivateVerifiedProfile(req); activationCode(err) != ActivationRecoveryFailure {
		t.Fatalf("unproven recovery code=%v", err)
	}
	if !store.quarantined || store.candidate.State.Status != "" || store.marked {
		t.Fatal("unproven recovery was not quarantined")
	}

	req, store = replacementActivationRequest(t)
	store.failAfter, store.failRecover, store.failQuarantine = StageCandidateStored, true, true
	record, err := ActivateVerifiedProfile(req)
	if activationCode(err) != ActivationQuarantineFailure {
		t.Fatalf("quarantine failure code=%v", err)
	}
	if !activationRecordEqual(record, ActivationRecord{}) {
		t.Fatalf("quarantine failure returned candidate: %#v", record)
	}
	if _, _, snapshotErr := store.Snapshot(); snapshotErr != nil {
		t.Fatalf("fixture must prove provider remained readable: %v", snapshotErr)
	}
}

func TestRecoveryAcceptsFullyReverifiedNewerGenerationOnlyAfterCommitBoundary(t *testing.T) {
	request, store := replacementActivationRequest(t)
	priorActive := cloneActivationRecord(store.active)
	store.failAfter = StageActivationCommitted
	if _, err := ActivateVerifiedProfile(request); activationCode(err) != ActivationStorageFailure {
		t.Fatalf("commit fault code=%v", err)
	}
	if store.active.State.Generation != priorActive.State.Generation+1 || store.active.Profile.ContentID != "content-2" {
		t.Fatalf("newer committed candidate not retained: %#v", store.active)
	}
	if !activationRecordEqual(store.lkg, priorActive) || store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) || store.quarantined {
		t.Fatalf("newer recovery transaction state invalid: %#v", store)
	}

	request, store = replacementActivationRequest(t)
	priorActive, priorLKG := cloneActivationRecord(store.active), cloneActivationRecord(store.lkg)
	store.failAfter = StageActivationMarked
	if _, err := ActivateVerifiedProfile(request); activationCode(err) != ActivationStorageFailure {
		t.Fatalf("precommit fault code=%v", err)
	}
	if !activationRecordEqual(store.active, priorActive) || !activationRecordEqual(store.lkg, priorLKG) || store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) || store.quarantined {
		t.Fatalf("precommit newer candidate escaped: %#v", store)
	}
}

func TestActivateVerifiedProfileSealedPathAndDispatchMismatch(t *testing.T) {
	req, _ := validActivationRequest(t)
	metadata := envelope.ArtifactMetadata{Class: envelope.ArtifactDeviceRecipient, AudienceClass: envelope.AudienceProvisionedDevice, RecipientHint: "device-hint-0001", RecipientEpoch: 7}
	signedObject := resignProfile(t, &req, nil, metadata, req.Delegation.Artifact.IssuerKey.KeyID)
	sealRequestHPKE(t, &req, signedObject, metadata)
	var stages []ActivationStage
	req.Observe = func(stage ActivationStage) { stages = append(stages, stage) }
	if _, err := ActivateVerifiedProfile(req); err != nil {
		t.Fatal(err)
	}
	assertStageBefore(t, stages, StageRecipientOpened, StageProfileSignatureVerified)
	assertStageBefore(t, stages, StageProfileSignatureVerified, StageDispatchMatched)

	mismatchCases := []struct {
		name   string
		mutate func(*envelope.ArtifactMetadata)
	}{
		{"class", func(m *envelope.ArtifactMetadata) {
			m.Class = envelope.ArtifactProviderGroup
			m.AudienceClass = envelope.AudienceProvisionedGroup
		}},
		{"audience", func(m *envelope.ArtifactMetadata) {
			m.Class = envelope.ArtifactEncryptedBackup
			m.AudienceClass = envelope.AudienceProvisionedBackupKey
		}},
		{"hint", func(m *envelope.ArtifactMetadata) { m.RecipientHint = "device-hint-0002" }},
		{"epoch", func(m *envelope.ArtifactMetadata) { m.RecipientEpoch++ }},
	}
	for i, mismatch := range mismatchCases {
		if mismatch.name != wo805DispatchMismatchCaseNames[i+1] {
			t.Fatalf("dispatch evidence case order mismatch at %d", i)
		}
		t.Run(mismatch.name, func(t *testing.T) {
			r, s := validActivationRequest(t)
			signedMeta := metadata
			opened := resignProfile(t, &r, nil, signedMeta, r.Delegation.Artifact.IssuerKey.KeyID)
			outerMeta := signedMeta
			mismatch.mutate(&outerMeta)
			sealRequestHPKE(t, &r, opened, outerMeta)
			if _, err := ActivateVerifiedProfile(r); err == nil {
				t.Fatal("authenticated dispatch mismatch accepted")
			}
			if s.active.State.Status != "" {
				t.Fatal("mismatch activated")
			}
		})
	}

	t.Run("tampered-encapsulation", func(t *testing.T) {
		r, s := validActivationRequest(t)
		opened := resignProfile(t, &r, nil, metadata, r.Delegation.Artifact.IssuerKey.KeyID)
		sealRequestHPKE(t, &r, opened, metadata)
		sealed, err := envelope.ParseSealedProfileOpaque(r.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		sealed.Encapsulation[1] ^= 1
		r.Artifact, err = envelope.BuildSealedFrame(sealed.Protected, sealed.Encapsulation, sealed.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ActivateVerifiedProfile(r); err == nil {
			t.Fatal("tampered encapsulation accepted")
		}
		if !activationRecordEqual(s.active, ActivationRecord{}) {
			t.Fatal("tampered enc activated")
		}
	})
	t.Run("tampered-ciphertext", func(t *testing.T) {
		r, _ := validActivationRequest(t)
		opened := resignProfile(t, &r, nil, metadata, r.Delegation.Artifact.IssuerKey.KeyID)
		sealRequestHPKE(t, &r, opened, metadata)
		sealed, err := envelope.ParseSealedProfileOpaque(r.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		sealed.Ciphertext[len(sealed.Ciphertext)-1] ^= 1
		r.Artifact, err = envelope.BuildSealedFrame(sealed.Protected, sealed.Encapsulation, sealed.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ActivateVerifiedProfile(r); err == nil {
			t.Fatal("tampered ciphertext accepted")
		}
	})
	t.Run("wrong-resolver-binding", func(t *testing.T) {
		r, _ := validActivationRequest(t)
		opened := resignProfile(t, &r, nil, metadata, r.Delegation.Artifact.IssuerKey.KeyID)
		sealRequestHPKE(t, &r, opened, metadata)
		wrong := r.Resolver.(fixedActivationResolver).binding
		wrong.Hint = "device-hint-wrong"
		r.Resolver = fixedActivationResolver{binding: wrong}
		if _, err := ActivateVerifiedProfile(r); err == nil {
			t.Fatal("wrong binding accepted")
		}
	})
	assertEvidenceObservation(t, "authenticated-hint-mismatch-report.json", wo805DispatchMismatchCaseNames)
}

func TestPhase8ActivationRejectsRecipientEpochAndScopeSubstitution(t *testing.T) {
	metadata := envelope.ArtifactMetadata{Class: envelope.ArtifactDeviceRecipient, AudienceClass: envelope.AudienceProvisionedDevice, RecipientHint: "device-hint-0001", RecipientEpoch: 7}
	for _, tc := range []struct {
		name   string
		mutate func(*RecipientBinding)
	}{
		{"recipient epoch", func(binding *RecipientBinding) { binding.Epoch++ }},
		{"provider scope", func(binding *RecipientBinding) { binding.ProviderID = "provider-other" }},
		{"lineage scope", func(binding *RecipientBinding) { binding.LineageID = "lineage-other" }},
		{"profile namespace", func(binding *RecipientBinding) { binding.ProfileNamespace = "other." }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, store := validActivationRequest(t)
			signedObject := resignProfile(t, &request, nil, metadata, request.Delegation.Artifact.IssuerKey.KeyID)
			sealRequestHPKE(t, &request, signedObject, metadata)
			wrong := request.Resolver.(fixedActivationResolver).binding
			tc.mutate(&wrong)
			opener := request.Opener.(hpkeActivationOpener)
			opener.want = wrong
			request.Resolver, request.Opener = fixedActivationResolver{binding: wrong}, opener
			if _, err := ActivateVerifiedProfile(request); err == nil {
				t.Fatal("substituted recipient binding activated")
			}
			if !activationRecordEqual(store.active, ActivationRecord{}) || store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) {
				t.Fatalf("recipient substitution changed activation state: %#v", store)
			}
		})
	}
}

func TestPhase8ActivationRejectsNonClassicalVerifierKeyReferences(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ActivationRequest)
	}{
		{"root set key", func(request *ActivationRequest) {
			request.Root.Keys[0].SuiteID = uint16(envelope.SuiteReservedPQV1)
			request.Delegation.RootKey = request.Root.Keys[0]
			request.Revocations.RootKey = request.Root.Keys[0]
		}},
		{"delegation root key", func(request *ActivationRequest) {
			request.Delegation.RootKey.SuiteID = uint16(envelope.SuiteReservedPQV1)
		}},
		{"revocation root key", func(request *ActivationRequest) {
			request.Revocations.RootKey.SuiteID = uint16(envelope.SuiteReservedPQV1)
		}},
		{"issuer key", func(request *ActivationRequest) {
			request.Delegation.Artifact.IssuerKey.SuiteID = uint16(envelope.SuiteReservedPQV1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, store := validActivationRequest(t)
			tc.mutate(&request)
			if _, err := ActivateVerifiedProfile(request); err == nil {
				t.Fatal("non-classical verifier key was accepted")
			}
			if !activationRecordEqual(store.active, ActivationRecord{}) {
				t.Fatal("rejected verifier key changed active state")
			}
		})
	}
}

func TestPhase8ActivationPinsExpectedRecordBeforeStaging(t *testing.T) {
	request, backing := validActivationRequest(t)
	expected := append([]byte(nil), request.Artifact...)
	request.Storage = mutatingStageArgumentStore{memoryActivationStore: backing}
	record, err := ActivateVerifiedProfile(request)
	if err != nil {
		t.Fatalf("provider mutation of a staged argument denied valid activation: %v", err)
	}
	if !bytes.Equal(record.Artifact, expected) || !bytes.Equal(backing.active.Artifact, expected) {
		t.Fatal("staged argument alias changed the verified artifact")
	}
}

func TestWO805RevocationAndGenerationMatrix(t *testing.T) {
	for _, name := range wo805RevocationGenerationCaseNames {
		t.Run(name, func(t *testing.T) {
			switch name {
			case "exact-authenticated-replay":
				r, _ := validActivationRequest(t)
				first, err := ActivateVerifiedProfile(r)
				if err != nil {
					t.Fatal(err)
				}
				r.Current = first.State
				if _, err := ActivateVerifiedProfile(r); err != nil {
					t.Fatal(err)
				}
			case "conflicting-equal-generation":
				r, _ := validActivationRequest(t)
				first, err := ActivateVerifiedProfile(r)
				if err != nil {
					t.Fatal(err)
				}
				r.Current = first.State
				resignProfile(t, &r, func(p *envelope.CanonicalProfileV1) { p.ContentID = "content-fork" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
				if _, err := ActivateVerifiedProfile(r); activationCode(err) != ActivationPolicyRejected {
					t.Fatalf("fork=%v", err)
				}
			case "higher-generation-full-replacement":
				r, _ := replacementActivationRequest(t)
				if _, err := ActivateVerifiedProfile(r); err != nil {
					t.Fatal(err)
				}
			default:
				r, _ := validActivationRequest(t)
				switch name {
				case "revocation-root-stale":
					r.Revocations.Set.RootEpoch = 2
				case "revocation-floor":
					r.MinRevocationEpoch = 5
					if _, err := ActivateVerifiedProfile(r); err == nil {
						t.Fatal("accepted")
					}
					return
				case "revocation-epoch-mismatch":
					resignProfile(t, &r, func(p *envelope.CanonicalProfileV1) { p.RevocationEpoch = 3 }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
					if _, err := ActivateVerifiedProfile(r); err == nil {
						t.Fatal("accepted")
					}
					return
				case "revocation-scope-mismatch":
					resignProfile(t, &r, func(p *envelope.CanonicalProfileV1) { p.RevocationScope = "revocation-other" }, r.Dispatch, r.Delegation.Artifact.IssuerKey.KeyID)
					if _, err := ActivateVerifiedProfile(r); err == nil {
						t.Fatal("accepted")
					}
					return
				case "offline-staleness":
					r.Revocations.Set.MaxOfflineStalenessSecs = 1
				case "emergency-deny":
					r.Revocations.Set.EmergencyDenied = true
				case "revoked-issuer":
					r.Revocations.Set.RevokedIssuerKeyIDs = []string{r.Delegation.Artifact.IssuerKey.KeyID}
				case "revoked-content":
					r.Revocations.Set.RevokedContentIDs = []string{"content-1"}
				}
				resignRevocations(t, &r)
				if _, err := ActivateVerifiedProfile(r); err == nil {
					t.Fatal("accepted")
				}
			}
		})
	}
	assertEvidenceObservation(t, "revocation-generation-report.json", wo805RevocationGenerationCaseNames)
}

func TestActivateVerifiedProfileFullSnapshotReplacementRemovesOmittedMembers(t *testing.T) {
	req, store := validActivationRequest(t)
	first, err := ActivateVerifiedProfile(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Current = first.State
	resignProfile(t, &req, func(p *envelope.CanonicalProfileV1) {
		p.ContentID = "content-2"
		p.Generation = 2
		p.UpdateKind = "replacement"
		p.PreviousContentID = "content-1"
		p.RelayIDs = []string{"relay-2"}
		p.StrategyIDs = []string{"strategy-2"}
	}, req.Dispatch, req.Delegation.Artifact.IssuerKey.KeyID)
	second, err := ActivateVerifiedProfile(req)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(second.Profile.RelayIDs) != "[relay-2]" || fmt.Sprint(second.Profile.StrategyIDs) != "[strategy-2]" {
		t.Fatalf("replacement was merged instead of replaced: %#v", second.Profile)
	}
	if len(store.lkg.Profile.RelayIDs) != 1 || store.lkg.Profile.RelayIDs[0] != "relay-1" {
		t.Fatalf("last-known-good lost: %#v", store.lkg.Profile)
	}
}

func TestActivateVerifiedProfileUnwrapsOuterBundleBeforeContextBoundRecipientOpen(t *testing.T) {
	request, _ := validActivationRequest(t)
	metadata := envelope.ArtifactMetadata{
		Class: envelope.ArtifactDeviceRecipient, AudienceClass: envelope.AudienceProvisionedDevice,
		RecipientHint: "request-outer-1", RecipientEpoch: 1,
	}
	signed := resignProfile(t, &request, func(*envelope.CanonicalProfileV1) {}, metadata, request.Delegation.Artifact.IssuerKey.KeyID)
	sealRequestHPKE(t, &request, signed, metadata)
	legacy := request.Opener.(hpkeActivationOpener)
	inner := bytes.Clone(request.Artifact)
	outer := append([]byte("owner-bundle-v2:"), inner...)
	request.Artifact = outer
	request.Opener = nil
	request.OfflineOpener = hpkeOfflineActivationOpener{key: legacy.key, want: legacy.want}
	request.UnwrapArtifact = func(candidate []byte) ([]byte, error) {
		if !bytes.HasPrefix(candidate, []byte("owner-bundle-v2:")) {
			return nil, errors.New("outer authority rejected")
		}
		return bytes.Clone(candidate[len("owner-bundle-v2:"):]), nil
	}
	activated, err := ActivateVerifiedProfile(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(activated.Artifact, outer) || !bytes.Equal(activated.SignedObject, signed) {
		t.Fatal("activation did not preserve exact outer artifact and opened signed object")
	}
	outer[len(outer)-1] ^= 1
	if bytes.Equal(activated.Artifact, outer) {
		t.Fatal("activation record aliases caller-owned outer artifact")
	}
}

func validActivationRequest(t testing.TB) (ActivationRequest, *memoryActivationStore) {
	t.Helper()
	rootKey := KeyReference{KeyID: "root-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}
	issuerKey := KeyReference{KeyID: "issuer-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}
	root := RootSetArtifact{Epoch: 3, ViewID: "root-view-0003", ValidFrom: 100, ValidUntil: 10000, Keys: []KeyReference{rootKey}}
	delegation := IssuerDelegationArtifact{RootEpoch: 3, RootKeyID: rootKey.KeyID, IssuerKey: issuerKey, Scope: AuthorityScope{ProviderID: "provider-1", LineageID: "lineage-1", ProfileNamespace: "profiles."}, ValidFrom: 100, ValidUntil: 9000, DelegationEpoch: 2, MaxProfileValiditySecs: 1000}
	delegationPayload, err := EncodeIssuerDelegationV1(delegation)
	if err != nil {
		t.Fatal(err)
	}
	profile := envelope.CanonicalProfileV1{ContentID: "content-1", ProfileID: "profiles.one", LineageID: "lineage-1", ProviderID: "provider-1", ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation-1", SnapshotMode: "full-snapshot", UpdateKind: "initial", Generation: 1, RequiredSafetyFloor: 2, ValidFrom: 200, ValidUntil: 800, RootEpoch: 3, RevocationEpoch: 4, RelayIDs: []string{"relay-1"}, StrategyIDs: []string{"strategy-1"}, Policy: []byte{0xa1, 0x01, 0x01}}
	payload, err := envelope.EncodeCanonicalProfileV1(profile)
	if err != nil {
		t.Fatal(err)
	}
	metadata := envelope.ArtifactMetadata{Class: envelope.ArtifactSignedPublic, AudienceClass: envelope.AudiencePublic}
	protected, err := envelope.BuildSignedProtectedHeaders([]byte(issuerKey.KeyID), metadata)
	if err != nil {
		t.Fatal(err)
	}
	sigStructure, err := envelope.BuildCOSESigStructure(protected, payload)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := envelope.BuildTaggedCOSESign1(protected, payload, testSignature(issuerKey, sigStructure))
	if err != nil {
		t.Fatal(err)
	}
	revocations := RevocationSetV1{Version: 1, Scope: "revocation-1", RootEpoch: 3, Epoch: 4, IssuedAt: 150, ExpiresAt: 1000, MaxOfflineStalenessSecs: 500, RevokedIssuerKeyIDs: []string{}, RevokedContentIDs: []string{}}
	revocationPayload, err := EncodeRevocationSetV1(revocations)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryActivationStore{}
	return ActivationRequest{Artifact: artifact, Dispatch: metadata, Now: 500, Root: root, Delegation: SignedIssuerDelegationV1{Artifact: delegation, RootKey: rootKey, Payload: delegationPayload, Signature: testSignature(rootKey, delegationPayload)}, Revocations: SignedRevocationSetV1{Set: revocations, RootKey: rootKey, Payload: revocationPayload, Signature: testSignature(rootKey, revocationPayload)}, Verifier: exactVerifier{}, Storage: store, ContractVersion: "product-profile-admission-v1", MinSafetyFloor: 2, MinRootEpoch: 3, MinRevocationEpoch: 4}, store
}

func replacementActivationRequest(t *testing.T) (ActivationRequest, *memoryActivationStore) {
	t.Helper()
	request, store := validActivationRequest(t)
	first, err := ActivateVerifiedProfile(request)
	if err != nil {
		t.Fatal(err)
	}
	priorLKG := cloneActivationRecord(first)
	priorLKG.Artifact = []byte("non-empty-prior-lkg")
	store.lkg = priorLKG
	request.Current = first.State
	resignProfile(t, &request, func(p *envelope.CanonicalProfileV1) {
		p.ContentID, p.Generation, p.UpdateKind, p.PreviousContentID = "content-2", 2, "replacement", "content-1"
		p.RelayIDs, p.StrategyIDs = []string{"relay-2"}, []string{"strategy-2"}
	}, request.Dispatch, request.Delegation.Artifact.IssuerKey.KeyID)
	return request, store
}

func assertStageBefore(t *testing.T, stages []ActivationStage, first, second ActivationStage) {
	t.Helper()
	indexes := map[ActivationStage]int{}
	for i, stage := range stages {
		indexes[stage] = i
	}
	if indexes[first] >= indexes[second] {
		t.Fatalf("stage order %s !< %s: %v", first, second, stages)
	}
}

func resignProfile(t *testing.T, request *ActivationRequest, mutate func(*envelope.CanonicalProfileV1), metadata envelope.ArtifactMetadata, keyID string) []byte {
	t.Helper()
	parsed, err := envelope.ParseSignedProfileOpaque(request.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	profileValue, err := envelope.DecodeCanonicalProfileV1(parsed.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&profileValue)
	}
	payload, err := envelope.EncodeCanonicalProfileV1(profileValue)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := envelope.BuildSignedProtectedHeaders([]byte(keyID), metadata)
	if err != nil {
		t.Fatal(err)
	}
	sigStructure, err := envelope.BuildCOSESigStructure(protected, payload)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := envelope.BuildTaggedCOSESign1(protected, payload, testSignature(request.Delegation.Artifact.IssuerKey, sigStructure))
	if err != nil {
		t.Fatal(err)
	}
	request.Artifact, request.Dispatch = artifact, metadata
	return artifact
}

func resignDelegation(t *testing.T, request *ActivationRequest) {
	t.Helper()
	payload, err := EncodeIssuerDelegationV1(request.Delegation.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	request.Delegation.Payload = payload
	request.Delegation.Signature = testSignature(request.Delegation.RootKey, payload)
}

func resignRevocations(t *testing.T, request *ActivationRequest) {
	t.Helper()
	payload, err := EncodeRevocationSetV1(request.Revocations.Set)
	if err != nil {
		t.Fatal(err)
	}
	request.Revocations.Payload = payload
	request.Revocations.Signature = testSignature(request.Revocations.RootKey, payload)
}

func sealRequestHPKE(t *testing.T, request *ActivationRequest, signedObject []byte, metadata envelope.ArtifactMetadata) {
	t.Helper()
	protected, err := envelope.BuildSealProtected(metadata)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hpke.DHKEM(ecdh.P256()).DeriveKeyPair([]byte("phase8 activation hpke recipient fixture"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := envelope.BuildHPKEInfo(protected)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := envelope.BuildHPKEAAD(protected)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(key.PublicKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sender.Seal(aad, signedObject)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := envelope.BuildSealedFrame(protected, enc, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	binding := RecipientBinding{Class: metadata.Class, ProviderID: "provider-1", LineageID: "lineage-1", ProfileNamespace: "profiles.", Hint: metadata.RecipientHint, KeyID: "recipient-key-0001", Epoch: metadata.RecipientEpoch}
	request.Artifact, request.Dispatch = frame, metadata
	request.Resolver, request.Opener = fixedActivationResolver{binding: binding}, hpkeActivationOpener{key: key, protected: protected, want: binding}
}

func activationCode(err error) ActivationReasonCode {
	var activationErr *ActivationError
	if errors.As(err, &activationErr) {
		return activationErr.Code
	}
	return ""
}

func activationRecordsEqual(a, b ActivationRecord) bool {
	return fmt.Sprintf("%#v", a) == fmt.Sprintf("%#v", b)
}
