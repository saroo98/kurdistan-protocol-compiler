// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/product/envelope"
)

func TestWO807IssuerReplacementRecoveryDrill(t *testing.T) {
	observations := runWO807IssuerReplacementRecoveryDrill(t)
	assertWO807RecoveryEvidence(t, "issuer-replacement", "TestWO807IssuerReplacementRecoveryDrill", observations)
}

func runWO807IssuerReplacementRecoveryDrill(t *testing.T) []string {
	t.Helper()
	request, store := replacementActivationRequest(t)
	oldIssuer := request.Delegation.Artifact
	request.Delegation.Artifact.IssuerKey.KeyID = "issuer-key-0002"
	request.Delegation.Artifact.DelegationEpoch++
	resignDelegation(t, &request)
	resignProfile(t, &request, nil, request.Dispatch, request.Delegation.Artifact.IssuerKey.KeyID)

	replaced, err := ActivateVerifiedProfile(request)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.State.Generation != 2 || replaced.Profile.ContentID != "content-2" || store.active.State != replaced.State {
		t.Fatalf("issuer replacement did not commit generation two: %#v", replaced)
	}

	before := cloneActivationRecord(store.active)
	request.Current = replaced.State
	request.Delegation.Artifact = oldIssuer
	resignDelegation(t, &request)
	resignProfile(t, &request, func(p *envelope.CanonicalProfileV1) {
		p.ContentID, p.Generation, p.PreviousContentID = "content-3", 3, "content-2"
	}, request.Dispatch, oldIssuer.IssuerKey.KeyID)
	request.Revocations.Set.RevokedIssuerKeyIDs = []string{oldIssuer.IssuerKey.KeyID}
	resignRevocations(t, &request)
	if _, err := ActivateVerifiedProfile(request); activationCode(err) != ActivationPolicyRejected {
		t.Fatalf("revoked predecessor issuer code=%v", err)
	}
	if !activationRecordEqual(store.active, before) || store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) {
		t.Fatalf("rejected predecessor issuer changed state: %#v", store)
	}
	return []string{"generation-1-predecessor-active", "generation-2-replacement-issuer-committed", "revoked-predecessor-rejected", "rejection-left-active-and-transaction-state-unchanged"}
}

func TestWO807NewGenerationReplacesRevokedActiveProfile(t *testing.T) {
	observations := runWO807NewGenerationReplacesRevokedActiveProfile(t)
	assertWO807RecoveryEvidence(t, "revoked-profile-new-generation", "TestWO807NewGenerationReplacesRevokedActiveProfile", observations)
}

func runWO807NewGenerationReplacesRevokedActiveProfile(t *testing.T) []string {
	t.Helper()
	request, store := replacementActivationRequest(t)
	before := cloneActivationRecord(store.active)
	request.Revocations.Set.RevokedContentIDs = []string{before.Profile.ContentID, "content-2"}
	resignRevocations(t, &request)
	if _, err := ActivateVerifiedProfile(request); activationCode(err) != ActivationPolicyRejected {
		t.Fatalf("revoked replacement candidate code=%v", err)
	}
	if !activationRecordEqual(store.active, before) || store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) {
		t.Fatalf("rejected revoked replacement changed state: %#v", store)
	}

	request.Revocations.Set.RevokedContentIDs = []string{before.Profile.ContentID}
	resignRevocations(t, &request)
	after, err := ActivateVerifiedProfile(request)
	if err != nil {
		t.Fatal(err)
	}
	if before.Profile.ContentID != "content-1" || after.Profile.ContentID != "content-2" || after.State.Generation != before.State.Generation+1 {
		t.Fatalf("revoked-profile replacement transition invalid: before=%#v after=%#v", before.State, after.State)
	}
	if !activationRecordEqual(store.active, after) || !activationRecordEqual(store.lkg, before) || store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) {
		t.Fatalf("revoked-profile replacement persistence invalid: %#v", store)
	}
	return []string{"generation-1-active-and-revoked", "revoked-generation-2-candidate-rejected", "rejection-left-active-and-transaction-state-unchanged", "valid-generation-2-committed", "generation-1-retained-as-last-known-good"}
}

func TestWO807LocalWrapKeyLossLeavesActiveStateAtomic(t *testing.T) {
	observations := runWO807LocalWrapKeyLossLeavesActiveStateAtomic(t)
	assertWO807RecoveryEvidence(t, "local-wrap-key-loss", "TestWO807LocalWrapKeyLossLeavesActiveStateAtomic", observations)
}

func runWO807LocalWrapKeyLossLeavesActiveStateAtomic(t *testing.T) []string {
	t.Helper()
	request, store := validActivationRequest(t)
	provider := newMemoryKeyProvider()
	key := KeyReference{KeyID: "device-key-1", SuiteID: uint16(envelope.SuiteClassicalV1)}
	wrapped, err := provider.Wrap(key, request.Artifact)
	if err != nil || len(wrapped) == 0 {
		t.Fatalf("local wrap failed: bytes=%d err=%v", len(wrapped), err)
	}
	active, err := ActivateLocallyWrappedProfile(LocallyWrappedActivationRequest{Activation: request, Wrapper: provider, Key: key, WrappedArtifact: wrapped})
	if err != nil {
		t.Fatal(err)
	}
	before := cloneActivationRecord(store.active)

	replacement, _ := replacementActivationRequest(t)
	storageObserver := &countingActivationStore{next: store}
	replacement.Storage = storageObserver
	replacement.Current = active.State
	replacementWrapped, err := provider.Wrap(key, replacement.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	delete(provider.secrets, key.KeyID)
	if _, err := ActivateLocallyWrappedProfile(LocallyWrappedActivationRequest{Activation: replacement, Wrapper: provider, Key: key, WrappedArtifact: replacementWrapped}); activationCode(err) != ActivationStorageFailure {
		t.Fatalf("lost local-wrap key activation code=%v", err)
	}
	if storageObserver.calls != 0 {
		t.Fatalf("lost local-wrap key reached activation storage %d times", storageObserver.calls)
	}
	if !activationRecordEqual(store.active, before) || !activationRecordEqual(store.active, active) || store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) {
		t.Fatalf("local-wrap loss changed active state: %#v", store)
	}
	return []string{"generation-1-activated-through-local-wrap-boundary", "device-wrap-key-removed", "wrapped-generation-2-activation-failed-closed", "active-and-transaction-state-unchanged"}
}

type countingActivationStore struct {
	next  TransactionalActivationProvider
	calls int
}

func (s *countingActivationStore) called() { s.calls++ }
func (s *countingActivationStore) Snapshot() (ActivationRecord, ActivationRecord, error) {
	s.called()
	return s.next.Snapshot()
}
func (s *countingActivationStore) StageCandidate(record ActivationRecord) error {
	s.called()
	return s.next.StageCandidate(record)
}
func (s *countingActivationStore) ReopenCandidate() (ActivationRecord, error) {
	s.called()
	return s.next.ReopenCandidate()
}
func (s *countingActivationStore) MarkActivation() error { s.called(); return s.next.MarkActivation() }
func (s *countingActivationStore) CommitMarked() error   { s.called(); return s.next.CommitMarked() }
func (s *countingActivationStore) FinalizeActivation() error {
	s.called()
	return s.next.FinalizeActivation()
}
func (s *countingActivationStore) Recover() error    { s.called(); return s.next.Recover() }
func (s *countingActivationStore) Quarantine() error { s.called(); return s.next.Quarantine() }

func TestWO807InterruptedActivationRecoveryDrill(t *testing.T) {
	observations := runWO807InterruptedActivationRecoveryDrill(t)
	assertWO807RecoveryEvidence(t, "interrupted-activation", "TestWO807InterruptedActivationRecoveryDrill", observations)
}

func runWO807InterruptedActivationRecoveryDrill(t *testing.T) []string {
	t.Helper()
	observations := make([]string, 0, 4)
	for _, tc := range []struct {
		name      string
		stage     ActivationStage
		committed bool
	}{{"precommit", StageActivationMarked, false}, {"postcommit", StageActivationCommitted, true}} {
		t.Run(tc.name, func(t *testing.T) {
			request, store := replacementActivationRequest(t)
			before := cloneActivationRecord(store.active)
			store.failAfter = tc.stage
			if _, err := ActivateVerifiedProfile(request); activationCode(err) != ActivationStorageFailure {
				t.Fatalf("interruption code=%v", err)
			}
			if tc.committed {
				if store.active.State.Generation != before.State.Generation+1 || store.active.Profile.ContentID != "content-2" || !activationRecordEqual(store.lkg, before) {
					t.Fatalf("postcommit recovery state invalid: %#v", store)
				}
			} else if !activationRecordEqual(store.active, before) {
				t.Fatalf("precommit interruption changed active state: %#v", store)
			}
			if store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) || store.quarantined {
				t.Fatalf("interruption cleanup incomplete: %#v", store)
			}
			if tc.committed {
				observations = append(observations, "postcommit-interruption-retained-verified-generation-2", "postcommit-transaction-markers-cleared")
			} else {
				observations = append(observations, "precommit-interruption-restored-generation-1", "precommit-transaction-markers-cleared")
			}
		})
	}
	return observations
}

func TestWO807RecoveryEvidenceReport(t *testing.T) {
	assertWO807RecoveryEvidence(t, "issuer-replacement", "TestWO807IssuerReplacementRecoveryDrill", runWO807IssuerReplacementRecoveryDrill(t))
	assertWO807RecoveryEvidence(t, "revoked-profile-new-generation", "TestWO807NewGenerationReplacesRevokedActiveProfile", runWO807NewGenerationReplacesRevokedActiveProfile(t))
	assertWO807RecoveryEvidence(t, "local-wrap-key-loss", "TestWO807LocalWrapKeyLossLeavesActiveStateAtomic", runWO807LocalWrapKeyLossLeavesActiveStateAtomic(t))
	assertWO807RecoveryEvidence(t, "interrupted-activation", "TestWO807InterruptedActivationRecoveryDrill", runWO807InterruptedActivationRecoveryDrill(t))
}

type wo807RecoveryScenario struct {
	Name                    string   `json:"name"`
	ObservedBy              string   `json:"observed_by"`
	StateBefore             string   `json:"state_before"`
	StateAfter              string   `json:"state_after"`
	RejectionAtomicity      bool     `json:"rejection_atomicity"`
	Observations            []string `json:"observations"`
	ObservedExecutionSHA256 string   `json:"observed_execution_sha256"`
}

func assertWO807RecoveryEvidence(t *testing.T, name, observedBy string, observations []string) {
	t.Helper()
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "evidence", "phase8-wo807-recovery-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Schema                      string                  `json:"schema"`
		ActivationSourceSHA256      string                  `json:"activation_source_sha256"`
		LocalActivationSourceSHA256 string                  `json:"local_activation_source_sha256"`
		TestSourceSHA256            string                  `json:"test_source_sha256"`
		Scenarios                   []wo807RecoveryScenario `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != "kurdistan.phase8.wo807-recovery-report.v2" || len(report.Scenarios) != 4 {
		t.Fatalf("invalid recovery evidence identity/cardinality: %+v", report)
	}
	if report.ActivationSourceSHA256 != wo807FileSHA256(t, "phase8_activation.go") || report.LocalActivationSourceSHA256 != wo807FileSHA256(t, "phase8_local_activation.go") || report.TestSourceSHA256 != wo807FileSHA256(t, "phase8_recovery_test.go") {
		t.Fatal("recovery evidence source hash mismatch")
	}
	for _, scenario := range report.Scenarios {
		if scenario.Name != name {
			continue
		}
		if scenario.ObservedBy != observedBy || scenario.StateBefore == "" || scenario.StateAfter == "" || !scenario.RejectionAtomicity {
			t.Fatalf("invalid recovery evidence scenario: %+v", scenario)
		}
		if strings.Join(scenario.Observations, "\n") != strings.Join(observations, "\n") || scenario.ObservedExecutionSHA256 != wo807ObservedExecutionSHA256(observations) {
			t.Fatalf("recovery evidence is not bound to executed observations: %+v", scenario)
		}
		return
	}
	t.Fatalf("missing recovery evidence scenario %q", name)
}

func wo807FileSHA256(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func wo807ObservedExecutionSHA256(observations []string) string {
	passed := make([]string, len(observations))
	for i, observation := range observations {
		passed[i] = observation + "=pass"
	}
	digest := sha256.Sum256([]byte(strings.Join(passed, "\n")))
	return hex.EncodeToString(digest[:])
}
