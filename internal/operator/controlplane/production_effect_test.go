// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import "testing"

func TestProductionEffectResolutionIsAttemptBoundAndFailClosed(t *testing.T) {
	state := executedPublicationState(t)
	event := state.Outbox[0]
	resolution := ProductionEffectResolution{
		EventID: event.ID, EffectID: "phase16-effect-" + event.ID,
		ReceiptHash: DigestLabel("external-effect-receipt"), WorkerID: "worker-publication",
		Attempt: 1, At: event.CreatedAt + 1, Outcome: ProductionEffectDelivered,
	}
	next, result, err := ApplyProductionEffectResolution(state, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != state.Revision+1 || result.Event.DeliveredAt != resolution.At || len(PendingOutbox(next)) != 0 {
		t.Fatalf("result=%+v state=%+v", result, next)
	}
	for name, mutate := range map[string]func(*ProductionEffectResolution){
		"stale attempt": func(value *ProductionEffectResolution) { value.Attempt = 2 },
		"wrong effect":  func(value *ProductionEffectResolution) { value.EffectID = "phase16-effect-substituted" },
		"bad digest":    func(value *ProductionEffectResolution) { value.ReceiptHash = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := resolution
			mutate(&candidate)
			if _, _, err := ApplyProductionEffectResolution(state, candidate); err == nil {
				t.Fatal("invalid resolution accepted")
			}
		})
	}
}

func TestProductionEffectRetryBecomesTerminalOnlyAtBound(t *testing.T) {
	state := executedPublicationState(t)
	event := state.Outbox[0]
	for attempt := uint32(1); attempt < MaxEffectAttempts; attempt++ {
		var err error
		state, _, err = ApplyProductionEffectResolution(state, ProductionEffectResolution{
			EventID: event.ID, EffectID: "phase16-effect-" + event.ID, WorkerID: "worker-publication",
			Attempt: attempt, At: event.CreatedAt + int64(attempt), Outcome: ProductionEffectRetry,
		})
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	state, result, err := ApplyProductionEffectResolution(state, ProductionEffectResolution{
		EventID: event.ID, EffectID: "phase16-effect-" + event.ID, WorkerID: "worker-publication",
		Attempt: MaxEffectAttempts, At: event.CreatedAt + int64(MaxEffectAttempts), Outcome: ProductionEffectTerminal,
	})
	if err != nil || result.Event.FailedAt == 0 || len(PendingOutbox(state)) != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func executedPublicationState(t *testing.T) State {
	t.Helper()
	store := NewMemoryStore()
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	input := RequestInput{
		ID: "operation-production-effect", Action: ActionPublishSnapshot, TargetID: "publication-primary",
		SubjectDigest: DigestLabel("publication-subject"), ScopeDigest: DigestLabel("publication-scope"),
		ExpectedRevision: 0, CreatedAt: 500, ExpiresAt: 1_000, IdempotencyKey: "idempotency-production-effect",
		Publication: &PublicationInput{Version: 1, RootVersion: 1, SnapshotDigest: DigestLabel("snapshot"), TargetsDigest: DigestLabel("targets"), ValidUntil: 900},
	}
	requester := Actor{ID: "requester-production", AuthorityRole: "operator", Duties: []Duty{DutyRequest}}
	if _, err := service.Request(requester, input); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"approver-production-a", "approver-production-b"} {
		if _, err := service.Approve(Actor{ID: id, AuthorityRole: "operator", Duties: []Duty{DutyApprove}}, input.ID, "idempotency-"+id, service.State().Revision, 501); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Execute(Actor{ID: "publisher-production", AuthorityRole: "operator", Duties: []Duty{DutyExecute, DutyPublish}}, input.ID, "idempotency-production-execute", service.State().Revision, 502); err != nil {
		t.Fatal(err)
	}
	return service.State()
}
