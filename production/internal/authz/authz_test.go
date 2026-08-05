// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package authz

import (
	"errors"
	"testing"

	"kurdistan/production/internal/authn"
)

func TestDualControlSeparation(t *testing.T) {
	authorizer, err := New(map[string]map[Phase][]string{
		"profile.issue": {PhaseRequest: {"requester"}, PhaseApprove: {"approver"}, PhaseExecute: {"executor"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	operation := OperationContext{RequesterActorID: "actor-requester", ApproverActorIDs: []string{"actor-approver-a", "actor-approver-b"}}
	tests := []struct {
		name     string
		identity authn.Identity
		phase    Phase
		wantErr  bool
	}{
		{"request", authn.Identity{ActorID: "actor-requester", Roles: []string{"requester"}}, PhaseRequest, false},
		{"self approval", authn.Identity{ActorID: "actor-requester", Roles: []string{"approver"}}, PhaseApprove, true},
		{"approval", authn.Identity{ActorID: "actor-approver-a", Roles: []string{"approver"}}, PhaseApprove, false},
		{"requester execution", authn.Identity{ActorID: "actor-requester", Roles: []string{"executor"}}, PhaseExecute, true},
		{"approver execution", authn.Identity{ActorID: "actor-approver-a", Roles: []string{"executor"}}, PhaseExecute, true},
		{"separate execution", authn.Identity{ActorID: "actor-executor", Roles: []string{"executor"}}, PhaseExecute, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := authorizer.Authorize(test.identity, "profile.issue", test.phase, operation)
			if test.wantErr != errors.Is(err, ErrForbidden) {
				t.Fatalf("Authorize() error=%v", err)
			}
		})
	}
}
