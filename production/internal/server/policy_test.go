// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"kurdistan/production/internal/authz"
)

func TestProductionActionRolesMatchCommittedPolicy(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, "config", "production", "actions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Schema  string `json:"schema"`
		Actions []struct {
			ID            string   `json:"id"`
			RequestRoles  []string `json:"requestRoles"`
			ApprovalRoles []string `json:"approvalRoles"`
			ExecuteRole   string   `json:"executeRole"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.Schema != "phase16-action-policy-v1" {
		t.Fatalf("invalid committed action policy: %v", err)
	}
	actual := ProductionActionRoles()
	for _, action := range document.Actions {
		phases, ok := actual[action.ID]
		if !ok {
			t.Fatalf("committed action %q absent from runtime policy", action.ID)
		}
		assertRoles(t, action.ID+" request", phases[authz.PhaseRequest], action.RequestRoles)
		assertRoles(t, action.ID+" approve", phases[authz.PhaseApprove], action.ApprovalRoles)
		assertRoles(t, action.ID+" execute", phases[authz.PhaseExecute], []string{action.ExecuteRole})
	}
}

func assertRoles(t *testing.T, label string, actual, expected []string) {
	t.Helper()
	actual = append([]string(nil), actual...)
	expected = append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(expected)
	if len(actual) != len(expected) {
		t.Fatalf("%s role count mismatch: got %v want %v", label, actual, expected)
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("%s roles mismatch: got %v want %v", label, actual, expected)
		}
	}
}
