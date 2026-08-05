// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package entitlements

import (
	"context"
	"strings"
	"testing"
)

const testActor = "actor-0123456789abcdef0123456789abcdef"

func TestStoreReloadImmediatelyChangesRoles(t *testing.T) {
	store, err := New("qualification", entitlementDocument("entitlement-v1", "requester"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Resolve(context.Background(), testActor)
	if err != nil || before.Roles[0] != "requester" {
		t.Fatalf("initial entitlement=%+v err=%v", before, err)
	}
	if err := store.Reload(entitlementDocument("entitlement-v2", "viewer")); err != nil {
		t.Fatal(err)
	}
	after, err := store.Resolve(context.Background(), testActor)
	if err != nil || after.Version != "entitlement-v2" || after.Roles[0] != "viewer" {
		t.Fatalf("reloaded entitlement=%+v err=%v", after, err)
	}
}

func TestStoreRejectsPersonalDataAndForbiddenRoles(t *testing.T) {
	tests := [][]byte{
		[]byte(`{"schema":"phase16-entitlements-v1","environment":"qualification","version":"v1","assignments":[{"actor_id":"person@example.invalid","roles":["viewer"]}]}`),
		entitlementDocument("entitlement-v1", "approver", "executor"),
		entitlementDocument("entitlement-v1", "owner"),
	}
	for _, raw := range tests {
		if _, err := New("qualification", raw); err == nil {
			t.Fatalf("unsafe entitlement accepted: %s", raw)
		}
	}
}

func entitlementDocument(version string, roles ...string) []byte {
	quoted := make([]string, len(roles))
	for index, role := range roles {
		quoted[index] = `"` + role + `"`
	}
	return []byte(`{"schema":"phase16-entitlements-v1","environment":"qualification","version":"` + version + `","assignments":[{"actor_id":"` + testActor + `","roles":[` + strings.Join(quoted, ",") + `]}]}`)
}
