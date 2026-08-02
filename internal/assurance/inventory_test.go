// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildPolicyInventoryProducesStableProofLanes(t *testing.T) {
	policy := testProofPolicy()
	policy.Proofs[0].OperatingSystems = []string{"windows", "linux"}
	inventory, err := BuildPolicyInventory(policy, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Lanes) != 2 || inventory.Lanes[0].OperatingSystem != "linux" || inventory.Lanes[1].OperatingSystem != "windows" {
		t.Fatalf("unexpected stable lane inventory: %+v", inventory.Lanes)
	}
}

func TestDecodePolicyInventoryRejectsUnknownDuplicateAndTruncatedJSON(t *testing.T) {
	inventory, err := BuildPolicyInventory(testProofPolicy(), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(raw), `"policySha256":`, `"unknown":true,"policySha256":`, 1)
	if _, err := DecodePolicyInventory(strings.NewReader(unknown)); err == nil {
		t.Fatal("expected unknown inventory field rejection")
	}
	duplicate := strings.Replace(string(raw), `"proofId":"go-core"`, `"proofId":"go-core","proofId":"go-core"`, 1)
	if _, err := DecodePolicyInventory(strings.NewReader(duplicate)); err == nil {
		t.Fatal("expected duplicate inventory key rejection")
	}
	if _, err := DecodePolicyInventory(strings.NewReader(string(raw[:len(raw)-1]))); err == nil {
		t.Fatal("expected truncated inventory rejection")
	}
}
