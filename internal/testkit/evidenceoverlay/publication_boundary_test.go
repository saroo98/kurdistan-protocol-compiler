// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package evidenceoverlay

import (
	"path/filepath"
	"testing"
)

func TestRepositorySuccessorChainUsesOnlyPublishedEvidence(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	if _, err := LoadSuccessor(root, "phase15-production-contract-v1"); err != nil {
		t.Fatalf("load repository successor chain: %v", err)
	}
}
