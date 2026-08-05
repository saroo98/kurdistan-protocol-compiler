// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package backup

import (
	"errors"
	"testing"
)

func TestVerifyRestoreRejectsRollbackAndFork(t *testing.T) {
	base := Head{Epoch: 2, Revision: 8, Sequence: 12, StateDigest: digest("a"), AuditDigest: digest("b"), PublicDigest: digest("c")}
	evidence := RestoreEvidence{Restored: base, PreIncident: base, ExternalAudit: base, ExternalPublic: base, PendingOutbox: 2, SchemaVersion: "phase16-spanner-authority-v1"}
	plan, err := VerifyRestore(evidence)
	if err != nil || plan.FromSequence != 13 || plan.Count != 2 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	evidence.Restored.Revision = 7
	if _, err := VerifyRestore(evidence); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback error=%v", err)
	}
	evidence.Restored = base
	evidence.ExternalPublic.StateDigest = digest("d")
	if _, err := VerifyRestore(evidence); !errors.Is(err, ErrFork) {
		t.Fatalf("fork error=%v", err)
	}
}

func digest(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}
