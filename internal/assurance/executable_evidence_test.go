// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestExecutableEvidenceInventoryIsDefensiveAndComplete(t *testing.T) {
	commands := ExecutableEvidenceCommands()
	if len(commands) != 4 {
		t.Fatalf("command count = %d, want 4", len(commands))
	}
	commands[0][0] = "mutated"
	if ExecutableEvidenceCommands()[0][0] != "test" {
		t.Fatal("caller mutation changed authoritative command inventory")
	}
}

func TestRunExecutableEvidenceFailsClosedInCanonicalOrder(t *testing.T) {
	want := ExecutableEvidenceCommands()
	seen := [][]string{}
	errSentinel := errors.New("failure")
	err := runExecutableEvidence(context.Background(), ".", &bytes.Buffer{}, func(_ context.Context, _ string, args []string) ([]byte, error) {
		seen = append(seen, append([]string(nil), args...))
		if len(seen) == 3 {
			return []byte("failed\n"), errSentinel
		}
		return []byte("passed\n"), nil
	})
	if !errors.Is(err, errSentinel) || !reflect.DeepEqual(seen, want[:3]) {
		t.Fatalf("seen = %v, err = %v", seen, err)
	}
}
