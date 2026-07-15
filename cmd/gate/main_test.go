// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"reflect"
	"testing"
)

func TestGateUsesUncachedFullTestCommand(t *testing.T) {
	steps := gateSteps(false, "report.json", "status.md")
	for _, step := range steps {
		if step.name != "test" {
			continue
		}
		want := []string{"test", "-count=1", "./..."}
		if !reflect.DeepEqual(step.args, want) {
			t.Fatalf("test gate args=%v want %v", step.args, want)
		}
		return
	}
	t.Fatal("test gate step missing")
}
