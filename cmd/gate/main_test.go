// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import "testing"

func TestGateStepsRemainCacheProof(t *testing.T) {
	steps := gateSteps(false, "report.json", "status.md")
	if len(steps) != 4 {
		t.Fatalf("got %d Go gate steps", len(steps))
	}
	if got := steps[2].args; len(got) < 2 || got[0] != "test" || got[1] != "-count=1" {
		t.Fatalf("test gate is not cache-proof: %v", got)
	}
	for _, value := range steps {
		if value.program != "go" {
			t.Fatalf("unexpected Go gate program %q", value.program)
		}
	}
}

func TestAndroidStepUsesRepositoryWrapper(t *testing.T) {
	value := androidStep()
	if value.dir != "android" {
		t.Fatalf("Android gate directory = %q", value.dir)
	}
	found := value.program == "./gradlew"
	for _, argument := range value.args {
		found = found || argument == "gradlew.bat"
	}
	if !found {
		t.Fatalf("Android gate does not use the repository wrapper: %#v", value)
	}
}
