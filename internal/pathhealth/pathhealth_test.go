// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import (
	"context"
	"encoding/json"
	"testing"
)

func TestGenerateFixtureSet(t *testing.T) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(set.Scenarios) != len(DefaultScenarios()) {
		t.Fatalf("scenario count mismatch")
	}
	if set.Controls.Conclusion != "failed" || len(set.Controls.MisuseFindings) == 0 {
		t.Fatalf("controls not detected: %+v", set.Controls)
	}
	if set.Parity.Conclusion != "passed" {
		t.Fatalf("parity failed: %+v", set.Parity)
	}
}

func TestScenarioOutcomes(t *testing.T) {
	for _, scenario := range DefaultScenarios() {
		run, err := RunScenario(context.Background(), scenario)
		if err != nil {
			t.Fatalf("%s: %v", scenario.ScenarioID, err)
		}
		if !scenario.Control && run.Report.FinalState != scenario.ExpectedFinalState {
			t.Fatalf("%s final state = %s, want %s", scenario.ScenarioID, run.Report.FinalState, scenario.ExpectedFinalState)
		}
		if !scenario.Control && run.Failover.Outcome != scenario.ExpectedFailoverOutcome {
			t.Fatalf("%s failover = %s, want %s", scenario.ScenarioID, run.Failover.Outcome, scenario.ExpectedFailoverOutcome)
		}
	}
}

func TestTransitionsAndDetector(t *testing.T) {
	if !ValidTransition(HealthHealthy, HealthDegraded, false) {
		t.Fatalf("valid transition rejected")
	}
	if ValidTransition(HealthFailedOver, HealthHealthy, false) {
		t.Fatalf("terminal transition accepted")
	}
	run, err := RunScenario(context.Background(), DefaultScenarios()[2])
	if err != nil {
		t.Fatal(err)
	}
	if run.Degradation.StallEvents == 0 || run.Degradation.DegradationBucket != "severe" {
		t.Fatalf("stall degradation not detected: %+v", run.Degradation)
	}
}

func TestHygieneRejectsUnsafeFields(t *testing.T) {
	cases := []map[string]string{
		{"endpoint": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	}
	for _, tc := range cases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe metadata accepted: %+v", tc)
		}
	}
}

func FuzzValidateJSON(f *testing.F) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	f.Add(raw)
	f.Add([]byte(`{"endpoint":"synthetic"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			t.Skip()
		}
		_ = ValidateJSON(raw)
	})
}

func BenchmarkMonitor(b *testing.B) {
	scenario := DefaultScenarios()[2]
	for i := 0; i < b.N; i++ {
		if _, err := RunScenario(context.Background(), scenario); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMisuseScanner(b *testing.B) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanMisuse(set.Runs)
	}
}
