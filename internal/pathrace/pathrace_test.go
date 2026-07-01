// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import (
	"context"
	"testing"

	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/transportbundle"
)

func TestScenariosValidateAndReportsAreStable(t *testing.T) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	again, err := GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if set.FixtureSetHash != again.FixtureSetHash {
		t.Fatalf("fixture hash drift: %s != %s", set.FixtureSetHash, again.FixtureSetHash)
	}
	if set.Controls.Conclusion != "failed" || len(set.Controls.MisuseFindings) == 0 {
		t.Fatalf("controls not detected: %+v", set.Controls)
	}
	if err := ScanForLeak(set); err != nil {
		t.Fatalf("fixture leaked unsafe metadata: %v", err)
	}
}

func TestSchedulerVerifierScoringAndRanking(t *testing.T) {
	run, err := RunScenario(context.Background(), RaceScenario{
		ScenarioID: "tcp_blackhole_then_dns_success", RaceMode: RaceModeVerifiedUsable,
		BundleMode: transportbundle.BundleModeSurvivalDNS, CandidateCount: 5,
		ExpectedWinnerClass: string(adaptivepath.CandidateDNSSurvival), ExpectedVerified: 1, ExpectedRejected: 1, ExpectedConclusion: "passed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.Policy.MaxParallelCandidates < 2 {
		t.Fatalf("scheduler is not parallel: %+v", run.Policy)
	}
	if run.Report.WinnerFamily != string(adaptivepath.CandidateDNSSurvival) {
		t.Fatalf("winner = %s, want dns survival", run.Report.WinnerFamily)
	}
	for _, outcome := range run.Outcomes {
		if outcome.Family == string(adaptivepath.CandidateHTTPSLikeTCP) && outcome.FinalState != RaceStateFailed {
			t.Fatalf("blackholed tcp candidate not failed: %+v", outcome)
		}
	}
}

func TestRiskAndFreshnessControlsDetected(t *testing.T) {
	runs := []PathRaceRun{}
	for _, scenario := range DefaultScenarios() {
		if scenario.Control {
			run, err := RunScenario(context.Background(), scenario)
			if err != nil {
				t.Fatal(err)
			}
			runs = append(runs, run)
		}
	}
	report := ScanMisuse(runs)
	for _, finding := range []string{"always_picks_first_candidate", "stale_success_beats_fresh_success", "high_risk_candidate_wins_by_default"} {
		found := false
		for _, got := range report.MisuseFindings {
			if got == finding {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing misuse finding %q in %+v", finding, report)
		}
	}
}

func TestLeakDetection(t *testing.T) {
	for _, unsafe := range []map[string]string{
		{"endpoint": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	} {
		if err := ScanForLeak(unsafe); err == nil {
			t.Fatalf("unsafe field accepted: %#v", unsafe)
		}
	}
}

func FuzzValidateReportJSON(f *testing.F) {
	f.Add([]byte(`{"version":"pathrace-v1"}`))
	f.Add([]byte(`{"endpoint":"x"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = ValidateReportJSON(raw)
	})
}

func BenchmarkSchedulerExecution(b *testing.B) {
	compiled, err := transportbundle.Compile(context.Background(), transportbundle.DefaultPolicy(12345, transportbundle.BundleModeBalancedAdaptive))
	if err != nil {
		b.Fatal(err)
	}
	scenario := DefaultScenarios()[1]
	for i := 0; i < b.N; i++ {
		if _, err := RunScenarioWithManifest(scenario, compiled.Manifest); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMisuseScanner(b *testing.B) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		_ = ScanMisuse(set.Runs)
	}
}
