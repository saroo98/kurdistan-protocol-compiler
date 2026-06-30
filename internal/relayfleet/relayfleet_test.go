// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import (
	"context"
	"encoding/json"
	"testing"

	"kurdistan/internal/hostdetect"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wireeval"
)

func TestGenerateGoldenSummary(t *testing.T) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Conclusion != "passed" {
		t.Fatalf("summary failed: %+v", summary)
	}
	if len(summary.Fleet.Relays) < 6 {
		t.Fatalf("expected relays")
	}
	if summary.Assignment.UniqueProfileSeeds < 3 || summary.Assignment.UniqueWirePolicyHashes < 3 {
		t.Fatalf("assignment diversity collapsed: %+v", summary.Assignment)
	}
	if len(summary.ChurnEvents) == 0 {
		t.Fatalf("expected churn events")
	}
	if len(summary.MigrationEvents) == 0 {
		t.Fatalf("expected migration events")
	}
	if summary.BurnRisk.HighRiskRelays+summary.BurnRisk.CriticalRiskRelays == 0 {
		t.Fatalf("expected high risk relays")
	}
	if err := ScanForLeak(summary); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleTransitions(t *testing.T) {
	policy := DefaultPolicy()
	relay := SyntheticRelay{RelayID: "relay_0001", RelayClass: RelayClassGenerated, State: RelayProvisioned, ProfileID: "profile", ProfileSeed: 1, WirePolicyHash: "hash", SelectedFamily: "family", SyntheticHostID: "host_0001", BurnRiskBucket: RiskLow}
	relay, event, err := TransitionRelay(relay, RelayActive, 1, policy)
	if err != nil {
		t.Fatal(err)
	}
	if event.OldState != string(RelayProvisioned) || event.NewState != string(RelayActive) {
		t.Fatalf("bad transition event: %+v", event)
	}
	relay, _, err = TransitionRelay(relay, RelayBurned, 2, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := TransitionRelay(relay, RelayActive, 3, policy); err == nil {
		t.Fatalf("burned relay reactivated")
	}
}

func TestInvalidTransitionsRejected(t *testing.T) {
	if CanTransition(RelayRetired, RelayActive) {
		t.Fatalf("retired relay can reactivate")
	}
	if CanTransition(RelayBurned, RelayMigrating) {
		t.Fatalf("burned relay can migrate")
	}
}

func TestFleetCollapseControls(t *testing.T) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	collapsed := summary.Fleet
	for i := range collapsed.Relays {
		collapsed.Relays[i].ProfileSeed = 42
		collapsed.Relays[i].WirePolicyHash = "samepolicy"
		collapsed.Relays[i].SelectedFamily = "samefamily"
	}
	collapsed.FleetHash = FleetHash(collapsed)
	assignment := AnalyzeProfileAssignment(collapsed)
	churn := []ChurnEvent{}
	risk := ScoreBurnRisk(collapsed, churn)
	report := ScanCollapse(collapsed, assignment, churn, nil, risk)
	if report.Conclusion == "passed" {
		t.Fatalf("collapsed fleet passed: %+v", report)
	}
}

func TestMigrationValidation(t *testing.T) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range summary.MigrationEvents {
		if err := ValidateMigrationEvent(summary.Fleet, event); err != nil {
			t.Fatal(err)
		}
	}
	bad := summary.MigrationEvents[0]
	bad.TargetRelayID = "relay_9999"
	if err := ValidateMigrationEvent(summary.Fleet, bad); err == nil {
		t.Fatalf("invalid migration accepted")
	}
}

func TestValidationRejectsLeaks(t *testing.T) {
	relay := SyntheticRelay{RelayID: "relay_0001", RelayClass: RelayClassGenerated, State: RelayActive, ProfileID: "profile", ProfileSeed: 1, WirePolicyHash: "hash", SelectedFamily: "family", SyntheticHostID: "host_0001", BurnRiskBucket: RiskLow, PayloadLogged: true}
	if err := ValidateRelay(relay); err == nil {
		t.Fatalf("payload flag accepted")
	}
	if err := ScanForLeak(map[string]string{"endpoint": "synthetic"}); err == nil {
		t.Fatalf("endpoint marker accepted")
	}
	if err := ScanForLeak(map[string]string{"cloud_provider": "synthetic"}); err == nil {
		t.Fatalf("cloud marker accepted")
	}
}

func TestParitySelfComparison(t *testing.T) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	report := CompareFleets(summary, summary)
	if report.Conclusion != "passed" || report.ComparedRelays == 0 {
		t.Fatalf("parity failed: %+v", report)
	}
}

func TestManualRunWithFullOptions(t *testing.T) {
	dataset, err := wireeval.BuildDataset(context.Background(), protocorpus.DefaultCorpus(), wireeval.BuildOptions{Seeds: []int{12345, 12346, 12347, 12348}, Controls: true})
	if err != nil {
		t.Fatal(err)
	}
	hostSummary, err := hostdetect.Run(dataset, hostdetect.DefaultBuildOptions())
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.RelayCount = 8
	opts.ProfileSeeds = []int{12345, 12346, 12347, 12348, 12349, 12350, 12351, 12352}
	summary, err := Run(dataset, hostSummary, opts)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Fleet.Policy.MaxActiveRelays == 0 || summary.BurnRisk.RelayCount == 0 {
		t.Fatalf("empty run summary")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := StableJSON(summary.Fleet)
	if err != nil {
		t.Fatal(err)
	}
	var fleet RelayFleet
	if err := json.Unmarshal(raw, &fleet); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFleet(fleet); err != nil {
		t.Fatal(err)
	}
}
