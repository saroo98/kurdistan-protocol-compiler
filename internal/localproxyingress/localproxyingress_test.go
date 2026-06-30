// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import (
	"context"
	"testing"

	"kurdistan/internal/proxyingress"
)

func TestSourceDeterminism(t *testing.T) {
	a, err := GenerateEvents(ScenarioManySmallConnects)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateEvents(ScenarioManySmallConnects)
	if err != nil {
		t.Fatal(err)
	}
	if HashValue(a) != HashValue(b) || len(a) == 0 {
		t.Fatal("source not deterministic")
	}
}

func TestQueueBoundsAndDuplicate(t *testing.T) {
	events, _ := GenerateEvents(ScenarioSingleConnectEcho)
	q := NewQueue(1)
	if err := q.Enqueue(events[0]); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(events[0]); err == nil {
		t.Fatal("duplicate accepted")
	}
	events[1].EventID = "different_event"
	if err := q.Enqueue(events[1]); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestRunScenarios(t *testing.T) {
	for _, scenario := range FullScenarios() {
		summary, err := RunScenario(context.Background(), scenario, DefaultConfig())
		if err != nil {
			t.Fatalf("%s: %v", scenario, err)
		}
		if err := ValidateSummary(summary); err != nil {
			t.Fatalf("%s: %v", scenario, err)
		}
		if summary.PayloadLogged || summary.SecretLogged {
			t.Fatalf("%s leaked hygiene flags", scenario)
		}
	}
}

func TestInvalidAndLifecycleRejections(t *testing.T) {
	invalid, err := RunScenario(context.Background(), ScenarioInvalidTargetRejection, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if invalid.RejectedRequests == 0 {
		t.Fatal("invalid target scenario did not reject")
	}
	violation, err := RunScenario(context.Background(), ScenarioLifecycleViolation, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if violation.LifecycleViolations == 0 {
		t.Fatal("lifecycle violation was not detected")
	}
}

func TestFixtureSet(t *testing.T) {
	set, err := GenerateFixtureSet(context.Background(), QuickScenarios())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if CompareFixtureSets(set, set).Conclusion != "passed" {
		t.Fatal("self comparison failed")
	}
}

func FuzzSyntheticEventValidation(f *testing.F) {
	f.Add("evt", "req", "open", "target_alpha")
	contract := Contract()
	f.Fuzz(func(t *testing.T, eventID, requestID, kind, descriptor string) {
		if len(eventID) > 128 || len(requestID) > 128 || len(kind) > 64 || len(descriptor) > 256 {
			t.Skip()
		}
		target := proxyingress.ValidTargetDescriptors()[0]
		target.DescriptorID = descriptor
		_ = ValidateEvent(SyntheticIngressEvent{EventID: eventID, RequestID: requestID, Kind: RequestEventKind(kind), Target: target, ByteCountBucket: "bucket_1k", ChunkClass: "chunk_small", FlowClass: "interactive"}, contract)
	})
}

func BenchmarkRunScenario(b *testing.B) {
	cfg := DefaultConfig()
	for i := 0; i < b.N; i++ {
		_, _ = RunScenario(context.Background(), ScenarioManySmallConnects, cfg)
	}
}
