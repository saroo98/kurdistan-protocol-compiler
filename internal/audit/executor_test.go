// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParallelFamilyExecutorReturnsRegistryOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	releaseFirst := make(chan struct{})
	secondFinished := make(chan struct{})
	families := []auditFamily{
		{ID: "first", Run: func(context.Context, familyValues) (any, error) {
			<-releaseFirst
			return "first-value", nil
		}},
		{ID: "second", Run: func(context.Context, familyValues) (any, error) {
			close(secondFinished)
			return "second-value", nil
		}},
	}
	type outcome struct {
		results []auditFamilyResult
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := executeAuditFamilies(ctx, ExecutorOptions{Mode: ExecutorParallel, Workers: 2}, families)
		done <- outcome{results: results, err: err}
	}()

	select {
	case <-secondFinished:
		close(releaseFirst)
	case <-ctx.Done():
		t.Fatal("families did not execute concurrently")
	}
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if len(result.results) != 2 || result.results[0].ID != "first" || result.results[1].ID != "second" {
		t.Fatalf("result order = %+v", result.results)
	}
}

func TestParallelFamilyExecutorReturnsRegistryFirstFailure(t *testing.T) {
	secondFinished := make(chan struct{})
	families := []auditFamily{
		{ID: "first", Run: func(context.Context, familyValues) (any, error) {
			<-secondFinished
			return nil, errors.New("first failure")
		}},
		{ID: "second", Run: func(context.Context, familyValues) (any, error) {
			close(secondFinished)
			return nil, errors.New("second failure")
		}},
	}
	_, err := executeAuditFamilies(context.Background(), ExecutorOptions{Mode: ExecutorParallel, Workers: 2}, families)
	if err == nil || !strings.Contains(err.Error(), "first failure") || strings.Contains(err.Error(), "second failure") {
		t.Fatalf("parallel failure = %v", err)
	}
}

func TestFamilyExecutorConvertsPanicToFailure(t *testing.T) {
	for _, mode := range []ExecutorMode{ExecutorSerial, ExecutorParallel} {
		t.Run(string(mode), func(t *testing.T) {
			families := []auditFamily{{ID: "panic-family", Run: func(context.Context, familyValues) (any, error) {
				panic("injected panic")
			}}}
			_, err := executeAuditFamilies(context.Background(), ExecutorOptions{Mode: mode, Workers: 2}, families)
			if err == nil || !strings.Contains(err.Error(), "panic-family") || !strings.Contains(err.Error(), "injected panic") {
				t.Fatalf("panic error = %v", err)
			}
		})
	}
}

func TestFamilyExecutorRejectsCancelledContextBeforeStartingWork(t *testing.T) {
	for _, mode := range []ExecutorMode{ExecutorSerial, ExecutorParallel} {
		t.Run(string(mode), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var called atomic.Int32
			families := []auditFamily{{ID: "must-not-run", Run: func(context.Context, familyValues) (any, error) {
				called.Add(1)
				return "unexpected", nil
			}}}
			_, err := executeAuditFamilies(ctx, ExecutorOptions{Mode: mode, Workers: 2}, families)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation error = %v", err)
			}
			if called.Load() != 0 {
				t.Fatalf("cancelled executor started %d families", called.Load())
			}
		})
	}
}

func TestFamilyExecutorFailsWhenContextIsCancelledDuringWork(t *testing.T) {
	for _, mode := range []ExecutorMode{ExecutorSerial, ExecutorParallel} {
		t.Run(string(mode), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			families := []auditFamily{{ID: "cancelling-family", Run: func(context.Context, familyValues) (any, error) {
				cancel()
				return "must-not-be-accepted", nil
			}}}
			_, err := executeAuditFamilies(ctx, ExecutorOptions{Mode: mode, Workers: 2}, families)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation error = %v", err)
			}
		})
	}
}

func TestOrderAuditFamilyResultsRejectsMissingAndDuplicateResult(t *testing.T) {
	families := []auditFamily{{ID: "first"}, {ID: "second"}}
	tests := []struct {
		name    string
		results []auditFamilyResult
	}{
		{name: "missing", results: []auditFamilyResult{{ID: "first"}}},
		{name: "duplicate", results: []auditFamilyResult{{ID: "first"}, {ID: "first"}, {ID: "second"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := orderAuditFamilyResults(families, test.results); err == nil {
				t.Fatalf("results %+v unexpectedly accepted", test.results)
			}
		})
	}
}

func TestFamilyExecutorRejectsInvalidRegistryBeforeStartingWork(t *testing.T) {
	tests := []struct {
		name     string
		families func(*atomic.Int32) []auditFamily
	}{
		{name: "duplicate identity", families: func(called *atomic.Int32) []auditFamily {
			return []auditFamily{countedFamily("same", nil, called), countedFamily("same", nil, called)}
		}},
		{name: "missing dependency", families: func(called *atomic.Int32) []auditFamily {
			return []auditFamily{countedFamily("dependent", []string{"absent"}, called)}
		}},
		{name: "cycle", families: func(called *atomic.Int32) []auditFamily {
			return []auditFamily{countedFamily("first", []string{"second"}, called), countedFamily("second", []string{"first"}, called)}
		}},
		{name: "duplicate dependency", families: func(called *atomic.Int32) []auditFamily {
			return []auditFamily{countedFamily("first", nil, called), countedFamily("second", []string{"first", "first"}, called)}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var called atomic.Int32
			_, err := executeAuditFamilies(context.Background(), ExecutorOptions{Mode: ExecutorParallel, Workers: 2}, test.families(&called))
			if err == nil {
				t.Fatal("invalid registry unexpectedly accepted")
			}
			if called.Load() != 0 {
				t.Fatalf("invalid registry started %d families", called.Load())
			}
		})
	}
}

func countedFamily(id string, dependencies []string, called *atomic.Int32) auditFamily {
	return auditFamily{ID: id, Dependencies: dependencies, Run: func(context.Context, familyValues) (any, error) {
		called.Add(1)
		return id, nil
	}}
}

func TestCanonicalAuditReportEqualityIgnoresVolatileFields(t *testing.T) {
	left := AuditReport{
		Version: Version, Mode: "quick", GeneratedAt: "2026-08-02T10:00:00Z",
		ProfileCount: 3, TraceCount: 1,
		Gates:            []GateResult{{Name: "gate-a", Passed: true, Severity: "required", Summary: "ok"}},
		BenchmarkSummary: BenchmarkSummary{ProfileGenerationMillis: 1, TraceGenerationMillis: 2, TotalMillis: 3},
		Conclusion:       "passed",
	}
	right := left
	right.GeneratedAt = "2026-08-02T10:00:05Z"
	right.BenchmarkSummary = BenchmarkSummary{ProfileGenerationMillis: 10, TraceGenerationMillis: 20, TotalMillis: 30}
	if err := CanonicalAuditReportsEqual(left, right); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalAuditReportEqualityDetectsGateDrift(t *testing.T) {
	left := AuditReport{Version: Version, Mode: "quick", Gates: []GateResult{{Name: "gate-a", Passed: true, Severity: "required", Summary: "ok"}}, Conclusion: "passed"}
	right := left
	right.Gates = []GateResult{{Name: "gate-a", Passed: false, Severity: "required", Summary: "failed"}}
	right.Conclusion = "failed"
	if err := CanonicalAuditReportsEqual(left, right); err == nil {
		t.Fatal("gate drift unexpectedly compared equal")
	}
}

func TestRunWithParallelExecutorUsesCanonicalShadow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 8
	cfg.TraceCount = 3
	report, err := RunWithExecutor(ctx, cfg, ExecutorOptions{Mode: ExecutorParallel, Workers: 3})
	if err != nil {
		t.Fatalf("parallel audit shadow: %v", err)
	}
	if len(report.Gates) == 0 {
		t.Fatal("executor returned an empty audit")
	}
	if report.Mode != "quick" {
		t.Fatalf("report mode = %q", report.Mode)
	}
	if report.GeneratedAt == "" || report.BenchmarkSummary == nil {
		t.Fatal("shadow did not return the authoritative audit report")
	}
}

func TestCanonicalMainAuditFamilyEqualityIncludesErrorText(t *testing.T) {
	left := mainAuditFamilyValues{WireEvaluation: wireEvaluationFamilyValue{Err: errors.New("same failure")}}
	right := mainAuditFamilyValues{WireEvaluation: wireEvaluationFamilyValue{Err: errors.New("same failure")}}
	if err := canonicalMainAuditFamilyValuesEqual(left, right); err != nil {
		t.Fatal(err)
	}
	right.WireEvaluation.Err = errors.New("different failure")
	if err := canonicalMainAuditFamilyValuesEqual(left, right); err == nil {
		t.Fatal("error drift unexpectedly compared equal")
	}
}

func TestParallelFamilyExecutorDoesNotExceedWorkerLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	var active atomic.Int32
	var maximum atomic.Int32
	families := make([]auditFamily, 0, 4)
	for index := range 4 {
		id := fmt.Sprintf("family-%d", index)
		families = append(families, auditFamily{ID: id, Run: func(ctx context.Context, _ familyValues) (any, error) {
			current := active.Add(1)
			for observed := maximum.Load(); current > observed && !maximum.CompareAndSwap(observed, current); observed = maximum.Load() {
			}
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				active.Add(-1)
				return nil, ctx.Err()
			}
			active.Add(-1)
			return id, nil
		}})
	}
	done := make(chan error, 1)
	go func() {
		_, err := executeAuditFamilies(ctx, ExecutorOptions{Mode: ExecutorParallel, Workers: 2}, families)
		done <- err
	}()
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("two workers did not start")
		}
	}
	select {
	case <-started:
		close(release)
		<-done
		t.Fatalf("third family started before a worker was released; maximum=%d", maximum.Load())
	case <-time.After(100 * time.Millisecond):
		close(release)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if maximum.Load() > 2 {
		t.Fatalf("maximum workers = %d, want at most 2", maximum.Load())
	}
}

func TestParallelFamilyExecutorHonorsDeclaredDependencies(t *testing.T) {
	families := []auditFamily{
		{ID: "dependent", Dependencies: []string{"prerequisite"}, Run: func(_ context.Context, values familyValues) (any, error) {
			if values["prerequisite"] != "ready" {
				return nil, errors.New("prerequisite result unavailable")
			}
			return "dependent-value", nil
		}},
		{ID: "prerequisite", Run: func(context.Context, familyValues) (any, error) {
			return "ready", nil
		}},
	}
	results, err := executeAuditFamilies(context.Background(), ExecutorOptions{Mode: ExecutorParallel, Workers: 2}, families)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].ID != "dependent" || results[0].Value != "dependent-value" {
		t.Fatalf("dependency results = %+v", results)
	}
}
