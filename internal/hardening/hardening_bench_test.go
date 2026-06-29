// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	ktrace "kurdistan/internal/trace"
)

func BenchmarkInvariantRegistryQuickRun(b *testing.B) {
	profiles := mustProfiles(b, 3)
	for i := 0; i < b.N; i++ {
		_ = RunInvariantRegistry(profiles)
	}
}

func BenchmarkAPIContractSuite(b *testing.B) {
	profiles := mustProfiles(b, 3)
	for i := 0; i < b.N; i++ {
		_ = RunAPIContractChecks(context.Background(), profiles)
	}
}

func BenchmarkPanicSafetySuite(b *testing.B) {
	profiles := mustProfiles(b, 3)
	for i := 0; i < b.N; i++ {
		_ = RunPanicSafetyChecks(profiles)
	}
}

func BenchmarkTraceHygieneScanner(b *testing.B) {
	events := []ktrace.Event{{EventType: "runtime", PayloadHygiene: true, SecretHygiene: true}}
	for i := 0; i < b.N; i++ {
		_ = ScanEvents(events)
	}
}

func BenchmarkResourceLimitSuite(b *testing.B) {
	profiles := mustProfiles(b, 3)
	for i := 0; i < b.N; i++ {
		_ = RunResourceLimitChecks(context.Background(), profiles, Options{Mode: "quick", ProfileCount: 3})
	}
}

func BenchmarkHardeningQuickAudit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		report := Run(context.Background(), nil, Options{Mode: "quick", ProfileCount: 3})
		if report.Conclusion != "passed" {
			b.Fatal(report.Conclusion)
		}
	}
}

func BenchmarkHardeningFullCoreChecks(b *testing.B) {
	profiles := mustProfiles(b, 20)
	for i := 0; i < b.N; i++ {
		report := Run(context.Background(), profiles, Options{Mode: "full", ProfileCount: 20})
		if report.Conclusion != "passed" {
			b.Fatal(report.Conclusion)
		}
	}
}

func mustProfiles(b *testing.B, count int) []*ir.Profile {
	b.Helper()
	profiles := make([]*ir.Profile, 0, count)
	for i := 0; i < count; i++ {
		p, err := compiler.Generate(int64(14010 + i))
		if err != nil {
			b.Fatal(err)
		}
		profiles = append(profiles, p)
	}
	return profiles
}
