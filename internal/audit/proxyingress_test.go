// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"

	"kurdistan/internal/proxyingress"
	"kurdistan/internal/proxyingressreview"
)

func TestProxyIngressGatesPass(t *testing.T) {
	set, err := proxyingress.GoldenFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	review, misuse, parity, err := proxyingressreview.GenerateGoldenReview()
	if err != nil {
		t.Fatal(err)
	}
	gates := ProxyIngressGates(set, review, misuse, parity, proxyingress.CompareContractsOnly(set.Contract, set.Contract))
	for _, gate := range gates[:len(gates)-1] {
		if !gate.Passed {
			t.Fatalf("%s failed: %v", gate.Name, gate.Details)
		}
	}
}

func TestProxyIngressAuditQuickRuns(t *testing.T) {
	report, err := RunProxyIngressAudit(context.Background(), DefaultConfig("quick"))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Gates) == 0 {
		t.Fatal("no gates")
	}
}

func TestProxyIngressMisuseGateFailsUnsafeSynthetic(t *testing.T) {
	set, _ := proxyingress.GoldenFixtureSet()
	set.Requests[0].Target.DescriptorID = "127.0.0.1"
	review, _, _, _ := proxyingressreview.GenerateGoldenReview()
	report := proxyingressreview.ScanMisuse(set.Contract, set.Requests, set.Mappings, set.Lifecycle, review)
	gate := ProxyIngressMisuseDetectionGate(report)
	if gate.Passed {
		t.Fatal("unsafe target misuse gate passed")
	}
}

func BenchmarkProxyIngressAuditQuick(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = RunProxyIngressAudit(context.Background(), DefaultConfig("quick"))
	}
}
