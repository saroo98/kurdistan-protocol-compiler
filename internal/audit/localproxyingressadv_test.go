// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"

	"kurdistan/internal/localproxyingressadversary"
)

func TestLocalProxyIngressAdversarialGatesPass(t *testing.T) {
	set, err := localproxyingressadversary.GenerateAdversarialFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gates := LocalProxyIngressAdversarialGates(set, localproxyingressadversary.CompareAdversarialFixtureSets(set, set))
	for _, gate := range gates {
		if !gate.Passed {
			t.Fatalf("%s failed: %#v", gate.Name, gate)
		}
	}
}

func TestLocalProxyIngressAdversarialMutantGateFailsMissing(t *testing.T) {
	control := localproxyingressadversary.RunCollapsedMappingControl()
	if control.Conclusion != "failed" {
		t.Fatal("collapsed mapping control was not detected")
	}
}

func TestRunLocalProxyIngressAdversarialAuditQuick(t *testing.T) {
	report, err := RunLocalProxyIngressAdversarialAudit(context.Background(), DefaultConfig("quick"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Conclusion != "passed" {
		t.Fatalf("audit failed: %#v", report.Gates)
	}
	if _, ok := gateByName(report.Gates, "localproxyingressadv_m27_readiness"); !ok {
		t.Fatal("readiness gate missing")
	}
}

func BenchmarkLocalProxyIngressAdversarialQuick(b *testing.B) {
	for i := 0; i < b.N; i++ {
		report, err := RunLocalProxyIngressAdversarialAudit(context.Background(), DefaultConfig("quick"))
		if err != nil {
			b.Fatal(err)
		}
		if report.Conclusion != "passed" {
			b.Fatal(report.Conclusion)
		}
	}
}
