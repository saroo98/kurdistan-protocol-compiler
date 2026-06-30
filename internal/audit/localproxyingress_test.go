// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"

	"kurdistan/internal/localproxyingress"
)

func TestLocalProxyIngressGatesPass(t *testing.T) {
	set, err := localproxyingress.GenerateFixtureSet(context.Background(), localproxyingress.FullScenarios())
	if err != nil {
		t.Fatal(err)
	}
	gates := LocalProxyIngressGates(set, localproxyingress.CompareFixtureSets(set, set))
	for _, gate := range gates {
		if !gate.Passed {
			t.Fatalf("%s failed: %#v", gate.Name, gate.Details)
		}
	}
}

func TestLocalProxyIngressAuditQuickRuns(t *testing.T) {
	set, err := localproxyingress.GenerateFixtureSet(context.Background(), localproxyingress.QuickScenarios())
	if err != nil {
		t.Fatal(err)
	}
	gates := LocalProxyIngressGates(set, localproxyingress.CompareFixtureSets(set, set))
	if len(gates) == 0 {
		t.Fatal("no gates")
	}
}

func BenchmarkLocalProxyIngressAuditQuick(b *testing.B) {
	set, _ := localproxyingress.GenerateFixtureSet(context.Background(), localproxyingress.QuickScenarios())
	cmp := localproxyingress.CompareFixtureSets(set, set)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LocalProxyIngressGates(set, cmp)
	}
}
