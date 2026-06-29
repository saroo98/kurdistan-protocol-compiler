// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"testing"

	"kurdistan/internal/proxyadversary"
	"kurdistan/internal/security"
)

func BenchmarkRuntimeHarnessHappyPath(b *testing.B) {
	p := mustProfile(b, 91)
	scenario := proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := RunLocalHarness(context.Background(), p, HarnessOptions{Scenario: scenario}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCapabilityNegotiation(b *testing.B) {
	required := security.DefaultCapabilities()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NegotiateCapabilities(security.DefaultCapabilities(), security.DefaultCapabilities(), required); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMemoryLinkSendDeliver(b *testing.B) {
	link := NewMemoryLink(1024)
	frame := LinkFrame{Direction: "client_to_server", Sequence: 1, EnvelopeKind: "runtime_session", ByteCount: 64}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame.Sequence = uint64(i + 1)
		if err := link.Send(frame); err != nil {
			b.Fatal(err)
		}
		if _, err := link.Deliver("client_to_server"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamManagerOpenClose(b *testing.B) {
	p := mustProfile(b, 92)
	cfg := DefaultConfig(RoleClient, "bench", []byte("secret"))
	rt, err := NewRuntime(cfg, p)
	if err != nil {
		b.Fatal(err)
	}
	session, err := NewManager(rt).CreateSession()
	if err != nil {
		b.Fatal(err)
	}
	_ = session.BeginNegotiation()
	_ = session.BeginSecuring()
	_ = session.MarkOpen()
	manager, err := NewStreamManager(session, p)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id, err := manager.OpenStream("interactive", zeroIntent())
		if err != nil {
			b.Fatal(err)
		}
		if err := manager.CloseStream(id); err != nil {
			b.Fatal(err)
		}
	}
}
