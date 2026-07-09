// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localvpnadapter

import "testing"

func TestGenerateFixtureSetCoversPrototype(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if set.BackendVersion != BackendVersion || set.Summary.RuntimeStreamsMapped < 7 || set.Summary.BackpressureEvents == 0 || set.Summary.FlowsReset == 0 {
		t.Fatalf("prototype summary incomplete: %+v", set.Summary)
	}
	if set.PayloadLogged || set.SecretLogged || set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.PacketDumped {
		t.Fatalf("unsafe fixture hygiene flags set")
	}
}

func TestValidateConfigRejectsUnsafeModes(t *testing.T) {
	mutators := []func(*Config){
		func(c *Config) { c.AllowAndroidService = true },
		func(c *Config) { c.AllowPublicDeployment = true },
		func(c *Config) { c.AllowRouteMutation = true },
		func(c *Config) { c.AllowPacketDump = true },
		func(c *Config) { c.AllowPayloadLogging = true },
		func(c *Config) { c.AllowCredentialStorage = true },
		func(c *Config) { c.AllowAppIdentityLogging = true },
		func(c *Config) { c.AllowPreciseEndpointLog = true },
		func(c *Config) { c.AllowDNSInterception = true },
		func(c *Config) { c.AllowPublicNetworkDefaults = true },
		func(c *Config) { c.PayloadLogged = true },
		func(c *Config) { c.SecretLogged = true },
	}
	for i, mutate := range mutators {
		cfg := DefaultConfig()
		mutate(&cfg)
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("unsafe config %d accepted", i)
		}
	}
}

func TestMisuseControlsDetected(t *testing.T) {
	report := BuildMisuseReport()
	if report.DetectedCount != len(RequiredMisuseNames()) || report.ExpectedCount != len(RequiredMisuseNames()) || report.Conclusion != ConclusionPassed {
		t.Fatalf("misuse report incomplete: %+v", report)
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Summary.BackpressureEvents++
	newSet.FixtureHash = HashValue(fixtureHashInput(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion == ConclusionPassed || len(report.UnexpectedDrift) == 0 {
		t.Fatalf("drift was not detected: %+v", report)
	}
}

func TestScanForLeakRejectsUnsafeFields(t *testing.T) {
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_packet_bytes": "synthetic"},
		map[string]string{"exact_endpoint_value": "synthetic"},
		map[string]string{"app_identity_value": "synthetic"},
		map[string]bool{"payload_logged": true},
		map[string]bool{"allow_route_mutation": true},
		map[string]bool{"allow_android_service": true},
		map[string]bool{"packet_dumped": true},
	}
	for _, tc := range unsafeCases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe metadata accepted: %#v", tc)
		}
	}
}

func TestControlFlowsRejectedBeforeRuntimeMapping(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	rejected := 0
	for _, run := range set.Runs {
		if run.Rejected {
			rejected++
			if run.OpenResult != "rejected_before_runtime_stream" || run.RejectReasonBucket == "" {
				t.Fatalf("rejected control missing safe reason: %+v", run)
			}
		}
	}
	if rejected < 4 {
		t.Fatalf("expected at least four rejected controls, got %d", rejected)
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"packet_flow_class":"tcp_like_flow"}`)
	f.Add(`{"raw_packet_bytes":"synthetic"}`)
	f.Fuzz(func(t *testing.T, input string) {
		_ = ScanForLeak(map[string]string{"value": input})
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompareFixtureSets(b *testing.B) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	newSet, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CompareFixtureSets(oldSet, newSet)
	}
}

func BenchmarkScanForLeak(b *testing.B) {
	set, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ScanForLeak(set); err != nil {
			b.Fatal(err)
		}
	}
}
