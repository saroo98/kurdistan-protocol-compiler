// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package loopbackrelay

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateConfigRejectsUnsafeControls(t *testing.T) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	cases := []struct {
		name string
		edit func(*LoopbackRelayConfig)
	}{
		{"wildcard bind", func(c *LoopbackRelayConfig) { c.AllowWildcardBind = true }},
		{"external bind", func(c *LoopbackRelayConfig) { c.AllowExternalBind = true }},
		{"external dial", func(c *LoopbackRelayConfig) { c.AllowExternalDial = true }},
		{"dns", func(c *LoopbackRelayConfig) { c.AllowDNSResolution = true }},
		{"payload logging", func(c *LoopbackRelayConfig) { c.AllowPayloadLogging = true }},
		{"unsafe host", func(c *LoopbackRelayConfig) { c.AllowedBindHosts = []string{"8.8.8.8"} }},
	}
	for _, tc := range cases {
		cfg := DefaultConfig()
		tc.edit(&cfg)
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("%s config accepted", tc.name)
		}
	}
}

func TestLoopbackHostValidation(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		if err := ValidateLoopbackHost(host); err != nil {
			t.Fatalf("%s rejected: %v", host, err)
		}
	}
	for _, host := range []string{"0.0.0.0", "1.1.1.1", "example.invalid", ""} {
		if err := ValidateLoopbackHost(host); err == nil {
			t.Fatalf("%s accepted", host)
		}
	}
}

func TestGenerateFixtureSet(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || set.Report.SessionsOpened != len(set.Scenarios) {
		t.Fatalf("unexpected fixture: %+v", set.Report)
	}
	if set.Report.BackpressureEvents == 0 || set.Report.ResetsObserved == 0 || set.Report.MalformedRejected == 0 {
		t.Fatalf("fixture did not exercise pressure/reset/malformed cases: %+v", set.Report)
	}
	if err := ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureComparisonDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Report.SessionsOpened++
	newSet.FixtureHash = HashValue(setWithoutHash(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" {
		t.Fatalf("drift not detected: %+v", report)
	}
}

func TestScanForLeakRejectsUnsafeMarkers(t *testing.T) {
	if err := ScanForLeak(map[string]string{"raw_payload": "synthetic"}); err == nil {
		t.Fatal("raw payload marker accepted")
	}
	if err := ScanForLeak(map[string]string{"public_ip": "synthetic"}); err == nil {
		t.Fatal("public address marker accepted")
	}
}

func FuzzValidateLoopbackHost(f *testing.F) {
	for _, seed := range []string{"127.0.0.1", "::1", "8.8.8.8", "localhost"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		if len(host) > 256 {
			host = host[:256]
		}
		_ = ValidateLoopbackHost(host)
	})
}

func FuzzFixtureJSON(f *testing.F) {
	set, err := GenerateFixtureSet()
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	f.Add(string(raw))
	f.Add(`{"raw_payload":"x"}`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<15 {
			input = input[:1<<15]
		}
		var v any
		if json.Unmarshal([]byte(input), &v) == nil {
			err := ScanForLeak(v)
			if strings.Contains(strings.ToLower(input), "raw_payload") && err == nil {
				t.Fatalf("unsafe fixture input accepted")
			}
		}
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}
