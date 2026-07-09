// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package labegress

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
		edit func(*LabEgressConfig)
	}{
		{"external target", func(c *LabEgressConfig) { c.AllowExternalTargets = true }},
		{"dns", func(c *LabEgressConfig) { c.AllowDNSResolution = true }},
		{"raw address", func(c *LabEgressConfig) { c.AllowRawAddressTrace = true }},
		{"payload logging", func(c *LabEgressConfig) { c.AllowPayloadLogging = true }},
		{"unknown target", func(c *LabEgressConfig) { c.AllowedTargetClasses = []string{"unknown"} }},
		{"unsafe host", func(c *LabEgressConfig) { c.AllowedLoopbackHosts = []string{"8.8.8.8"} }},
	}
	for _, tc := range cases {
		cfg := DefaultConfig()
		tc.edit(&cfg)
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("%s config accepted", tc.name)
		}
	}
}

func TestGenerateFixtureSet(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || set.Report.ConnectionsOpened != len(set.Scenarios) {
		t.Fatalf("unexpected fixture: %+v", set.Report)
	}
	if set.Report.BackpressureEvents == 0 || set.Report.TargetErrors == 0 || set.Report.TargetResets == 0 {
		t.Fatalf("fixture did not exercise egress pressure/error/reset cases: %+v", set.Report)
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
	newSet.Report.ConnectionsOpened++
	newSet.FixtureHash = HashValue(setWithoutHash(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" {
		t.Fatalf("drift not detected: %+v", report)
	}
}

func TestScanForLeakRejectsUnsafeMarkers(t *testing.T) {
	for _, marker := range []string{"raw_payload", "public_ip", "dns_query", "raw_secret"} {
		if err := ScanForLeak(map[string]string{marker: "synthetic"}); err == nil {
			t.Fatalf("%s accepted", marker)
		}
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
