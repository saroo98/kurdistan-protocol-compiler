// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package concretelocaladapter

import (
	"context"
	"encoding/json"
	"testing"
)

func TestValidateBindConfigRejectsUnsafeHosts(t *testing.T) {
	for _, host := range []string{"", "0.0.0.0", "::", "8.8.8.8", "example.invalid"} {
		cfg := DefaultConfig()
		cfg.Host = host
		if err := ValidateBindConfig(cfg); err == nil {
			t.Fatalf("unsafe host accepted: %q", host)
		}
	}
	for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
		cfg := DefaultConfig()
		cfg.Host = host
		if err := ValidateBindConfig(cfg); err != nil {
			t.Fatalf("loopback host rejected: %q: %v", host, err)
		}
	}
}

func TestLoopbackProbe(t *testing.T) {
	summary, err := RunLoopbackProbe(context.Background(), DefaultConfig(), DefaultScenarios()[0])
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Completed || summary.ConnectionsAccepted != 1 || summary.PayloadLogged || summary.SecretLogged {
		t.Fatalf("unexpected loopback summary: %+v", summary)
	}
}

func TestGenerateFixtureSet(t *testing.T) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || len(set.Summaries) < 8 || set.FixtureHash == "" {
		t.Fatalf("invalid fixture set: %+v", set)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
}

func TestScanForLeakRejectsUnsafeMetadata(t *testing.T) {
	for _, tc := range []map[string]string{{"raw_payload": "x"}, {"client_write_key": "x"}, {"encoded_bytes": "x"}} {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe metadata accepted: %+v", tc)
		}
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mutated := set
	mutated.Summaries[0].FlowsOpened++
	report := CompareFixtureSets(set, mutated)
	if report.Conclusion != "failed" {
		t.Fatalf("drift not detected: %+v", report)
	}
}

func FuzzValidateBindConfig(f *testing.F) {
	f.Add("127.0.0.1", 0, 1, 1024, 16)
	f.Add("0.0.0.0", 80, 1, 1024, 16)
	f.Fuzz(func(t *testing.T, host string, port, maxConn, maxBuf, maxEvents int) {
		cfg := BindConfig{Host: host, Port: port, MaxConnections: maxConn, MaxBufferedBytes: maxBuf, MaxEvents: maxEvents}
		_ = ValidateBindConfig(cfg)
	})
}

func FuzzFixtureJSON(f *testing.F) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		var set SocketFixtureSet
		if len(raw) > 128*1024 {
			t.Skip()
		}
		_ = json.Unmarshal(raw, &set)
		_ = ValidateFixtureSet(set)
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateBindConfig(b *testing.B) {
	cfg := DefaultConfig()
	for i := 0; i < b.N; i++ {
		if err := ValidateBindConfig(cfg); err != nil {
			b.Fatal(err)
		}
	}
}
