// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localprotocoladapter

import (
	"encoding/json"
	"testing"
)

func TestValidateConfigRejectsForbiddenBehavior(t *testing.T) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	controls := []func(*LocalProtocolAdapterConfig){
		func(c *LocalProtocolAdapterConfig) { c.AllowOutboundDial = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowDNSResolution = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowPayloadForwarding = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowTargetPersistence = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowExactPortPersistence = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowCredentials = true },
		func(c *LocalProtocolAdapterConfig) { c.PayloadLoggingAllowed = true },
		func(c *LocalProtocolAdapterConfig) { c.MaxHeaderBytes = 0 },
	}
	for _, mutate := range controls {
		cfg := DefaultConfig()
		mutate(&cfg)
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("unsafe config accepted: %+v", cfg)
		}
	}
}

func TestConnectLikeParserRedactsAndRejectsControls(t *testing.T) {
	cfg := DefaultConfig()
	req, err := ParseConnectLike(cfg, "conn-1", "CONNECT synthetic-alpha:8080 KP/1")
	if err != nil {
		t.Fatal(err)
	}
	if req.TargetClass != TargetClassSyntheticName || req.TargetPortBucket != TargetPortBucketCommon || req.ExactTargetPersisted || req.OutboundDialUsed || req.DNSResolutionUsed || req.PayloadForwardingUsed {
		t.Fatalf("unsafe connect parse result: %+v", req)
	}
	for _, input := range []string{
		"GET synthetic-alpha:8080 KP/1",
		"CONNECT http://synthetic-alpha:8080 KP/1",
		"CONNECT synthetic-alpha:8080 KP/1\r\nHost: synthetic-alpha",
	} {
		if _, err := ParseConnectLike(cfg, "bad", input); err == nil {
			t.Fatalf("unsafe connect-like metadata accepted: %q", input)
		}
	}
}

func TestSocks5LikeParserRedactsAndRejectsUnsupported(t *testing.T) {
	cfg := DefaultConfig()
	req, err := ParseSocks5Like(cfg, "conn-2", []byte{0x05, 0x01, 0x00}, socksRequest("fixture-beta", 8443))
	if err != nil {
		t.Fatal(err)
	}
	if req.TargetClass != TargetClassSyntheticName || req.TargetPortBucket != TargetPortBucketCommon || req.CredentialsSeen || req.DNSResolutionUsed || req.OutboundDialUsed {
		t.Fatalf("unsafe socks5-like parse result: %+v", req)
	}
	if _, err := ParseSocks5Like(cfg, "auth", []byte{0x05, 0x01, 0x02}, socksRequest("fixture-beta", 8443)); err == nil {
		t.Fatal("username/password auth metadata accepted")
	}
	if _, err := ParseSocks5Like(cfg, "udp", []byte{0x05, 0x01, 0x00}, []byte{0x05, 0x03, 0x00, 0x03, 0x01, 'x', 0, 53}); err == nil {
		t.Fatal("UDP associate metadata accepted")
	}
}

func TestTargetRedactionAndStateMachine(t *testing.T) {
	cases := map[string]string{
		"synthetic-alpha": TargetClassSyntheticName,
		"fixture-name":    TargetClassSyntheticName,
		"203.0.113.10":    TargetClassRedactedIPv4Like,
		"2001:db8::1":     TargetClassRedactedIPv6Like,
		"127.0.0.1":       TargetClassLoopbackLocal,
	}
	for target, want := range cases {
		got, err := RedactTargetClass(target)
		if err != nil {
			t.Fatalf("target rejected: %s: %v", target, err)
		}
		if got != want {
			t.Fatalf("target class mismatch for %s: got %s want %s", target, got, want)
		}
	}
	if err := ValidateTransition(ParserStateCreated, ParserStateAwaitingInput); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTransition(ParserStateClosed, ParserStateMapped); err == nil {
		t.Fatal("invalid terminal transition accepted")
	}
}

func TestGenerateFixtureSetAndDrift(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || set.FixtureHash == "" || len(set.Requests) < 5 {
		t.Fatalf("invalid fixture set: %+v", set)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	mutated := set
	mutated.Requests[0].TargetClass = TargetClassRejectedUnsafe
	report := CompareFixtureSets(set, mutated)
	if report.Conclusion != "failed" {
		t.Fatalf("fixture drift not detected: %+v", report)
	}
}

func TestScanForLeakRejectsForbiddenMetadata(t *testing.T) {
	for _, tc := range []map[string]string{{"raw_payload": "x"}, {"dns_query": "x"}, {"credential": "x"}, {"destination_address": "x"}} {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe metadata accepted: %+v", tc)
		}
	}
}

func FuzzConnectLikeParser(f *testing.F) {
	f.Add("CONNECT synthetic-alpha:8080 KP/1")
	f.Add("GET synthetic-alpha:8080 KP/1")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		_, _ = ParseConnectLike(DefaultConfig(), "fuzz", input)
	})
}

func FuzzFixtureJSON(f *testing.F) {
	set, err := GenerateFixtureSet()
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 256*1024 {
			t.Skip()
		}
		var set LocalProtocolFixtureSet
		_ = json.Unmarshal(raw, &set)
		_ = ValidateFixtureSet(set)
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConnectLikeParser(b *testing.B) {
	cfg := DefaultConfig()
	for i := 0; i < b.N; i++ {
		if _, err := ParseConnectLike(cfg, "bench", "CONNECT synthetic-alpha:8080 KP/1"); err != nil {
			b.Fatal(err)
		}
	}
}
