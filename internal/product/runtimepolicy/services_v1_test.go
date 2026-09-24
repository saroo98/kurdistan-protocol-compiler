// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimepolicy

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"kurdistan/internal/product/envelope"
)

func TestPublicServiceAddressClass(t *testing.T) {
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "192.0.1.1", "198.17.255.255", "198.20.0.1", "2000::1", "2001:4860:4860::8888", "2606:4700::1111", "3fff::1"} {
		if !IsPublicServiceAddress(netip.MustParseAddr(ip)) {
			t.Errorf("public address rejected: %s", ip)
		}
	}
	for _, ip := range []string{"0.0.0.0", "0.255.255.255", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:1.1.1.1", "fc00::1", "fe80::1", "ff02::1", "2001::1", "2001:1ff::1", "2001:db8::1", "2002::1", "4000::1", "2606:4700::1111%eth0"} {
		if IsPublicServiceAddress(netip.MustParseAddr(ip)) {
			t.Errorf("unsafe address accepted: %s", ip)
		}
	}
	if IsPublicServiceAddress(netip.Addr{}) {
		t.Fatal("invalid address accepted")
	}
}

func TestCanonicalProxyDomains(t *testing.T) {
	for _, name := range []string{"example.com", "a", "xn--bcher-kva.example", strings.Repeat("a", 63) + ".example", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)} {
		if !IsCanonicalProxyDomain(name) {
			t.Errorf("canonical domain rejected: %q", name)
		}
	}
	for _, name := range []string{"", "Example.com", "example.com.", ".example", "a..b", "-a.example", "a-.example", "a_b.example", "a:443", "a@b", "https://a", "bücher.example", "a\x00b", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "b"} {
		if IsCanonicalProxyDomain(name) {
			t.Errorf("bad domain accepted: %q", name)
		}
	}
}

func TestCanonicalUpdateURLs(t *testing.T) {
	p := fixturePolicyV3(t, false)
	for _, url := range []string{"https://example.com/", "https://example.com/a-b_1.~x", "https://example.com:8443/a/b", "https://1.1.1.1/a", "https://[2606:4700::1111]/a", "https://xn--bcher-kva.example/a"} {
		q := p.Clone()
		q.Services.Update.URL = url
		if _, err := RelayAdmissionDigestV3(q); err != nil {
			t.Errorf("valid URL %q: %v", url, err)
		}
	}
	for _, url := range []string{"", "http://example.com/a", "HTTPS://example.com/a", "https://Example.com/a", "https://example.com./a", "https://user@example.com/a", "https://example.com/a?x=1", "https://example.com/a?", "https://example.com/a#x", "https://example.com/a#", "https://example.com", "https://example.com:443/a", "https://example.com:0444/a", "https://example.com:0/a", "https://example.com:65536/a", "https://example.com:/a", "https://example.com//a", "https://example.com/a/../b", "https://example.com/a/./b", "https://example.com/%61", "https://example.com/a\\b", "https://example.com/a b", "https://bücher.example/a", "https://%65xample.com/a", "https://127.0.0.1/a", "https://[::1]/a", "https://[2001:db8::1]/a", "https://[2606:4700:0:0:0:0:0:1111]/a", "https://[2606:4700::1111%25eth0]/a", "https://2606:4700::1111/a", "https://example.com/" + strings.Repeat("x", 2048)} {
		q := p.Clone()
		q.Services.Update.URL = url
		if _, err := RelayAdmissionDigestV3(q); err == nil {
			t.Errorf("bad URL accepted: %q", url)
		}
	}
}

func TestServiceLimitsAndAuthorityValidation(t *testing.T) {
	tests := map[string]func(*ServicesV1){
		"version":            func(s *ServicesV1) { s.Version = 2 },
		"empty":              func(s *ServicesV1) { s.Proxy = nil; s.Probes = nil; s.Update = nil },
		"kinds empty":        func(s *ServicesV1) { s.Proxy.AddressKinds = nil },
		"kinds duplicate":    func(s *ServicesV1) { s.Proxy.AddressKinds = []uint8{1, 1} },
		"kinds unsorted":     func(s *ServicesV1) { s.Proxy.AddressKinds = []uint8{2, 1} },
		"kinds unknown":      func(s *ServicesV1) { s.Proxy.AddressKinds = []uint8{4} },
		"kinds family":       func(s *ServicesV1) { s.Proxy.AddressKinds = []uint8{3} },
		"cidrs empty":        func(s *ServicesV1) { s.Proxy.DestinationCIDRs = nil },
		"cidrs excess":       func(s *ServicesV1) { s.Proxy.DestinationCIDRs = make([]PrefixV2, 65) },
		"cidrs malformed":    func(s *ServicesV1) { s.Proxy.DestinationCIDRs[0].Address = []byte{1} },
		"cidrs prefix bound": func(s *ServicesV1) { s.Proxy.DestinationCIDRs[0].PrefixLen = 33 },
		"cidrs unmasked": func(s *ServicesV1) {
			s.Proxy.DestinationCIDRs[0] = PrefixV2{Address: []byte{8, 8, 8, 8}, PrefixLen: 24}
		},
		"cidrs duplicate": func(s *ServicesV1) {
			s.Proxy.DestinationCIDRs = append(s.Proxy.DestinationCIDRs, s.Proxy.DestinationCIDRs[0])
		},
		"cidrs contained": func(s *ServicesV1) {
			s.Proxy.DestinationCIDRs = append(s.Proxy.DestinationCIDRs, PrefixV2{Address: []byte{8, 0, 0, 0}, PrefixLen: 8})
		},
		"cidrs unordered": func(s *ServicesV1) {
			s.Proxy.DestinationCIDRs = []PrefixV2{{Address: []byte{9, 0, 0, 0}, PrefixLen: 8}, {Address: []byte{8, 0, 0, 0}, PrefixLen: 8}}
		},
		"cidrs mapped": func(s *ServicesV1) {
			s.Proxy.DestinationCIDRs = []PrefixV2{{Address: netip.MustParseAddr("::ffff:8.8.8.8").AsSlice(), PrefixLen: 128}}
		},
		"cidrs family":   func(s *ServicesV1) { s.Proxy.DestinationCIDRs = []PrefixV2{{Address: make([]byte, 16)}} },
		"ports empty":    func(s *ServicesV1) { s.Proxy.DestinationPorts = nil },
		"ports excess":   func(s *ServicesV1) { s.Proxy.DestinationPorts = make([]PortRangeV1, 17) },
		"ports zero":     func(s *ServicesV1) { s.Proxy.DestinationPorts[0].First = 0 },
		"ports reversed": func(s *ServicesV1) { s.Proxy.DestinationPorts[0].First = 444 },
		"ports overlap": func(s *ServicesV1) {
			s.Proxy.DestinationPorts = append(s.Proxy.DestinationPorts, PortRangeV1{First: 443, Last: 444})
		},
		"ports adjacent": func(s *ServicesV1) {
			s.Proxy.DestinationPorts = append(s.Proxy.DestinationPorts, PortRangeV1{First: 444, Last: 445})
		},
		"streams zero":            func(s *ServicesV1) { s.Proxy.MaxConcurrentStreams = 0 },
		"streams excess":          func(s *ServicesV1) { s.Proxy.MaxConcurrentStreams = 65 },
		"buffer low":              func(s *ServicesV1) { s.Proxy.MaxBufferBytes = 16777215 },
		"buffer high":             func(s *ServicesV1) { s.Proxy.MaxBufferBytes = 134217729 },
		"connect low":             func(s *ServicesV1) { s.Proxy.ConnectTimeoutMillis = 999 },
		"connect high":            func(s *ServicesV1) { s.Proxy.ConnectTimeoutMillis = 30001 },
		"idle low":                func(s *ServicesV1) { s.Proxy.IdleTimeoutSeconds = 29 },
		"idle high":               func(s *ServicesV1) { s.Proxy.IdleTimeoutSeconds = 3601 },
		"queue low":               func(s *ServicesV1) { s.Proxy.MaxQueuedBytesPerDirection = 1023 },
		"queue high":              func(s *ServicesV1) { s.Proxy.MaxQueuedBytesPerDirection = 65537 },
		"targets empty":           func(s *ServicesV1) { s.Probes.Targets = nil },
		"targets excess":          func(s *ServicesV1) { s.Probes.Targets = make([]ProbeTargetV1, 17) },
		"targets duplicate":       func(s *ServicesV1) { s.Probes.Targets = append(s.Probes.Targets, s.Probes.Targets[0]) },
		"id zero":                 func(s *ServicesV1) { s.Probes.Targets[0].ID = 0 },
		"target unsafe":           func(s *ServicesV1) { s.Probes.Targets[0].Address = []byte{127, 0, 0, 1} },
		"target family":           func(s *ServicesV1) { s.Probes.Targets[0].Address = netip.MustParseAddr("2606:4700::1111").AsSlice() },
		"target port zero":        func(s *ServicesV1) { s.Probes.Targets[0].Port = 0 },
		"methods empty":           func(s *ServicesV1) { s.Probes.Targets[0].Methods = nil },
		"methods extra":           func(s *ServicesV1) { s.Probes.Targets[0].Methods = []uint8{1, 2} },
		"method unknown":          func(s *ServicesV1) { s.Probes.Targets[0].Methods = []uint8{2} },
		"modes empty":             func(s *ServicesV1) { s.Probes.Targets[0].Modes = nil },
		"modes duplicate":         func(s *ServicesV1) { s.Probes.Targets[0].Modes = []uint8{1, 1} },
		"modes reversed":          func(s *ServicesV1) { s.Probes.Targets[0].Modes = []uint8{2, 1} },
		"mode unknown":            func(s *ServicesV1) { s.Probes.Targets[0].Modes = []uint8{3} },
		"attempt low":             func(s *ServicesV1) { s.Probes.Targets[0].TimeoutMillis = 999 },
		"attempt above operation": func(s *ServicesV1) { s.Probes.Targets[0].TimeoutMillis = 1001 },
		"operations zero":         func(s *ServicesV1) { s.Probes.MaxConcurrentOperations = 0 },
		"operations high":         func(s *ServicesV1) { s.Probes.MaxConcurrentOperations = 5 },
		"samples zero":            func(s *ServicesV1) { s.Probes.MaxSamplesPerOperation = 0 },
		"samples high":            func(s *ServicesV1) { s.Probes.MaxSamplesPerOperation = 11 },
		"interval low":            func(s *ServicesV1) { s.Probes.MinAttemptIntervalMillis = 999 },
		"interval high":           func(s *ServicesV1) { s.Probes.MinAttemptIntervalMillis = 3600001 },
		"rate zero":               func(s *ServicesV1) { s.Probes.MaxAttemptsPerMinute = 0 },
		"rate high":               func(s *ServicesV1) { s.Probes.MaxAttemptsPerMinute = 61 },
		"operation low":           func(s *ServicesV1) { s.Probes.MaxOperationMillis = 999 },
		"operation high":          func(s *ServicesV1) { s.Probes.MaxOperationMillis = 30001 },
		"artifact zero":           func(s *ServicesV1) { s.Update.MaxArtifactBytes = 0 },
		"artifact high":           func(s *ServicesV1) { s.Update.MaxArtifactBytes = envelope.MaxTotalInputBytes + 1 },
		"update time low":         func(s *ServicesV1) { s.Update.TimeoutMillis = 999 },
		"update time high":        func(s *ServicesV1) { s.Update.TimeoutMillis = 30001 },
		"update interval low":     func(s *ServicesV1) { s.Update.MinCheckIntervalSeconds = 59 },
		"update interval high":    func(s *ServicesV1) { s.Update.MinCheckIntervalSeconds = 604801 },
		"profile empty":           func(s *ServicesV1) { s.Update.ProfileID = "" },
	}
	p := fixturePolicyV3(t, true)
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			q := p.Clone()
			mutate(q.Services)
			if _, err := RelayAdmissionDigestV3(q); err == nil {
				t.Fatal("invalid service accepted")
			}
		})
	}
	q := p.Clone()
	s := q.Services
	s.Proxy.MaxConcurrentStreams = 64
	s.Proxy.MaxBufferBytes = 134217728
	s.Proxy.ConnectTimeoutMillis = 30000
	s.Proxy.IdleTimeoutSeconds = 3600
	s.Proxy.MaxQueuedBytesPerDirection = 65536
	s.Proxy.DestinationPorts = []PortRangeV1{{First: 1, Last: 65535}}
	s.Probes.MaxConcurrentOperations = 4
	s.Probes.MaxSamplesPerOperation = 10
	s.Probes.MinAttemptIntervalMillis = 3600000
	s.Probes.MaxAttemptsPerMinute = 60
	s.Probes.MaxOperationMillis = 30000
	s.Probes.Targets[0].TimeoutMillis = 30000
	s.Probes.Targets[0].ID = 65535
	s.Probes.Targets[0].Port = 65535
	s.Update.TimeoutMillis = 30000
	s.Update.MinCheckIntervalSeconds = 604800
	if _, err := RelayAdmissionDigestV3(q); err != nil {
		t.Fatal("upper limits rejected", err)
	}
	q = p.Clone()
	q.Services.Proxy.DestinationCIDRs = []PrefixV2{{Address: []byte{8, 8, 8, 8}, PrefixLen: 32}}
	if _, err := RelayAdmissionDigestV3(q); err != nil {
		t.Fatal("independent probe/update authority constrained by proxy CIDRs", err)
	}
}

func TestServiceCBORExactShapes(t *testing.T) {
	p := fixturePolicyV3(t, true)
	encoded, err := EncodeV3(p)
	if err != nil {
		t.Fatal(err)
	}
	top, _ := rawMap(encoded, 26)
	s, _ := rawMap(top[26], 4)
	for _, tc := range []struct {
		label uint64
		count int
	}{{2, 8}, {3, 6}, {4, 5}} {
		var a []cbor.RawMessage
		if decode(s[tc.label], &a) != nil || len(a) != 1 {
			t.Fatal("service array shape")
		}
		if _, err := rawMap(a[0], tc.count); err != nil {
			t.Fatal(err)
		}
	}
	var proxy []cbor.RawMessage
	_ = decode(s[2], &proxy)
	fields, _ := rawMap(proxy[0], 8)
	if !bytes.Equal(fields[1], []byte{0x82, 1, 2}) {
		t.Fatal("kinds must be uint array, not byte string")
	}
	// Each recursive location gets missing, unknown, null, and mistyped members.
	for _, path := range [][]uint64{{}, {2}, {2, 2}, {2, 3}, {3}, {3, 1}, {4}} {
		for _, kind := range []string{"missing", "unknown", "null", "float", "negative", "boolean"} {
			t.Run(kind+strings.Repeat("/", len(path)), func(t *testing.T) {
				// Decode nested raw maps with concrete key types for precise mutation.
				var rewrite func([]byte, []uint64) []byte
				rewrite = func(raw []byte, rest []uint64) []byte {
					var m map[uint64]cbor.RawMessage
					_ = decode(raw, &m)
					if len(rest) > 0 {
						var a []cbor.RawMessage
						_ = decode(m[rest[0]], &a)
						a[0] = rewrite(a[0], rest[1:])
						m[rest[0]], _ = marshal(a)
					} else {
						switch kind {
						case "missing":
							delete(m, 1)
						case "unknown":
							m[99] = []byte{0}
						case "null":
							m[1] = []byte{0xf6}
						case "float":
							m[1] = []byte{0xf9, 0x3c, 0}
						case "negative":
							m[1] = []byte{0x20}
						case "boolean":
							m[1] = []byte{0xf5}
						}
					}
					out, _ := marshal(m)
					return out
				}
				f, _ := rawMap(encoded, 26)
				f[26] = rewrite(f[26], path)
				raw, _ := marshal(f)
				if _, err := DecodeV3(raw); err == nil {
					t.Fatal("malformed service map accepted")
				}
			})
		}
	}
	for _, bad := range [][]byte{{0xf6}, {0xa0}, {0x82, 0xa0, 0xa0}, {0x40}} {
		f, _ := rawMap(encoded, 26)
		ss, _ := rawMap(f[26], 4)
		ss[2] = bad
		f[26], _ = marshal(ss)
		raw, _ := marshal(f)
		if _, err := DecodeV3(raw); err == nil {
			t.Fatal("bad optional map accepted")
		}
	}
}

func TestServiceMaximumListsAndDualFamilyAuthority(t *testing.T) {
	p := fixturePolicyV3(t, true)
	p.ClientIPv6 = netip.MustParseAddr("2001:db8::2").AsSlice()
	p.DNSIPv6 = netip.MustParseAddr("2001:db8::1").AsSlice()
	p.DNSServers = append(p.DNSServers, bytes.Clone(p.DNSIPv6))
	p.Routes = append(p.Routes, PrefixV2{Address: make([]byte, 16)})
	p.AllowedIPModes = []IPModeV2{IPModeDualStack}
	p.Services.Proxy.AddressKinds = []uint8{1, 2, 3}
	p.Services.Proxy.DestinationCIDRs = nil
	for i := 0; i < 63; i++ {
		p.Services.Proxy.DestinationCIDRs = append(p.Services.Proxy.DestinationCIDRs, PrefixV2{Address: []byte{8, 8, 8, byte(i)}, PrefixLen: 32})
	}
	p.Services.Proxy.DestinationCIDRs = append(p.Services.Proxy.DestinationCIDRs, PrefixV2{Address: netip.MustParseAddr("2606:4700::1111").AsSlice(), PrefixLen: 128})
	p.Services.Proxy.DestinationPorts = nil
	p.Services.Probes.Targets = nil
	for i := uint16(1); i <= 16; i++ {
		p.Services.Proxy.DestinationPorts = append(p.Services.Proxy.DestinationPorts, PortRangeV1{First: i * 2, Last: i * 2})
		p.Services.Probes.Targets = append(p.Services.Probes.Targets, ProbeTargetV1{ID: i, Address: netip.MustParseAddr("2606:4700::1111").AsSlice(), Port: 443, Methods: []uint8{1}, Modes: []uint8{2}, TimeoutMillis: 1000})
	}
	var err error
	p.RelayAdmissionDigest, err = RelayAdmissionDigestV3(p)
	if err != nil {
		t.Fatal("maximum canonical lists rejected", err)
	}
	encoded, err := EncodeV3(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeV3(encoded); err != nil {
		t.Fatal(err)
	}
	// Reversing the family order must fail even when both families are allowed.
	q := p.Clone()
	q.Services.Proxy.DestinationCIDRs[0], q.Services.Proxy.DestinationCIDRs[63] = q.Services.Proxy.DestinationCIDRs[63], q.Services.Proxy.DestinationCIDRs[0]
	if _, err := RelayAdmissionDigestV3(q); err == nil {
		t.Fatal("IPv6-before-IPv4 order accepted")
	}
}

func TestEveryServiceFieldRejectsNullAndUnsignedOverflow(t *testing.T) {
	p := fixturePolicyV3(t, true)
	encoded, err := EncodeV3(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []struct {
		path  []uint64
		count int
	}{{nil, 4}, {[]uint64{2}, 8}, {[]uint64{2, 2}, 2}, {[]uint64{2, 3}, 2}, {[]uint64{3}, 6}, {[]uint64{3, 1}, 6}, {[]uint64{4}, 5}} {
		for label := uint64(1); label <= uint64(location.count); label++ {
			for _, bad := range [][]byte{{0xf6}, {0xf7}, {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
				var rewrite func([]byte, []uint64) []byte
				rewrite = func(raw []byte, path []uint64) []byte {
					var m map[uint64]cbor.RawMessage
					if err := decode(raw, &m); err != nil {
						t.Fatal(err)
					}
					if len(path) == 0 {
						m[label] = bad
					} else {
						var a []cbor.RawMessage
						if err := decode(m[path[0]], &a); err != nil {
							t.Fatal(err)
						}
						a[0] = rewrite(a[0], path[1:])
						m[path[0]], _ = marshal(a)
					}
					result, err := marshal(m)
					if err != nil {
						t.Fatal(err)
					}
					return result
				}
				top, _ := rawMap(encoded, 26)
				top[26] = rewrite(top[26], location.path)
				raw, _ := marshal(top)
				if _, err := DecodeV3(raw); err == nil {
					t.Fatalf("bad service member accepted at %v/%d", location.path, label)
				}
			}
		}
	}
}

func TestServiceSizeLimitAndNestedDuplicate(t *testing.T) {
	p := fixturePolicyV3(t, true)
	encoded, err := EncodeV3(p)
	if err != nil {
		t.Fatal(err)
	}
	top, _ := rawMap(encoded, 26)
	// A canonical service map can exceed its own allowance while the enclosing
	// policy still fits. It must be rejected before nested authority decoding.
	oversized, _ := marshal(map[uint64]any{1: uint64(1), 2: []any{}, 3: []any{}, 4: []any{map[uint64]any{1: strings.Repeat("x", 8192), 2: "profile.0001", 3: uint64(1), 4: uint64(1000), 5: uint64(60)}}})
	top[26] = oversized
	raw, _ := marshal(top)
	if len(raw) > MaxEncodedBytes {
		t.Fatal("fixture exceeded outer limit")
	}
	if _, err := DecodeV3(raw); !IsCategory(err, ErrorSize) {
		t.Fatal("service size limit not enforced", err)
	}
	top, _ = rawMap(encoded, 26)
	services, _ := rawMap(top[26], 4)
	// An optional proxy map with duplicate key 1, embedded as exact raw bytes.
	services[2] = []byte{0x81, 0xa2, 1, 0x81, 1, 1, 0x81, 1}
	top[26], _ = marshal(services)
	raw, _ = marshal(top)
	if _, err := DecodeV3(raw); err == nil {
		t.Fatal("nested duplicate key accepted")
	}
}

func TestServiceWireLabelsUseExactIndependentValues(t *testing.T) {
	p := fixturePolicyV3(t, true)
	s := p.Services
	s.Proxy.MaxConcurrentStreams = 5
	s.Proxy.MaxBufferBytes = 20971520
	s.Proxy.ConnectTimeoutMillis = 2200
	s.Proxy.IdleTimeoutSeconds = 80
	s.Proxy.MaxQueuedBytesPerDirection = 4096
	s.Probes.MaxConcurrentOperations = 2
	s.Probes.MaxSamplesPerOperation = 3
	s.Probes.MinAttemptIntervalMillis = 4444
	s.Probes.MaxAttemptsPerMinute = 5
	s.Probes.MaxOperationMillis = 6000
	s.Probes.Targets[0].TimeoutMillis = 1234
	s.Update.MaxArtifactBytes = 999
	s.Update.TimeoutMillis = 7777
	s.Update.MinCheckIntervalSeconds = 666
	want, err := marshal(map[uint64]any{
		1: uint64(1),
		2: []any{map[uint64]any{1: []uint64{1, 2}, 2: []any{map[uint64]any{1: []byte{0, 0, 0, 0}, 2: uint64(0)}}, 3: []any{map[uint64]any{1: uint64(443), 2: uint64(443)}}, 4: uint64(5), 5: uint64(20971520), 6: uint64(2200), 7: uint64(80), 8: uint64(4096)}},
		3: []any{map[uint64]any{1: []any{map[uint64]any{1: uint64(7), 2: []byte{1, 1, 1, 1}, 3: uint64(443), 4: []uint64{1}, 5: []uint64{1, 2}, 6: uint64(1234)}}, 2: uint64(2), 3: uint64(3), 4: uint64(4444), 5: uint64(5), 6: uint64(6000)}},
		4: []any{map[uint64]any{1: "https://updates.example/profile.bin", 2: "profile.0001", 3: uint64(999), 4: uint64(7777), 5: uint64(666)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.RelayAdmissionDigest, err = RelayAdmissionDigestV3(p)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeV3(p)
	if err != nil {
		t.Fatal(err)
	}
	top, _ := rawMap(encoded, 26)
	if !bytes.Equal(top[26], want) {
		t.Fatal("service wire label or type mismatch")
	}
	decoded, err := DecodeV3(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Services.Proxy.ConnectTimeoutMillis != 2200 || decoded.Services.Probes.MinAttemptIntervalMillis != 4444 || decoded.Services.Probes.Targets[0].TimeoutMillis != 1234 || decoded.Services.Update.MaxArtifactBytes != 999 {
		t.Fatal("decoded service labels changed authority")
	}
}
