// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimepolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/protocol/liveprogram"
)

func TestDecodeRuntimeTLSTimeDiagnosticPreservesFirstFailure(t *testing.T) {
	for _, version := range []uint64{2, 3} {
		p := fixturePolicyV2(t)
		if version == 3 {
			p = fixturePolicyV3(t, false)
		}
		leaf, err := x509.ParseCertificate(p.TLSLeafDER)
		if err != nil {
			t.Fatal(err)
		}
		goodNow := leaf.NotBefore.Add(time.Second)
		for _, name := range []string{"healthy", "zero", "expired", "earlier", "malformed", "later-signature", "later-hostname", "inclusive-end"} {
			t.Run(fmt.Sprintf("v%d/%s", version, name), func(t *testing.T) {
				value := p.Clone()
				now := leaf.NotAfter.Add(time.Second)
				want := RuntimeDiagnosticTLSValidityTime
				switch name {
				case "healthy":
					now = goodNow
					want = RuntimeDiagnosticNone
				case "zero":
					now = time.Time{}
					want = RuntimeDiagnosticNone
				case "earlier":
					value.WireProtocol = "invalid"
					want = RuntimeDiagnosticNone
				case "malformed":
					value.TLSLeafDER = []byte{0x30}
					value.TLSLeafSHA256 = sha256.Sum256(value.TLSLeafDER)
					want = RuntimeDiagnosticNone
				case "later-signature":
					value.TLSLeafDER[len(value.TLSLeafDER)-1] ^= 1
					value.TLSLeafSHA256 = sha256.Sum256(value.TLSLeafDER)
				case "later-hostname":
					value.TLSServerName = "other.example"
				case "inclusive-end":
					now = leaf.NotAfter
					want = RuntimeDiagnosticNone
				}
				var raw []byte
				if version == 3 {
					raw, err = marshalPolicyV3(value, true)
				} else {
					raw, err = marshal(policyMap(value, true))
				}
				if err != nil {
					t.Fatal(err)
				}
				_, legacyErr := DecodeRuntimeAt(raw, now)
				_, diagnostic, newErr := DecodeRuntimeAtWithDiagnostic(raw, now)
				if fmt.Sprint(legacyErr) != fmt.Sprint(newErr) || diagnostic != want {
					t.Fatalf("legacy=%v new=%v diagnostic=%v want=%v", legacyErr, newErr, diagnostic, want)
				}
				if name == "healthy" || name == "inclusive-end" {
					if newErr != nil {
						t.Fatal(newErr)
					}
				} else if newErr == nil {
					t.Fatal("invalid runtime admitted")
				}
			})
		}
	}
}

func fixturePolicyV3(t testing.TB, full bool) PolicyV2 {
	t.Helper()
	p := fixturePolicyV2(t)
	p.SchemaVersion = 3
	p.Services = &ServicesV1{Version: 1, Update: &UpdateV1{URL: "https://updates.example/profile.bin", ProfileID: "profile.0001", MaxArtifactBytes: envelope.MaxTotalInputBytes, TimeoutMillis: 1000, MinCheckIntervalSeconds: 60}}
	if full {
		p.Services.Proxy = &ProxyV1{AddressKinds: []uint8{1, 2}, DestinationCIDRs: []PrefixV2{{Address: []byte{0, 0, 0, 0}}}, DestinationPorts: []PortRangeV1{{First: 443, Last: 443}}, MaxConcurrentStreams: 1, MaxBufferBytes: 16777216, ConnectTimeoutMillis: 1000, IdleTimeoutSeconds: 30, MaxQueuedBytesPerDirection: 1024}
		p.Services.Probes = &ProbesV1{Targets: []ProbeTargetV1{{ID: 7, Address: []byte{1, 1, 1, 1}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 1, MaxOperationMillis: 1000}
	}
	var err error
	p.RelayAdmissionDigest, err = RelayAdmissionDigestV3(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestV3CanonicalRoundTripAndDispatch(t *testing.T) {
	for _, full := range []bool{false, true} {
		p := fixturePolicyV3(t, full)
		encoded, err := EncodeV3(p)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := rawMap(encoded, 26)
		if err != nil {
			t.Fatal(err)
		}
		services, err := rawMap(fields[26], 4)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []uint64{2, 3, 4} {
			var list []cbor.RawMessage
			if decode(services[key], &list) != nil || len(list) > 1 {
				t.Fatal("optional maps are not zero/one arrays")
			}
		}
		if !full && (!bytes.Equal(services[2], []byte{0x80}) || !bytes.Equal(services[3], []byte{0x80})) {
			t.Fatal("absent service not empty array")
		}
		for _, decoder := range []func([]byte, time.Time) (PolicyV2, error){DecodeV3At, DecodeRuntimeAt} {
			got, err := decoder(encoded, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			again, err := EncodeRuntimeAt(got, time.Now())
			if err != nil || !bytes.Equal(encoded, again) {
				t.Fatal("canonical roundtrip changed bytes", err)
			}
		}
		if _, err := DecodeV2(encoded); err == nil {
			t.Fatal("V2 decoded V3")
		}
		if err := ValidateV2(p); err == nil {
			t.Fatal("V2 validated V3")
		}
		for _, mutate := range []func(*PolicyV2){func(q *PolicyV2) { q.SchemaVersion = 2 }, func(q *PolicyV2) { q.Services = nil }, func(q *PolicyV2) { q.Services = &ServicesV1{Version: 1} }} {
			q := p.Clone()
			mutate(&q)
			if ValidateV3(q) == nil {
				t.Fatal("invalid schema/services accepted")
			}
		}
		projection := p.Clone()
		projection.SchemaVersion = 2
		if _, err := RelayAdmissionDigestV2(projection); err == nil {
			t.Fatal("V2 accepts Services")
		}
		projection.Services = nil
		projection.RelayAdmissionDigest, err = RelayAdmissionDigestV2(projection)
		if err != nil {
			t.Fatal(err)
		}
		v2, err := EncodeV2(projection)
		if err != nil {
			t.Fatal(err)
		}
		runtimeBytes, err := EncodeRuntimeAt(projection, time.Now())
		if err != nil || !bytes.Equal(v2, runtimeBytes) {
			t.Fatal("V2 dispatch changed bytes")
		}
		if _, err := DecodeV3(v2); err == nil {
			t.Fatal("V3 decoded V2")
		}
		if _, err := DecodeRuntimeAt(v2, time.Now()); err != nil {
			t.Fatal(err)
		}
		for _, version := range []uint64{0, 1, 4, 255} {
			q := p.Clone()
			q.SchemaVersion = version
			raw, _ := marshal(policyMap(q, true))
			if _, err := DecodeRuntimeAt(raw, time.Now()); err == nil {
				t.Fatal("unknown version decoded")
			}
			if _, err := EncodeRuntimeAt(q, time.Now()); err == nil {
				t.Fatal("unknown version encoded")
			}
			if ValidateRuntimeAt(q, time.Now()) == nil {
				t.Fatal("unknown version validated")
			}
			if _, err := RelayAdmissionDigestRuntimeAt(q, time.Now()); err == nil {
				t.Fatal("unknown version digested")
			}
		}
	}
}

func TestV3DigestAndEnvelopeBinding(t *testing.T) {
	p := fixturePolicyV3(t, true)
	encoded, err := EncodeV3(p)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := rawMap(encoded, 26)
	if err != nil {
		t.Fatal(err)
	}
	delete(fields, 25)
	preimage, err := marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(preimage) != p.RelayAdmissionDigest {
		t.Fatal("digest not canonical labels 1-24 and 26")
	}
	for _, mutate := range []func(*PolicyV2){func(p *PolicyV2) { p.Endpoints[0].Port++ }, func(p *PolicyV2) { p.Services.Proxy.MaxConcurrentStreams++ }, func(p *PolicyV2) { p.Services.Probes.Targets[0].Port++ }, func(p *PolicyV2) { p.Services.Update.URL = "https://updates.example/new.bin" }} {
		q := p.Clone()
		mutate(&q)
		if !IsCategory(ValidateV3(q), ErrorBinding) {
			t.Fatal("unsigned mutation accepted")
		}
		d, err := RelayAdmissionDigestRuntimeAt(q, time.Now())
		if err != nil || d == p.RelayAdmissionDigest {
			t.Fatal("mutation not in digest", err)
		}
	}
	profile := envelope.CanonicalProfileV1{ProfileID: "profile.0001", Policy: encoded}
	if ValidateRuntimeAgainstEnvelopeAt(p, profile, time.Now()) != nil {
		t.Fatal("valid envelope rejected")
	}
	profile.ProfileID = "profile.0002"
	if !IsCategory(ValidateRuntimeAgainstEnvelopeAt(p, profile, time.Now()), ErrorBinding) {
		t.Fatal("mismatched update profile accepted")
	}
	profile.ProfileID = "profile.0001"
	profile.Policy = bytes.Clone(encoded)
	profile.Policy[0] ^= 1
	if ValidateRuntimeAgainstEnvelopeAt(p, profile, time.Now()) == nil {
		t.Fatal("different signed bytes accepted")
	}
	if p.ValidateAgainstEnvelopeAt(envelope.CanonicalProfileV1{Policy: encoded}, time.Now()) == nil {
		t.Fatal("strict V2 envelope accepted V3")
	}
	if ValidateV3At(p, time.Time{}) == nil {
		t.Fatal("zero time accepted")
	}
}

func TestV3ProgramAcceptsServiceAndMTURange(t *testing.T) {
	for _, tc := range []struct {
		min, max int
		ok       bool
	}{{0, 1280, true}, {8, 1280, true}, {9, 1280, false}, {0, 271, false}, {0, 272, false}, {0, 1279, false}} {
		p := fixturePolicyV3(t, false)
		program, err := liveprogram.DecodeV1(p.LiveProgram)
		if err != nil {
			t.Fatal(err)
		}
		program.Messages[0].MinPayloadBytes = tc.min
		program.Messages[0].MaxPayloadBytes = tc.max
		p.LiveProgram, err = liveprogram.EncodeV1(program)
		if err != nil {
			t.Fatal(err)
		}
		p.LiveProgramSHA256 = sha256.Sum256(p.LiveProgram)
		_, err = RelayAdmissionDigestV3(p)
		if (err == nil) != tc.ok {
			t.Fatalf("range %d..%d: %v", tc.min, tc.max, err)
		}
	}
}

func TestV3StrictMalformedFields(t *testing.T) {
	p := fixturePolicyV3(t, true)
	encoded, err := EncodeV3(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"empty": nil, "oversized": make([]byte, MaxEncodedBytes+1), "duplicate": {0xa2, 1, 3, 1, 3}, "indefinite": {0xbf, 1, 3, 0xff}, "nonminimal": {0xa1, 0x18, 1, 3}, "trailing": append(bytes.Clone(encoded), 0)} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeV3(raw); err == nil {
				t.Fatal("malformed accepted")
			}
		})
	}
	for _, mutate := range []func(map[uint64]cbor.RawMessage){func(m map[uint64]cbor.RawMessage) { delete(m, 26) }, func(m map[uint64]cbor.RawMessage) { m[27] = []byte{0} }, func(m map[uint64]cbor.RawMessage) { m[26] = []byte{0xf6} }, func(m map[uint64]cbor.RawMessage) { m[1] = []byte{0xf6} }} {
		fields, _ := rawMap(encoded, 26)
		mutate(fields)
		raw, _ := marshal(fields)
		if _, err := DecodeV3(raw); err == nil {
			t.Fatal("bad fields accepted")
		}
	}
}

func TestV3CloneDoesNotAliasServiceAuthority(t *testing.T) {
	p := fixturePolicyV3(t, true)
	before, err := EncodeV3(p)
	if err != nil {
		t.Fatal(err)
	}
	q := p.Clone()
	q.Services.Version = 2
	q.Services.Proxy.AddressKinds[0] = 3
	q.Services.Proxy.DestinationCIDRs[0].Address[0] = 1
	q.Services.Proxy.DestinationCIDRs[0].PrefixLen = 1
	q.Services.Proxy.DestinationPorts[0].First = 1
	q.Services.Probes.Targets[0].Address[0] = 2
	q.Services.Probes.Targets[0].Methods[0] = 2
	q.Services.Probes.Targets[0].Modes[0] = 2
	q.Services.Probes.Targets[0].ID = 8
	q.Services.Update.URL = "changed"
	q.Services.Update.ProfileID = "changed"
	after, err := EncodeV3(p)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("clone aliases original authority", err)
	}
}

func TestV3RejectsNullWhereV2HistoricallyUsesNull(t *testing.T) {
	v2 := fixturePolicyV2(t)
	old, err := EncodeV2(v2)
	if err != nil {
		t.Fatal(err)
	}
	oldFields, _ := rawMap(old, 25)
	if !bytes.Equal(oldFields[16], []byte{0xf6}) || !bytes.Equal(oldFields[17], []byte{0xf6}) {
		t.Fatal("historical V2 absent-address encoding changed")
	}
	p := fixturePolicyV3(t, false)
	encoded, err := EncodeV3(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []uint64{16, 17} {
		fields, _ := rawMap(encoded, 26)
		if !bytes.Equal(fields[label], []byte{0x40}) {
			t.Fatal("V3 optional address is not empty bstr")
		}
		fields[label] = []byte{0xf6}
		raw, _ := marshal(fields)
		if _, err := DecodeV3(raw); err == nil {
			t.Fatal("V3 null address accepted")
		}
	}
}
