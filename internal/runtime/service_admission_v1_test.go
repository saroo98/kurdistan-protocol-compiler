// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
	"math/big"
	"net/netip"
	"reflect"
	"testing"
	"time"
	"unsafe"
)

var serviceTestNowV1 = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func TestServiceAdmissionRetainedCapacityAndDestroyV1(t *testing.T) {
	p := servicePolicyFixtureV1(t)
	a, err := NewServiceAdmissionV1(p, serviceTestNowV1)
	if err != nil {
		t.Fatal(err)
	}
	n := a.retainedBytesV1()
	t.Logf("admission actual=%d maximum=%d holder=%d", n, serviceAdmissionMaximumBytesV1(), unsafe.Sizeof(*a))
	if n != uint64(unsafe.Sizeof(*a))+productionBackingBytesV1(reflect.ValueOf(a.policy)) || n > serviceAdmissionMaximumBytesV1() {
		t.Fatal("retained descriptors/leaves/text unaccounted")
	}
	b, ok := sessionplan.AdmittedCalculationBoundsV2(65536)
	if !ok || serviceAdmissionMaximumBytesV1() > b.PolicyBytes {
		t.Fatal("retained formula exceeds dependency policy envelope")
	}
	leaf := a.policy.LiveProgram
	proxy := a.policy.Services.Proxy.AddressKinds
	a.Destroy()
	a.Destroy()
	if a.policy.Services != nil || !bytes.Equal(leaf, make([]byte, len(leaf))) || !bytes.Equal(proxy, make([]byte, len(proxy))) || p.LiveProgram[0] == 0 {
		t.Fatal("admission retirement did not retire only owned leaves")
	}
	// An over-capacity owned graph must not be mistaken for bounded occupancy.
	a.policy.LiveProgram = make([]byte, 1, serviceAdmissionMaximumBytesV1()+1)
	if a.retainedBytesV1() <= serviceAdmissionMaximumBytesV1() {
		t.Fatal("capacity counted as length")
	}
	a.Destroy()
}

func TestServiceAdmissionMaximumSourceShapeV1(t *testing.T) {
	// The admitted schema maxima need not coexist in one 8192-byte Services
	// encoding. This synthetic owned clone exercises their conservative sum.
	p := runtimepolicy.PolicyV2{LiveProgram: make([]byte, 49152), TLSLeafDER: make([]byte, 4096), Endpoints: make([]runtimepolicy.EndpointV2, 4), ClientIPv4: make([]byte, 4), DNSIPv4: make([]byte, 4), ClientIPv6: make([]byte, 16), DNSIPv6: make([]byte, 16), Routes: make([]runtimepolicy.PrefixV2, 2), DNSServers: make([][]byte, 2), AllowedIPModes: make([]runtimepolicy.IPModeV2, 3), AllowedProtocols: make([]runtimepolicy.PayloadProtocolV2, 4)}
	p.Fallback.EndpointIndexes = make([]uint8, 4)
	for j := range p.Endpoints {
		p.Endpoints[j].Address = make([]byte, 16)
	}
	for j := range p.Routes {
		p.Routes[j].Address = make([]byte, 16)
		p.DNSServers[j] = make([]byte, 16)
	}
	p.Services = &runtimepolicy.ServicesV1{Proxy: &runtimepolicy.ProxyV1{AddressKinds: make([]uint8, 3), DestinationCIDRs: make([]runtimepolicy.PrefixV2, 64), DestinationPorts: make([]runtimepolicy.PortRangeV1, 16)}, Probes: &runtimepolicy.ProbesV1{Targets: make([]runtimepolicy.ProbeTargetV1, 16)}, Update: &runtimepolicy.UpdateV1{URL: string(make([]byte, 65536))}}
	for j := range p.Services.Proxy.DestinationCIDRs {
		p.Services.Proxy.DestinationCIDRs[j].Address = make([]byte, 16)
	}
	for j := range p.Services.Probes.Targets {
		p.Services.Probes.Targets[j] = runtimepolicy.ProbeTargetV1{Address: make([]byte, 16), Methods: make([]uint8, 1), Modes: make([]uint8, 2)}
	}
	a := &ServiceAdmissionV1{policy: p.Clone()}
	defer a.Destroy()
	defer p.Destroy()
	if a.retainedBytesV1() > serviceAdmissionMaximumBytesV1() {
		t.Fatal("maximum admitted clone exceeds preallocation envelope")
	}
	withText := a.retainedBytesV1()
	a.policy.Services.Update.URL = ""
	if withText-a.retainedBytesV1() != 65536 {
		t.Fatal("retained immutable text uncharged")
	}
	absent := &ServiceAdmissionV1{}
	if absent.retainedBytesV1() != uint64(unsafe.Sizeof(*absent)) {
		t.Fatal("absent services charged decoder graph")
	}
	var raw *ServiceAdmissionV1
	if raw.retainedBytesV1() != 0 {
		t.Fatal("raw mode admission charged")
	}
}

func TestAdmitProbePolicyV1BoundedOwnershipAndLegacyParity(t *testing.T) {
	p := servicePolicyFixtureV1(t)
	legacy, err := NewServiceAdmissionV1(p, serviceTestNowV1)
	if err != nil {
		t.Fatal(err)
	}
	r := ProbeRequestV1{TargetID: 7, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 1000, Samples: 1}
	for _, request := range []ProbeRequestV1{r, {}, {TargetID: 7, Method: 2, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 1000, Samples: 1}} {
		old, oldErr := legacy.AdmitProbe(request, ProbeDisconnectedDefaultV1, 1)
		fresh, err := AdmitProbePolicyV1(p.Services.Probes, request, ProbeDisconnectedDefaultV1, 1)
		if oldErr != err || !bytes.Equal(old.Target().Address, fresh.Target().Address) {
			t.Fatalf("shared decision drift: %v %v", oldErr, err)
		}
		fresh.Destroy()
	}
	a, err := AdmitProbePolicyV1(p.Services.Probes, r, ProbeDisconnectedDefaultV1, 1)
	if err != nil {
		t.Fatal(err)
	}
	owned := a.target.Address
	a.Destroy()
	a.Destroy()
	if !bytes.Equal(owned, make([]byte, len(owned))) || len(a.Target().Address) != 0 || p.Services.Probes.Targets[0].Address[0] != 1 {
		t.Fatal("owned target cleanup touched source or retained authority")
	}
	p.Services.Probes.Targets[0].Address = make([]byte, 65536)
	if _, err := AdmitProbePolicyV1(p.Services.Probes, r, ProbeDisconnectedDefaultV1, 1); err != ServiceNotAdmittedV1 {
		t.Fatal("unbounded selected target was cloned")
	}
}

func servicePolicyFixtureV1(t testing.TB) runtimepolicy.PolicyV2 {
	t.Helper()
	legacy, err := compiler.Generate(71)
	if err != nil {
		t.Fatal(err)
	}
	caps := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: legacy, ClientMandatoryFeatures: caps[:2], RelayMandatoryFeatures: caps[:2], SelectedFeatures: caps})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := liveprogram.EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	client := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	relayPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	relay := relayPrivate.Public().(ed25519.PublicKey)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"relay.example"}, NotBefore: serviceTestNowV1.Add(-time.Hour), NotAfter: serviceTestNowV1.Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leaf, err := x509.CreateCertificate(rand.Reader, cert, cert, relay, relayPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ch := sha256.Sum256(client)
	rh := sha256.Sum256(relay)
	p := runtimepolicy.PolicyV2{SchemaVersion: 3, WireProtocol: "kurd-wire-v1", CarrierFamily: "tls13-tcp", LiveProgram: raw, LiveProgramSHA256: sha256.Sum256(raw), ClientAuthKeyID: hex.EncodeToString(ch[:16]), RelayAuthKeyID: "relay." + hex.EncodeToString(rh[:8]), ClientAuthPublic: [32]byte(client), RelayAuthPublic: [32]byte(relay), TLSServerName: "relay.example", TLSLeafDER: leaf, TLSLeafSHA256: sha256.Sum256(leaf), Endpoints: []runtimepolicy.EndpointV2{{Address: []byte{198, 51, 100, 10}, Family: 4, Port: 443}}, ClientIPv4: []byte{10, 77, 0, 2}, DNSIPv4: []byte{10, 77, 0, 1}, ClientIPv6: netip.MustParseAddr("2001:db8::2").AsSlice(), DNSIPv6: netip.MustParseAddr("2001:db8::1").AsSlice(), Routes: []runtimepolicy.PrefixV2{{Address: make([]byte, 4)}, {Address: make([]byte, 16)}}, DNSServers: [][]byte{{10, 77, 0, 1}, netip.MustParseAddr("2001:db8::1").AsSlice()}, MTU: 1280, AllowedIPModes: []runtimepolicy.IPModeV2{runtimepolicy.IPModeDualStack}, AllowedProtocols: []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolTCP, runtimepolicy.PayloadProtocolUDP}, Limits: runtimepolicy.LimitsV2{MaxPackets: 1000, MaxQueuedPackets: 100, MaxFrames: 1000, MaxMessages: 1000, MaxIdleSeconds: 30, MaxReconnectAttempts: 3}, Fallback: runtimepolicy.FallbackV2{EndpointIndexes: []uint8{0}, TotalAttempts: 3, AttemptTimeoutSeconds: 5, MaxBackoffSeconds: 10}, Services: &runtimepolicy.ServicesV1{Version: 1, Proxy: &runtimepolicy.ProxyV1{AddressKinds: []uint8{1, 2, 3}, DestinationCIDRs: []runtimepolicy.PrefixV2{{Address: make([]byte, 4)}, {Address: make([]byte, 16)}}, DestinationPorts: []runtimepolicy.PortRangeV1{{First: 443, Last: 443}}, MaxConcurrentStreams: 4, MaxBufferBytes: 16777216, ConnectTimeoutMillis: 1000, IdleTimeoutSeconds: 30, MaxQueuedBytesPerDirection: 1024}, Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 7, Address: []byte{1, 1, 1, 1}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 2000}}, MaxConcurrentOperations: 2, MaxSamplesPerOperation: 3, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 3, MaxOperationMillis: 10000}}}
	serviceSignPolicyV1(t, &p)
	return p
}
func serviceSignPolicyV1(t testing.TB, p *runtimepolicy.PolicyV2) {
	t.Helper()
	var err error
	p.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestV3At(*p, serviceTestNowV1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestServiceAdmissionProxyAuthorityAndOwnership(t *testing.T) {
	p := servicePolicyFixtureV1(t)
	a, err := NewServiceAdmissionV1(p, serviceTestNowV1)
	if err != nil {
		t.Fatal(err)
	}
	req := ProxyRequestV1{Kind: 2, Address: []byte("xn--bcher-kva.example"), Port: 443}
	got, err := a.AdmitProxy(req)
	if err != nil || string(got.Address) != "xn--bcher-kva.example" {
		t.Fatal("domain not preserved", err)
	}
	req.Address[0] = 'z'
	p.Services.Proxy.DestinationPorts[0].First = 444
	if string(got.Address) != "xn--bcher-kva.example" {
		t.Fatal("request alias")
	}
	if _, err := a.AdmitProxy(got); err != nil {
		t.Fatal("policy alias", err)
	}
	for _, q := range []ProxyRequestV1{{2, []byte("Example.com"), 443}, {2, []byte("example.com"), 80}, {1, []byte{127, 0, 0, 1}, 443}, {3, netip.MustParseAddr("::ffff:1.1.1.1").AsSlice(), 443}, {0, nil, 443}, {1, []byte{1, 1, 1, 1}, 0}} {
		if _, err := a.AdmitProxy(q); err == nil {
			t.Fatal("invalid request admitted")
		}
	}
	if _, err := NewServiceAdmissionV1(p, serviceTestNowV1); err == nil {
		t.Fatal("tampered authority")
	}
	p = servicePolicyFixtureV1(t)
	p.Services.Proxy.AddressKinds = []uint8{1}
	serviceSignPolicyV1(t, &p)
	a, _ = NewServiceAdmissionV1(p, serviceTestNowV1)
	if _, err := a.AdmitProxy(got); !errors.Is(err, ServiceNotAdmittedV1) {
		t.Fatal("unsigned kind", err)
	}
}

func TestServiceAdmissionDestinationFilteringAndBound(t *testing.T) {
	p := servicePolicyFixtureV1(t)
	a, _ := NewServiceAdmissionV1(p, serviceTestNowV1)
	req := ProxyRequestV1{2, []byte("example.com"), 443}
	var answers []netip.Addr
	for _, ip := range []string{"2606:4700::1111", "8.8.8.8", "127.0.0.1", "1.1.1.1", "8.8.8.8", "::ffff:1.1.1.1"} {
		answers = append(answers, netip.MustParseAddr(ip))
	}
	got, err := a.ProxyCandidates(req, answers)
	if err != nil || len(got) != 2 || got[0].String() != "1.1.1.1" || got[1].String() != "8.8.8.8" {
		t.Fatal("filter/order", got, err)
	}
	answers[0] = netip.Addr{}
	if got[0].String() != "1.1.1.1" {
		t.Fatal("answer alias")
	}
	for i := 1; i <= 17; i++ {
		answers = append(answers, netip.AddrFrom4([4]byte{9, 9, 9, byte(i)}))
	}
	if _, err := a.ProxyCandidates(req, answers); !errors.Is(err, ServiceDestinationDeniedV1) {
		t.Fatal("distinct answer bound", err)
	}
	if _, err := a.ProxyCandidates(req, []netip.Addr{netip.MustParseAddr("192.0.2.1")}); !errors.Is(err, ServiceDestinationDeniedV1) {
		t.Fatal("no safe result", err)
	}
	p.Services.Proxy.DestinationCIDRs = []runtimepolicy.PrefixV2{{Address: []byte{8, 8, 8, 0}, PrefixLen: 24}}
	serviceSignPolicyV1(t, &p)
	a, _ = NewServiceAdmissionV1(p, serviceTestNowV1)
	got, err = a.ProxyCandidates(req, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")})
	if err != nil || len(got) != 1 || got[0].String() != "8.8.8.8" {
		t.Fatal("signed CIDR", got, err)
	}
	if _, err := a.ProxyCandidates(ProxyRequestV1{1, []byte{8, 8, 8, 8}, 443}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}); err == nil {
		t.Fatal("numeric request redirected by answers")
	}
}

func TestServiceAdmissionProbeExactTargetModeAndNarrowing(t *testing.T) {
	p := servicePolicyFixtureV1(t)
	a, _ := NewServiceAdmissionV1(p, serviceTestNowV1)
	req := ProbeRequestV1{TargetID: 7, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 5000, Samples: 2}
	got, err := a.AdmitProbe(req, ProbeActiveRelayV1, 1)
	if err != nil || got.Target().Port != 443 || !bytes.Equal(got.Target().Address, []byte{1, 1, 1, 1}) {
		t.Fatal(err)
	}
	p.Services.Probes.Targets[0].Address[0] = 9
	target := got.Target()
	target.Address[0] = 8
	target.Methods[0] = 2
	target.Modes[0] = 2
	if got.Target().Address[0] != 1 || got.Target().Methods[0] != 1 || got.Target().Modes[0] != 1 {
		t.Fatal("authority alias")
	}
	for _, mutate := range []func(*ProbeRequestV1){func(r *ProbeRequestV1) { r.TargetID = 0 }, func(r *ProbeRequestV1) { r.TargetID = 8 }, func(r *ProbeRequestV1) { r.Method = 2 }, func(r *ProbeRequestV1) { r.Samples = 0 }, func(r *ProbeRequestV1) { r.Samples = 4 }, func(r *ProbeRequestV1) { r.AttemptTimeoutMillis = 999 }, func(r *ProbeRequestV1) { r.AttemptTimeoutMillis = 2001 }, func(r *ProbeRequestV1) { r.TotalTimeoutMillis = 10001 }, func(r *ProbeRequestV1) { r.TotalTimeoutMillis = 999 }} {
		r := req
		mutate(&r)
		if _, err := a.AdmitProbe(r, ProbeActiveRelayV1, 1); err == nil {
			t.Fatal("widening admitted")
		}
	}
	for _, c := range []uint8{0, 3, 5} {
		if _, err := a.AdmitProbe(req, ProbeActiveRelayV1, c); err == nil {
			t.Fatal("concurrency widening")
		}
	}
	if _, err := a.AdmitProbe(req, ProbeModeV1(0), 1); err == nil {
		t.Fatal("unknown mode")
	}
	p = servicePolicyFixtureV1(t)
	p.Services.Probes.Targets[0].Modes = []uint8{1}
	serviceSignPolicyV1(t, &p)
	a, _ = NewServiceAdmissionV1(p, serviceTestNowV1)
	if _, err := a.AdmitProbe(req, ProbeActiveRelayV1, 1); !errors.Is(err, ServiceNotAdmittedV1) {
		t.Fatal("mode authority", err)
	}
	if _, err := a.AdmitProbe(req, ProbeDisconnectedDefaultV1, 1); err != nil {
		t.Fatal(err)
	}
}

func TestServiceAdmissionFamilyDistinctBoundaryAndInvalidPolicy(t *testing.T) {
	p := servicePolicyFixtureV1(t)
	p.ClientIPv6 = nil
	p.DNSIPv6 = nil
	p.DNSServers = p.DNSServers[:1]
	p.Routes = p.Routes[:1]
	p.AllowedIPModes = []runtimepolicy.IPModeV2{runtimepolicy.IPModeIPv4Only}
	p.Services.Proxy.AddressKinds = []uint8{1, 2}
	p.Services.Proxy.DestinationCIDRs = p.Services.Proxy.DestinationCIDRs[:1]
	serviceSignPolicyV1(t, &p)
	a, err := NewServiceAdmissionV1(p, serviceTestNowV1)
	if err != nil {
		t.Fatal(err)
	}
	req := ProxyRequestV1{2, []byte("example.com"), 443}
	if _, err := a.ProxyCandidates(req, []netip.Addr{netip.MustParseAddr("2606:4700::1111")}); err == nil {
		t.Fatal("unsigned family")
	}
	answers := make([]netip.Addr, 0, 32)
	for i := 16; i >= 1; i-- {
		ip := netip.AddrFrom4([4]byte{8, 8, 8, byte(i)})
		answers = append(answers, ip, ip)
	}
	got, err := a.ProxyCandidates(req, answers)
	if err != nil || len(got) != 2 || got[0].String() != "8.8.8.1" || got[1].String() != "8.8.8.2" {
		t.Fatal("16 distinct plus duplicates", got, err)
	}
	got, err = a.ProxyCandidates(ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443}, nil)
	if err != nil || len(got) != 1 || got[0].String() != "1.1.1.1" {
		t.Fatal("numeric destination", got, err)
	}
	for _, mutate := range []func(*runtimepolicy.PolicyV2){func(p *runtimepolicy.PolicyV2) { p.Services = nil }, func(p *runtimepolicy.PolicyV2) { p.Services.Probes.Targets[0].Address = nil }, func(p *runtimepolicy.PolicyV2) { p.Services.Probes.Targets[0].Address = []byte{127, 0, 0, 1} }, func(p *runtimepolicy.PolicyV2) { p.Services.Probes.Targets[0].Modes = []uint8{3} }, func(p *runtimepolicy.PolicyV2) { p.Services.Proxy.DestinationCIDRs = nil }} {
		q := p.Clone()
		mutate(&q)
		if _, err := NewServiceAdmissionV1(q, serviceTestNowV1); err == nil {
			t.Fatal("invalid signed policy")
		}
	}
	if _, err := NewServiceAdmissionV1(p, serviceTestNowV1.Add(3*time.Hour)); err == nil {
		t.Fatal("expired policy")
	}
	var absent *ServiceAdmissionV1
	if _, err := absent.AdmitProxy(req); err == nil {
		t.Fatal("nil admission")
	}
	if _, err := absent.AdmitProbe(ProbeRequestV1{7, 1, 1000, 1000, 1}, ProbeActiveRelayV1, 1); err == nil {
		t.Fatal("nil probe admission")
	}
}
