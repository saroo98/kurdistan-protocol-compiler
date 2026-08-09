// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package sessionplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
)

func TestBuildV2UsesSignedDefaultsAndManualSelection(t *testing.T) {
	req := fixtureRequestV2(t)
	automatic, err := BuildV2(req)
	if err != nil {
		t.Fatal(err)
	}
	if automatic.Version != VersionV2 || automatic.StrategyID != "strategy.kurd-tls13-tcp" ||
		automatic.RelayKeyID != req.RuntimePolicy.RelayAuthKeyID || automatic.CarrierFamily != runtimepolicy.CarrierFamilyTLS13TCP ||
		automatic.ALPN != "kurd/1" || len(automatic.Endpoints) != 2 || automatic.Endpoints[0].Priority != 0 || automatic.Endpoints[1].Priority != 1 ||
		automatic.IPMode != runtimepolicy.IPModeIPv4Only || automatic.MTU != 1280 || automatic.MaxQueuePackets != 100 ||
		automatic.MaxIncompleteOps != 64 || automatic.MaxReconnectAttempts != 3 || automatic.DialTimeout != 5*time.Second ||
		automatic.IdleTimeout != 30*time.Second || automatic.Digest == ([32]byte{}) {
		t.Fatalf("unexpected default plan: %+v", automatic)
	}
	if err := ValidateV2(automatic); err != nil {
		t.Fatalf("built plan rejected: %v", err)
	}

	req.Requested.StrategyID = "strategy.kurd-tls13-tcp"
	manual, err := BuildV2(req)
	if err != nil {
		t.Fatal(err)
	}
	if manual.StrategyID != req.Requested.StrategyID || manual.Digest != automatic.Digest {
		t.Fatalf("equivalent manual selection changed authority: auto=%x manual=%x", automatic.Digest, manual.Digest)
	}
}

func TestBuildV2RejectsIncompleteOperationLimitAboveProcessCapacity(t *testing.T) {
	req := fixtureRequestV2(t)
	req.Requested.MaxIncompleteOps = 65
	if plan, err := BuildV2(req); err == nil || !reflect.DeepEqual(plan, PlanV2{}) {
		t.Fatalf("unsupported incomplete-operation limit accepted: plan=%+v err=%v", plan, err)
	}
}

func TestBuildV2PreservesSignedEndpointOrderAndDefensivelyClones(t *testing.T) {
	req := fixtureRequestV2(t)
	req.Requested.EndpointIndexes = []uint8{1}
	plan, err := BuildV2(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Endpoints) != 1 || plan.Endpoints[0].Priority != 1 {
		t.Fatalf("endpoint narrowing lost signed order: %+v", plan.Endpoints)
	}

	clone := plan.Clone()
	clone.Endpoints[0].Address[0] ^= 1
	clone.Routes[0].Address[0] ^= 1
	clone.PayloadProtocols[0] = runtimepolicy.PayloadProtocolICMP
	if bytes.Equal(plan.Endpoints[0].Address, clone.Endpoints[0].Address) ||
		bytes.Equal(plan.Routes[0].Address, clone.Routes[0].Address) ||
		plan.PayloadProtocols[0] == clone.PayloadProtocols[0] {
		t.Fatal("Clone exposed mutable plan slices")
	}

	req.Requested.EndpointIndexes[0] = 0
	req.RuntimePolicy.Endpoints[1].Address[0] ^= 1
	if plan.Endpoints[0].Priority != 1 || plan.Endpoints[0].Address[0] != 203 {
		t.Fatal("BuildV2 retained mutable request storage")
	}
}

func TestBuildV2AcceptsOnlyBoundedEffectiveNarrowing(t *testing.T) {
	req := fixtureRequestV2(t)
	req.Requested = NarrowingRequestV2{
		EndpointIndexes:      []uint8{1},
		IPMode:               runtimepolicy.IPModeIPv4Only,
		Routes:               []runtimepolicy.PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}},
		DNSServers:           [][]byte{{10, 77, 0, 1}},
		MTU:                  1280,
		PayloadProtocols:     []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolTCP},
		MaxQueuePackets:      4,
		MaxIncompleteOps:     2,
		MaxReconnectAttempts: 1,
	}
	plan, err := BuildV2(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Endpoints) != 1 || plan.Endpoints[0].Priority != 1 ||
		!reflect.DeepEqual(plan.PayloadProtocols, []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolTCP}) ||
		plan.MaxQueuePackets != 4 || plan.MaxIncompleteOps != 2 || plan.MaxReconnectAttempts != 1 {
		t.Fatalf("narrowing was not preserved: %+v", plan)
	}
}

func TestBuildV2AcceptsSignedDualStackTunnelAuthority(t *testing.T) {
	req := fixtureRequestV2(t)
	req.RuntimePolicy.ClientIPv6 = []byte{0xfd, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	req.RuntimePolicy.DNSIPv6 = []byte{0xfd, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	req.RuntimePolicy.Routes = append(req.RuntimePolicy.Routes, runtimepolicy.PrefixV2{Address: make([]byte, 16), PrefixLen: 0})
	req.RuntimePolicy.DNSServers = append(req.RuntimePolicy.DNSServers, bytes.Clone(req.RuntimePolicy.DNSIPv6))
	req.RuntimePolicy.AllowedIPModes = []runtimepolicy.IPModeV2{runtimepolicy.IPModeDualStack}
	var err error
	req.RuntimePolicy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestV2(req.RuntimePolicy)
	if err != nil {
		t.Fatal(err)
	}
	req.Profile.Policy, err = runtimepolicy.EncodeV2(req.RuntimePolicy)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildV2(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.IPMode != runtimepolicy.IPModeDualStack || len(plan.Routes) != 2 ||
		plan.ClientIPv4 == ([4]byte{}) || plan.DNSIPv4 == ([4]byte{}) ||
		plan.ClientIPv6 == ([16]byte{}) || plan.DNSIPv6 == ([16]byte{}) {
		t.Fatalf("dual-stack authority incomplete: %+v", plan)
	}
}

func TestBuildV2RejectsEveryAuthorityWidening(t *testing.T) {
	tests := map[string]func(*RequestV2){
		"receipt":      func(r *RequestV2) { r.ActivationReceipt.ContentID = "other" },
		"policy bytes": func(r *RequestV2) { r.Profile.Policy[0] ^= 1 },
		"strategy":     func(r *RequestV2) { r.Requested.StrategyID = "strategy.not-signed" },
		"unsupported signed strategy": func(r *RequestV2) {
			r.Profile.StrategyIDs = []string{"strategy.not-supported"}
			r.Requested.StrategyID = "strategy.not-supported"
		},
		"relay":              func(r *RequestV2) { r.Profile.RelayIDs = []string{"relay.0000000000000000"} },
		"endpoint duplicate": func(r *RequestV2) { r.Requested.EndpointIndexes = []uint8{0, 0} },
		"endpoint order":     func(r *RequestV2) { r.Requested.EndpointIndexes = []uint8{1, 0} },
		"endpoint outside fallback": func(r *RequestV2) {
			r.RuntimePolicy.Fallback.EndpointIndexes = []uint8{0}
			r.RuntimePolicy.Fallback.TotalAttempts = 1
			r.RuntimePolicy.RelayAdmissionDigest, _ = runtimepolicy.RelayAdmissionDigestV2(r.RuntimePolicy)
			r.Profile.Policy, _ = runtimepolicy.EncodeV2(r.RuntimePolicy)
			r.Requested.EndpointIndexes = []uint8{1}
		},
		"ip mode": func(r *RequestV2) { r.Requested.IPMode = runtimepolicy.IPModeIPv6Only },
		"route": func(r *RequestV2) {
			r.Requested.Routes = []runtimepolicy.PrefixV2{{Address: []byte{10, 0, 0, 0}, PrefixLen: 8}}
		},
		"dns": func(r *RequestV2) { r.Requested.DNSServers = [][]byte{{1, 1, 1, 1}} },
		"protocol": func(r *RequestV2) {
			r.Requested.PayloadProtocols = []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolICMP}
		},
		"mtu":        func(r *RequestV2) { r.Requested.MTU = 1500 },
		"lan":        func(r *RequestV2) { r.Requested.AllowLAN = true },
		"queue":      func(r *RequestV2) { r.Requested.MaxQueuePackets = 101 },
		"incomplete": func(r *RequestV2) { r.Requested.MaxIncompleteOps = 101 },
		"reconnect":  func(r *RequestV2) { r.Requested.MaxReconnectAttempts = 4 },
		"carrier": func(r *RequestV2) {
			r.RuntimePolicy.CarrierFamily = "other"
			r.Profile.Policy, _ = runtimepolicy.EncodeV2(r.RuntimePolicy)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := fixtureRequestV2(t)
			mutate(&req)
			if plan, err := BuildV2(req); err == nil || !reflect.DeepEqual(plan, PlanV2{}) {
				t.Fatalf("widening accepted: plan=%+v err=%v", plan, err)
			}
		})
	}
}

func TestPlanV2DigestBindsEveryEffectiveField(t *testing.T) {
	plan, err := BuildV2(fixtureRequestV2(t))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*PlanV2){
		"profile":    func(p *PlanV2) { p.ProfileContentID += "x" },
		"generation": func(p *PlanV2) { p.ProfileGeneration++ },
		"receipt":    func(p *PlanV2) { p.ActivationReceiptDigest[0] ^= 1 },
		"policy":     func(p *PlanV2) { p.RuntimePolicyDigest[0] ^= 1 },
		"program":    func(p *PlanV2) { p.LiveProgramDigest[0] ^= 1 },
		"strategy":   func(p *PlanV2) { p.StrategyID += "x" },
		"relay":      func(p *PlanV2) { p.RelayKeyID += "x" },
		"carrier":    func(p *PlanV2) { p.CarrierFamily += "x" },
		"alpn":       func(p *PlanV2) { p.ALPN += "x" },
		"endpoint":   func(p *PlanV2) { p.Endpoints[0].Port++ },
		"client4":    func(p *PlanV2) { p.ClientIPv4[0] ^= 1 },
		"dns4":       func(p *PlanV2) { p.DNSIPv4[0] ^= 1 },
		"client6":    func(p *PlanV2) { p.ClientIPv6[0] ^= 1 },
		"dns6":       func(p *PlanV2) { p.DNSIPv6[0] ^= 1 },
		"route":      func(p *PlanV2) { p.Routes[0].PrefixLen++ },
		"ip mode":    func(p *PlanV2) { p.IPMode = runtimepolicy.IPModeIPv6Only },
		"mtu":        func(p *PlanV2) { p.MTU++ },
		"protocol":   func(p *PlanV2) { p.PayloadProtocols[0] = runtimepolicy.PayloadProtocolICMP },
		"queue":      func(p *PlanV2) { p.MaxQueuePackets++ },
		"incomplete": func(p *PlanV2) { p.MaxIncompleteOps++ },
		"reconnect":  func(p *PlanV2) { p.MaxReconnectAttempts++ },
		"dial":       func(p *PlanV2) { p.DialTimeout++ },
		"idle":       func(p *PlanV2) { p.IdleTimeout++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := plan.Clone()
			mutate(&changed)
			if digestPlanV2(changed) == plan.Digest {
				t.Fatal("mutation did not change plan value")
			}
			if err := ValidateV2(changed); err == nil {
				t.Fatal("mutated plan passed validation")
			}
		})
	}
}

func TestPlanV1AuthorityAndDigestRemainFrozen(t *testing.T) {
	plan, err := Build(validRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.LoopbackOnly || plan.Digest == ([32]byte{}) {
		t.Fatalf("v1 authority changed: %+v", plan)
	}
	const frozen = "8652eadc7f2c8b2496d721ce0609cbc3091402e950cd035f111e795ec49c1d45"
	if got := hex.EncodeToString(plan.Digest[:]); got != frozen {
		t.Fatalf("v1 digest changed: got=%s want=%s", got, frozen)
	}
}

func fixtureRequestV2(t testing.TB) RequestV2 {
	t.Helper()
	policy := fixtureSessionPolicyV2(t)
	encoded, err := runtimepolicy.EncodeV2(policy)
	if err != nil {
		t.Fatal(err)
	}
	profile := envelope.CanonicalProfileV1{
		ContentID: "content.live.0001", ProfileID: "profiles.live.0001", LineageID: "lineage.live.0001", ProviderID: "provider.live.0001",
		ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation.live.0001", SnapshotMode: "full-snapshot", UpdateKind: "initial",
		Generation: 7, RequiredSafetyFloor: 1, ValidFrom: time.Now().Add(-time.Minute).Unix(), ValidUntil: time.Now().Add(time.Hour).Unix(),
		RootEpoch: 3, RevocationEpoch: 4, RelayIDs: []string{policy.RelayAuthKeyID}, StrategyIDs: []string{"strategy.kurd-tls13-tcp"}, Policy: encoded,
	}
	receipt := lifecycle.VerifiedReceipt{
		ContentID: profile.ContentID, ProviderID: profile.ProviderID, LineageID: profile.LineageID,
		AuthenticatedArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RootEpoch:                   profile.RootEpoch, RevocationEpoch: profile.RevocationEpoch, RecipientEpoch: 1,
	}
	return RequestV2{Profile: profile, ActivationReceipt: receipt, RuntimePolicy: policy}
}

func fixtureSessionPolicyV2(t testing.TB) runtimepolicy.PolicyV2 {
	t.Helper()
	legacy, err := compiler.Generate(73)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{
		Profile: legacy, ClientMandatoryFeatures: capabilities[:2], RelayMandatoryFeatures: capabilities[:2], SelectedFeatures: capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	programBytes, err := liveprogram.EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := fixtureSessionLeaf(t, "relay.example")
	policy := runtimepolicy.PolicyV2{
		SchemaVersion: runtimepolicy.SchemaVersionV2, WireProtocol: runtimepolicy.WireProtocolV1,
		CarrierFamily: runtimepolicy.CarrierFamilyTLS13TCP, LiveProgram: programBytes, LiveProgramSHA256: sha256.Sum256(programBytes),
		ClientAuthKeyID: sessionClientKeyID(clientPublic), RelayAuthKeyID: sessionRelayKeyID(relayPublic),
		TLSServerName: "relay.example", TLSLeafDER: leaf, TLSLeafSHA256: sha256.Sum256(leaf),
		Endpoints: []runtimepolicy.EndpointV2{
			{Priority: 0, Address: []byte{198, 51, 100, 10}, Family: 4, Port: 443},
			{Priority: 1, Address: []byte{203, 0, 113, 20}, Family: 4, Port: 443},
		},
		ClientIPv4: []byte{10, 77, 0, 2}, DNSIPv4: []byte{10, 77, 0, 1},
		Routes: []runtimepolicy.PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}}, DNSServers: [][]byte{{10, 77, 0, 1}}, MTU: 1280,
		AllowedIPModes:   []runtimepolicy.IPModeV2{runtimepolicy.IPModeIPv4Only},
		AllowedProtocols: []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolTCP, runtimepolicy.PayloadProtocolUDP},
		Limits:           runtimepolicy.LimitsV2{MaxPackets: 1_000, MaxQueuedPackets: 100, MaxFrames: 1_000, MaxMessages: 1_000, MaxIdleSeconds: 30, MaxReconnectAttempts: 3},
		Fallback:         runtimepolicy.FallbackV2{EndpointIndexes: []uint8{0, 1}, TotalAttempts: 3, AttemptTimeoutSeconds: 5, MaxBackoffSeconds: 10},
	}
	copy(policy.ClientAuthPublic[:], clientPublic)
	copy(policy.RelayAuthPublic[:], relayPublic)
	policy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestV2(policy)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func fixtureSessionLeaf(t testing.TB, serverName string) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func sessionClientKeyID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:16])
}

func sessionRelayKeyID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return "relay." + hex.EncodeToString(digest[:8])
}

func TestPlanV2ErrorCategoryIsStable(t *testing.T) {
	if !errors.Is(ErrInvalidV2, ErrInvalidV2) || reflect.TypeOf(ErrInvalidV2).Kind() != reflect.Ptr {
		t.Fatal("session-plan v2 error contract changed")
	}
}

func TestPlanV2RuntimePolicyProjectionIsValidatedClonedAndDestroyed(t *testing.T) {
	request := fixtureRequestV2(t)
	plan, err := BuildV2(request)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := plan.RuntimePolicyAt(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	policy.LiveProgram[0] ^= 1
	second, err := plan.RuntimePolicyAt(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(policy.LiveProgram, second.LiveProgram) {
		t.Fatal("runtime policy projection aliases retained plan authority")
	}
	plan.Destroy()
	if !reflect.DeepEqual(plan, PlanV2{}) {
		t.Fatalf("destroyed plan retained authority: %+v", plan)
	}
}
