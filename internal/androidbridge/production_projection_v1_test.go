// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
)

func productionAuthorityFixtureV1(t testing.TB, now time.Time, services *runtimepolicy.ServicesV1) sessionplan.RequestV2 {
	t.Helper()
	legacy, err := compiler.Generate(73)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: legacy, ClientMandatoryFeatures: capabilities[:2], RelayMandatoryFeatures: capabilities[:2], SelectedFeatures: capabilities})
	if err != nil {
		t.Fatal(err)
	}
	programBytes, err := liveprogram.EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	relayPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	clientPublic := clientPrivate.Public().(ed25519.PublicKey)
	relayPublic := relayPrivate.Public().(ed25519.PublicKey)
	leafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.example"}, DNSNames: []string{"relay.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leaf, err := x509.CreateCertificate(bytes.NewReader(bytes.Repeat([]byte{0x44}, 128)), template, template, leafKey.Public(), leafKey)
	if err != nil {
		t.Fatal(err)
	}
	clientDigest := sha256BytesV1(clientPublic)
	relayDigest := sha256BytesV1(relayPublic)
	policy := runtimepolicy.PolicyV2{
		SchemaVersion: runtimepolicy.SchemaVersionV2, WireProtocol: runtimepolicy.WireProtocolV1, CarrierFamily: runtimepolicy.CarrierFamilyTLS13TCP,
		LiveProgram: programBytes, LiveProgramSHA256: sha256.Sum256(programBytes), ClientAuthKeyID: hex.EncodeToString(clientDigest[:16]),
		RelayAuthKeyID: "relay." + hex.EncodeToString(relayDigest[:8]), TLSServerName: "relay.example", TLSLeafDER: leaf, TLSLeafSHA256: sha256.Sum256(leaf),
		Endpoints:  []runtimepolicy.EndpointV2{{Priority: 0, Address: []byte{198, 51, 100, 10}, Family: 4, Port: 443}, {Priority: 1, Address: []byte{203, 0, 113, 20}, Family: 4, Port: 443}},
		ClientIPv4: []byte{10, 77, 0, 2}, DNSIPv4: []byte{10, 77, 0, 1}, Routes: []runtimepolicy.PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}}, DNSServers: [][]byte{{10, 77, 0, 1}}, MTU: 1280,
		AllowedIPModes: []runtimepolicy.IPModeV2{runtimepolicy.IPModeIPv4Only}, AllowedProtocols: []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolTCP, runtimepolicy.PayloadProtocolUDP},
		Limits:   runtimepolicy.LimitsV2{MaxPackets: 1000, MaxQueuedPackets: 100, MaxFrames: 1000, MaxMessages: 1000, MaxIdleSeconds: 30, MaxReconnectAttempts: 3},
		Fallback: runtimepolicy.FallbackV2{EndpointIndexes: []uint8{0, 1}, TotalAttempts: 2, AttemptTimeoutSeconds: 5, MaxBackoffSeconds: 10}, Services: services,
	}
	copy(policy.ClientAuthPublic[:], clientPublic)
	copy(policy.RelayAuthPublic[:], relayPublic)
	if services != nil {
		policy.SchemaVersion = runtimepolicy.SchemaVersionV3
	}
	profile := envelope.CanonicalProfileV1{ContentID: "content.live.0001", ProfileID: "profile.0001", LineageID: "lineage.live.0001", ProviderID: "provider.live.0001", ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation.live.0001", SnapshotMode: "full-snapshot", UpdateKind: "initial", Generation: 7, RequiredSafetyFloor: 1, ValidFrom: now.Add(-time.Minute).Unix(), ValidUntil: now.Add(time.Hour).Unix(), RootEpoch: 3, RevocationEpoch: 4, RelayIDs: []string{policy.RelayAuthKeyID}, StrategyIDs: []string{"strategy.kurd-tls13-tcp"}}
	authority := sessionplan.RequestV2{Profile: profile, ActivationReceipt: lifecycle.VerifiedReceipt{ContentID: profile.ContentID, ProviderID: profile.ProviderID, LineageID: profile.LineageID, AuthenticatedArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RootEpoch: profile.RootEpoch, RevocationEpoch: profile.RevocationEpoch, RecipientEpoch: 1}, RuntimePolicy: policy}
	productionRebindAuthorityV1(t, &authority, now)
	return authority
}

func sha256BytesV1(value []byte) [32]byte { return sha256.Sum256(value) }

func TestProductionProjectionV1CustomDNSOwnerRetirementAndParity(t *testing.T) {
	borrowed := []byte{10, 77, 0, 1}
	rows := [][]byte{bytes.Clone(borrowed)}
	leaf := rows[0]
	retireProductionDNSRowsV1(rows)
	if rows[0] != nil || !bytes.Equal(leaf, make([]byte, 4)) || borrowed[0] != 10 {
		t.Fatal("owned DNS rows not retired or borrowed input changed")
	}
	now := time.Unix(1780000062, 0)
	authority := productionAuthorityFixtureV1(t, now, nil)
	before := authority.RuntimePolicy.Clone()
	settings := projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false))
	settings.dnsMode = 4
	settings.customPrimary = productionAddressV1{family: 4, value: [16]byte{10, 77, 0, 1}}
	admitted, status := projectProductionSettingsV1(settings, authority, now)
	if status != 0 {
		t.Fatal("matching custom DNS rejected", status)
	}
	admitted.Destroy()
	settings.customPrimary.value[0] = 11
	if _, status := projectProductionSettingsV1(settings, authority, now); status != productionDNSPolicyRejectedV1 {
		t.Fatal("DNS rejection changed", status)
	}
	if !reflect.DeepEqual(authority.RuntimePolicy, before) {
		t.Fatal("borrowed signed policy changed")
	}
}

func productionRebindAuthorityV1(t testing.TB, authority *sessionplan.RequestV2, now time.Time) {
	t.Helper()
	var digest [32]byte
	var encoded []byte
	var err error
	if authority.RuntimePolicy.SchemaVersion == runtimepolicy.SchemaVersionV3 {
		digest, err = runtimepolicy.RelayAdmissionDigestV3At(authority.RuntimePolicy, now)
		if err == nil {
			authority.RuntimePolicy.RelayAdmissionDigest = digest
			encoded, err = runtimepolicy.EncodeV3At(authority.RuntimePolicy, now)
		}
	} else {
		digest, err = runtimepolicy.RelayAdmissionDigestV2At(authority.RuntimePolicy, now)
		if err == nil {
			authority.RuntimePolicy.RelayAdmissionDigest = digest
			encoded, err = runtimepolicy.EncodeV2At(authority.RuntimePolicy, now)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	authority.Profile.Policy = encoded
}

func projectionSettingsFromRowsV1(t testing.TB, rows [][]byte) productionSettingsV1 {
	t.Helper()
	value, status := decodeProductionSettingsV1(productionSettingsMessageV1(rows))
	if status != productionSuccessV1 {
		t.Fatalf("settings decode: %d", status)
	}
	return value
}

func projectionTunnelRowV1(ip, dns uint8, primary productionAddressV1, resolver string, secondary productionAddressV1) []byte {
	row := []byte{ip, dns}
	row = appendSnapshotAddressV1(row, primary, true)
	row = append(row, 0x05, 0xdc, 1, 0)
	row = append(row, testProductionIDV1(resolver)...)
	row = appendSnapshotAddressV1(row, secondary, true)
	return row
}

func TestProductionProjectionV1BuildsV2FromSettingsOnlyAndPreservesSignedDigest(t *testing.T) {
	now := time.Unix(1800000000, 0)
	authority := productionAuthorityFixtureV1(t, now, nil)
	authority.Requested = sessionplan.NarrowingRequestV2{StrategyID: "forged", MTU: 65535, AllowLAN: true, MaxReconnectAttempts: 255}
	settings := projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false))
	projection, status := projectProductionSettingsV1(settings, authority, now)
	if status != productionSuccessV1 {
		t.Fatalf("projection: %d", status)
	}
	defer projection.Destroy()
	if projection.plan.StrategyID != "strategy.kurd-tls13-tcp" || projection.plan.IPMode != runtimepolicy.IPModeIPv4Only || projection.plan.MTU != 1280 || projection.effectiveMTU != 1280 || projection.plan.MaxReconnectAttempts != 3 || projection.effectiveAutomaticReconnectMax != 0 || projection.effectiveAggregateBufferBytes != 80<<20 || projection.rawFlowStatus != 1 || projection.effectiveTCPFlowMax != 256 || projection.effectiveUDPFlowMax != 128 || projection.effectiveFlowIdleMillis != 30000 || projection.fallbackAttemptMax != 2 {
		t.Fatalf("wrong V2 projection: %+v", projection)
	}
	retained, err := projection.plan.RuntimePolicyAt(now)
	if projection.plan.Digest == ([32]byte{}) || err != nil || retained.SchemaVersion != runtimepolicy.SchemaVersionV2 {
		t.Fatal("retained signed plan missing")
	}
	baselineDigest := projection.plan.Digest
	rows := productionSettingsRowsV1(false)
	rows[1][2], rows[1][6] = 1, 10
	rows[7] = []byte{0x0e, 0x10, 0x10, 0x00, 0, 0, 0, 40}
	rows[10] = []byte{0x2a, 0x38, 0x2a, 0x39, 16, 64, 0x0e, 0x10, 0, 128}
	changed, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, rows), authority, now)
	if status != productionSuccessV1 {
		t.Fatalf("local narrowing: %d", status)
	}
	defer changed.Destroy()
	if changed.plan.Digest != baselineDigest || changed.plan.MaxReconnectAttempts != 3 || changed.effectiveAutomaticReconnectMax != 3 || changed.effectiveAggregateBufferBytes != 40<<20 {
		t.Fatalf("local preferences rewrote signed plan: %+v", changed)
	}
	changed.Destroy()
	if !reflect.DeepEqual(changed, productionProjectionV1{}) {
		t.Fatalf("destroy retained projection references: %+v", changed)
	}
}

func TestProductionProjectionV1SelectionDNSFamilyAndRouteFailuresAreCategorical(t *testing.T) {
	now := time.Unix(1800000000, 0)
	authority := productionAuthorityFixtureV1(t, now, nil)
	tests := []struct {
		name   string
		mutate func([][]byte)
		status productionStatusV1
	}{
		{"manual-unknown", func(rows [][]byte) {
			rows[1] = append([]byte{3, 0, 0, 0, 0}, append(testProductionIDV1("strategy-other"), 3)...)
		}, productionNotAdmittedV1},
		{"manual-dotted", func(rows [][]byte) {
			rows[1] = append([]byte{3, 0, 0, 0, 0}, append(testProductionIDV1("strategy.kurd-tls13-tcp"), 3)...)
		}, productionInvalidRequestV1},
		{"preset", func(rows [][]byte) {
			rows[2] = projectionTunnelRowV1(2, 3, productionAddressV1{}, "resolver-1", productionAddressV1{})
		}, productionDNSPolicyRejectedV1},
		{"custom-missing", func(rows [][]byte) {
			rows[2] = projectionTunnelRowV1(2, 4, testSnapshotAddressV1(4, 1, 1, 1, 1), "", productionAddressV1{})
		}, productionDNSPolicyRejectedV1},
		{"custom-extra", func(rows [][]byte) {
			rows[2] = projectionTunnelRowV1(2, 4, testSnapshotAddressV1(4, 10, 77, 0, 1), "", testSnapshotAddressV1(6, 0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
		}, productionDNSPolicyRejectedV1},
		{"lan", func(rows [][]byte) { rows[1][3] = 1 }, productionPolicyRejectedV1},
		{"exclusion", func(rows [][]byte) {
			rows[3] = testProductionRoutingRowV1(1, nil, [][]byte{testProductionPrefixV1(4, []byte{10, 0, 0, 0}, 8)})
		}, productionPolicyRejectedV1},
		{"unsupported-v6", func(rows [][]byte) {
			rows[2] = projectionTunnelRowV1(3, 1, productionAddressV1{}, "", productionAddressV1{})
		}, productionPolicyRejectedV1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := productionSettingsRowsV1(false)
			test.mutate(rows)
			settings, decodeStatus := decodeProductionSettingsV1(productionSettingsMessageV1(rows))
			if decodeStatus != productionSuccessV1 {
				if test.status == productionInvalidRequestV1 {
					return
				}
				t.Fatalf("settings decode=%d", decodeStatus)
			}
			if _, status := projectProductionSettingsV1(settings, authority, now); status != test.status {
				t.Fatalf("status=%d want=%d", status, test.status)
			}
		})
	}
	customRows := productionSettingsRowsV1(false)
	customRows[2] = projectionTunnelRowV1(2, 4, testSnapshotAddressV1(4, 10, 77, 0, 1), "", productionAddressV1{})
	custom, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, customRows), authority, now)
	if status != productionSuccessV1 || custom.plan.DNSIPv4 != [4]byte{10, 77, 0, 1} || custom.request.customPrimary.family != 4 {
		t.Fatalf("exact custom DNS: %d %+v", status, custom)
	}
	custom.Destroy()

	dual := productionAuthorityFixtureV1(t, now, nil)
	dual.RuntimePolicy.ClientIPv6 = []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	dual.RuntimePolicy.DNSIPv6 = []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dual.RuntimePolicy.Routes = append(dual.RuntimePolicy.Routes, runtimepolicy.PrefixV2{Address: make([]byte, 16), PrefixLen: 0})
	dual.RuntimePolicy.DNSServers = append(dual.RuntimePolicy.DNSServers, append([]byte(nil), dual.RuntimePolicy.DNSIPv6...))
	dual.RuntimePolicy.AllowedIPModes = []runtimepolicy.IPModeV2{runtimepolicy.IPModeDualStack, runtimepolicy.IPModeIPv4Only, runtimepolicy.IPModeIPv6Only}
	productionRebindAuthorityV1(t, &dual, now)
	dualRows := productionSettingsRowsV1(false)
	dualRows[2] = projectionTunnelRowV1(4, 4, testSnapshotAddressV1(6, dual.RuntimePolicy.DNSIPv6...), "", testSnapshotAddressV1(4, dual.RuntimePolicy.DNSIPv4...))
	dualProjection, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, dualRows), dual, now)
	if status != productionSuccessV1 || dualProjection.request.customPrimary.family != 6 || dualProjection.request.customSecondary.family != 4 || dualProjection.plan.DNSIPv4 != [4]byte{10, 77, 0, 1} || dualProjection.plan.DNSIPv6[0] != 0xfd {
		t.Fatalf("dual DNS order/canonicalization: %d %+v", status, dualProjection)
	}
	dualProjection.Destroy()
}

func TestProductionProjectionV1ModesServicesAndLocalMinima(t *testing.T) {
	now := time.Unix(1800000000, 0)
	v2 := productionAuthorityFixtureV1(t, now, nil)
	proxyRows := productionSettingsRowsV1(false)
	proxyRows[9][0] = 2
	if _, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, proxyRows), v2, now); status != productionNotAdmittedV1 {
		t.Fatalf("V2 proxy status=%d", status)
	}

	services := &runtimepolicy.ServicesV1{Version: 1, Proxy: &runtimepolicy.ProxyV1{AddressKinds: []uint8{1, 2}, DestinationCIDRs: []runtimepolicy.PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}}, DestinationPorts: []runtimepolicy.PortRangeV1{{First: 443, Last: 443}}, MaxConcurrentStreams: 8, MaxBufferBytes: 24 << 20, ConnectTimeoutMillis: 5000, IdleTimeoutSeconds: 120, MaxQueuedBytesPerDirection: 32768}, Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 7, Address: []byte{1, 1, 1, 1}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 2, MaxSamplesPerOperation: 3, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 4, MaxOperationMillis: 5000}, Update: &runtimepolicy.UpdateV1{URL: "https://updates.example/profile.bin", ProfileID: "profile.0001", MaxArtifactBytes: 1 << 20, TimeoutMillis: 5000, MinCheckIntervalSeconds: 60}}
	v3 := productionAuthorityFixtureV1(t, now, services)
	proxyRows[10] = []byte{0x2a, 0x38, 0x2a, 0x39, 16, 64, 0x0e, 0x10, 0, 32}
	projection, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, proxyRows), v3, now)
	if status != productionSuccessV1 {
		t.Fatalf("V3 proxy projection=%d", status)
	}
	defer projection.Destroy()
	if projection.effectiveMode != 2 || projection.effectiveStreamMax != 8 || projection.effectiveClientMax != 16 || projection.effectiveProxyIdleSeconds != 120 || projection.effectiveProxyBufferBytes != 24<<20 || projection.perDirectionQueueBytes != 32768 || projection.streamChunkMax == 0 || projection.effectiveAggregateBufferBytes != 80<<20 {
		t.Fatalf("proxy minima: %+v", projection)
	}

	proxyOnlyRows := productionSettingsRowsV1(false)
	proxyOnlyRows[9][0] = 3
	proxyOnlyRows[7] = []byte{0, 30, 0, 16, 0, 0, 0, 0}
	proxyOnly, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, proxyOnlyRows), v3, now)
	if status != productionSuccessV1 || proxyOnly.rawFlowStatus != 2 || proxyOnly.effectiveTCPFlowMax != 0 || proxyOnly.effectiveUDPFlowMax != 0 || proxyOnly.effectiveFlowIdleMillis != 0 || proxyOnly.effectiveSessionIdleMillis != 30000 || proxyOnly.effectiveAggregateBufferBytes != 80<<20 {
		t.Fatalf("proxy-only: %d %+v", status, proxyOnly)
	}
	proxyOnly.Destroy()

	missing := &runtimepolicy.ServicesV1{Version: 1, Update: services.Update}
	v3Missing := productionAuthorityFixtureV1(t, now, missing)
	if _, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, proxyRows), v3Missing, now); status != productionNotAdmittedV1 {
		t.Fatalf("missing proxy service=%d", status)
	}
	inertRows := productionSettingsRowsV1(false)
	inertRows[5] = append([]byte{5, 2}, append(testProductionIDV1("probe-65535"), 30)...)
	if projection, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, inertRows), v3Missing, now); status != productionSuccessV1 {
		t.Fatalf("inert probe rejected TUN: %d", status)
	} else {
		projection.Destroy()
	}

	shortIdle := productionAuthorityFixtureV1(t, now, nil)
	shortIdle.RuntimePolicy.Limits.MaxIdleSeconds = 20
	productionRebindAuthorityV1(t, &shortIdle, now)
	maximumRows := productionSettingsRowsV1(false)
	maximumRows[7] = []byte{0x0e, 0x10, 0x10, 0x00, 0, 0, 0x02, 0x00}
	maximum, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, maximumRows), shortIdle, now)
	if status != productionSuccessV1 || maximum.signedIdleTimeoutMillis != 20000 || maximum.effectiveSessionIdleMillis != 20000 || maximum.effectiveFlowIdleMillis != 20000 || maximum.effectiveTCPFlowMax != 4096 || maximum.effectiveUDPFlowMax != 0 || maximum.effectiveAggregateBufferBytes != 128<<20 {
		t.Fatalf("signed idle and native maxima: %d %+v", status, maximum)
	}
	maximum.Destroy()
}

func TestProductionProjectionV1AuthorityTimeAndSyntaxRemainDistinct(t *testing.T) {
	now := time.Unix(1800000000, 0)
	authority := productionAuthorityFixtureV1(t, now, nil)
	settings := projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false))
	if _, status := projectProductionSettingsV1(settings, authority, time.Time{}); status != productionTrustUnavailableV1 {
		t.Fatalf("zero time=%d", status)
	}
	if _, status := projectProductionSettingsV1(settings, authority, time.Unix(authority.Profile.ValidUntil, 0)); status != productionAuthorityExpiredV1 {
		t.Fatalf("expired=%d", status)
	}
	authority.ActivationReceipt.ContentID = "wrong"
	if _, status := projectProductionSettingsV1(settings, authority, now); status != productionInvalidRequestV1 {
		t.Fatalf("malformed authority=%d", status)
	}
}
