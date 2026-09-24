//go:build phase18productiontest && (android || linux)

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"io"
	"math"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/profilehpke"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
	"kurdistan/internal/protocol/wirev1"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/transport/tlstcp"
)

type productionFixturePlatformV1 struct {
	mu         sync.Mutex
	input      androidbridge.MaintenanceCurrentInputV1
	expected   *androidbridge.ProductionCurrentExpectationV1
	closed     bool
	invalidate func() androidbridge.ErrorCode
}

func (p *productionFixturePlatformV1) RegisterProductionCurrentV1(epoch uint64, e *androidbridge.ProductionCurrentExpectationV1, invalidate func() androidbridge.ErrorCode) (androidbridge.MaintenanceRevisionRegistrationV1, androidbridge.ErrorCode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if epoch == 0 || p.closed || !e.MatchesV1(p.input) {
		return nil, androidbridge.CodeStateCorrupt
	}
	p.expected = e
	p.invalidate = invalidate
	return p, androidbridge.CodeOK
}
func (p *productionFixturePlatformV1) Revalidate(ctx context.Context) androidbridge.MaintenanceResultV1 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil {
		return androidbridge.MaintenanceCancelled
	}
	if p.closed || !p.expected.MatchesV1(p.input) {
		return androidbridge.MaintenanceInvalidState
	}
	return androidbridge.MaintenanceSuccess
}
func (p *productionFixturePlatformV1) AcquirePublication(ctx context.Context) (androidbridge.MaintenancePublicationLeaseV1, androidbridge.MaintenanceResultV1) {
	return productionFixtureLeaseV1{p}, p.Revalidate(ctx)
}
func (p *productionFixturePlatformV1) Close() androidbridge.ErrorCode {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return androidbridge.CodeOK
}

type productionFixtureLeaseV1 struct{ p *productionFixturePlatformV1 }

func (l productionFixtureLeaseV1) IsCurrent() bool {
	return l.p.Revalidate(context.Background()) == androidbridge.MaintenanceSuccess
}
func (l productionFixtureLeaseV1) Close() androidbridge.ErrorCode { return androidbridge.CodeOK }

func productionFixtureSettingsV1() []byte {
	rows := [][]byte{{1, 0, 0}, {1, 0, 0, 0, 0, 0, 3}, {1, 1, 0, 0x05, 0xdc, 0, 0, 0, 0}, {1, 0, 0, 0}, {0, 0, 2, 0, 1, 0}, {1, 1, 0, 3}, {3, 3},
		{0x01, 0x2c, 0x01, 0, 0, 0x80, 0, 0x50}, {0, 0, 0}, {1, 2, 1}, {0x2a, 0x38, 0x2a, 0x39, 4, 16, 0x01, 0x2c, 0, 32}, {0, 30, 0, 1}, {0, 1}, {0}, {0, 0, 0}}
	out := make([]byte, 12)
	copy(out, "KPS1")
	out[4] = 1
	for _, row := range rows {
		out = append(out, row...)
	}
	binary.BigEndian.PutUint32(out[8:12], uint32(len(out)))
	return out
}

func productionSignedNetworkFixtureV1(t *testing.T, raw bool, cleanupStatus ...int32) (*androidbridge.ProductionAttemptAdmissionV1, *productionFixturePlatformV1, net.Listener, *selfhost.RelayRuntimeSnapshotV1, time.Time) {
	return productionSignedNetworkServicesFixtureV1(t, raw, false, cleanupStatus...)
}
func productionSignedNetworkServicesFixtureV1(t *testing.T, raw, proxy bool, cleanupStatus ...int32) (*androidbridge.ProductionAttemptAdmissionV1, *productionFixturePlatformV1, net.Listener, *selfhost.RelayRuntimeSnapshotV1, time.Time) {
	return productionSignedNetworkEndpointsFixtureV1(t, raw, proxy, "", cleanupStatus...)
}
func productionSignedNetworkEndpointsFixtureV1(t *testing.T, raw, proxy bool, second string, cleanupStatus ...int32) (*androidbridge.ProductionAttemptAdmissionV1, *productionFixturePlatformV1, net.Listener, *selfhost.RelayRuntimeSnapshotV1, time.Time) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	base := t.TempDir()
	dir, recovery := filepath.Join(base, "node"), filepath.Join(base, "recovery")
	pass := []byte("synthetic local recovery only")
	_, err = selfhost.Initialize(selfhost.InitOptions{DataDir: dir, DeploymentName: "production-transport-fixture", Endpoint: listener.Addr().String(), RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(-2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err = selfhost.ConfirmRecovery(dir, recovery, pass, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	model, err := compiler.Generate(71)
	if err != nil {
		t.Fatal(err)
	}
	features := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: model, ClientMandatoryFeatures: features[:2], RelayMandatoryFeatures: features[:2], SelectedFeatures: features})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := liveprogram.EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, 24*time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestWire, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	privateWire, err := enrollment.EncodePrivateBundleV1(private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(privateWire); clear(private.RecipientPrivate); clear(private.ClientAuthSeed) })
	var services *runtimepolicy.ServicesV1
	if !raw {
		services = &runtimepolicy.ServicesV1{Version: 1, Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 10, MaxOperationMillis: 30000}}
		if proxy {
			services.Proxy = &runtimepolicy.ProxyV1{AddressKinds: []uint8{1}, DestinationCIDRs: []runtimepolicy.PrefixV2{{Address: []byte{8, 8, 8, 8}, PrefixLen: 32}}, DestinationPorts: []runtimepolicy.PortRangeV1{{First: 443, Last: 443}}, MaxConcurrentStreams: 4, MaxBufferBytes: 64 << 20, ConnectTimeoutMillis: 1000, IdleTimeoutSeconds: 30, MaxQueuedBytesPerDirection: 32768}
		}
	}
	issued, err := selfhost.CreateProfile(dir, selfhost.CreateProfileOptions{Name: "local-device", ValidFor: 12 * time.Hour, Now: now, RecipientRequest: requestWire, LiveProgram: wire, RegistryDir: filepath.Join(base, "registry"), Services: services})
	if err != nil {
		t.Fatal(err)
	}
	if second != "" {
		issued.Artifact = productionSignTwoEndpointsFixtureV1(t, dir, issued.Artifact, second, now, request, private)
	}
	activation, err := selfhost.NewAndroidLiveActivationSessionForRecipient(issued.Artifact, now, lifecycle.VerifiedState{}, request, private)
	if err != nil {
		t.Fatal(err)
	}
	defer activation.Destroy()
	var staged profile.ActivationRecord
	for {
		command, ok := activation.Next()
		if !ok {
			break
		}
		result := profile.ActivationCommandResult{}
		if command.Kind == profile.ActivationCommandStageCandidate {
			staged = command.Record
		}
		if command.Kind == profile.ActivationCommandReopenCandidate {
			result.Record = staged
		}
		if err = activation.Submit(command, result); err != nil {
			t.Fatal(err)
		}
	}
	record, err := activation.Result()
	if err != nil {
		t.Fatal(err)
	}
	recordWire, err := androidbridge.EncodeActivationRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	verifyWire, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{Ingress: envelope.IngressFile, Class: envelope.ArtifactDeviceRecipient, Parts: [][]byte{issued.Artifact}})
	if err != nil {
		t.Fatal(err)
	}
	input := androidbridge.MaintenanceCurrentInputV1{VerifyRequest: verifyWire, ActivationRecord: recordWire, RecipientRequest: requestWire, RecipientPrivate: privateWire}
	platform := &productionFixturePlatformV1{input: input}
	attempt, cleanup, s := androidbridge.NewProductionAttemptFixtureV1(input, productionFixtureSettingsV1(), selfHostedBridgeEnvironment{}, platform, now)
	if s != 0 {
		t.Fatal("genuine admission", s)
	}
	t.Cleanup(func() {
		want := int32(0)
		if len(cleanupStatus) == 1 {
			want = cleanupStatus[0]
		}
		if s := cleanup(); s != want {
			t.Error("joined fixture cleanup", s)
		}
	})
	snapshot, err := selfhost.OpenRelayRuntimeSnapshotV1(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(snapshot.Close)
	return attempt, platform, listener, snapshot, now
}

// Test-only issuance from this fixture's synthetic authority, before activation
// or admission. The relay still independently loads and reconstructs its plan.
func productionSignTwoEndpointsFixtureV1(t *testing.T, dir string, artifact []byte, second string, now time.Time, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1) []byte {
	t.Helper()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	mode, e := cbor.CoreDetEncOptions().EncMode()
	check(e)
	encode := func(v any) cbor.RawMessage { b, e := mode.Marshal(v); check(e); return b }
	decode := func(b []byte, v any) { check(cbor.Unmarshal(b, v)) }
	read := func(name string) []byte { b, e := os.ReadFile(filepath.Join(dir, name)); check(e); return b }
	master := read("master.key")
	defer clear(master)
	var outer, state, bundle []cbor.RawMessage
	decode(read("state.kurd-state"), &outer)
	var payload []byte
	decode(outer[1], &payload)
	defer clear(payload)
	decode(payload, &state)
	decode(artifact, &bundle)
	if len(state) != 35 || len(bundle) != 14 {
		t.Fatal("fixture state layout", len(state), len(bundle))
	}
	var issuer profile.KeyReference
	decode(state[12], &issuer)
	var deployment string
	decode(state[6], &deployment)
	var sealed []cbor.RawMessage
	decode(state[14], &sealed)
	var nonce, ciphertext []byte
	decode(sealed[1], &nonce)
	decode(sealed[2], &ciphertext)
	block, e := aes.NewCipher(master)
	check(e)
	aead, e := cipher.NewGCM(block)
	check(e)
	der, e := aead.Open(nil, nonce, ciphertext, []byte(deployment+"|"+issuer.KeyID))
	check(e)
	defer clear(der)
	key, e := x509.ParseECPrivateKey(der)
	check(e)
	_, verified, e := selfhost.VerifyLiveBundleForRecipient(artifact, now, 1, request, private)
	check(e)
	policy, e := runtimepolicy.DecodeRuntimeAt(verified.Profile.Policy, now)
	check(e)
	endpoint, e := netip.ParseAddrPort(second)
	check(e)
	policy.Endpoints = append(policy.Endpoints, runtimepolicy.EndpointV2{Priority: 1, Family: 4, Address: endpoint.Addr().AsSlice(), Port: endpoint.Port()})
	policy.Fallback.EndpointIndexes = []uint8{0, 1}
	policy.RelayAdmissionDigest, e = runtimepolicy.RelayAdmissionDigestRuntimeAt(policy, now)
	check(e)
	policyBytes, e := runtimepolicy.EncodeRuntimeAt(policy, now)
	check(e)
	verified.Profile.Policy = policyBytes
	var delegation profile.IssuerDelegationArtifact
	decode(bundle[7], &delegation)
	var records []cbor.RawMessage
	decode(state[30], &records)
	if len(records) != 1 {
		t.Fatal("fixture profile count", len(records))
	}
	var record, bindingFields []cbor.RawMessage
	decode(records[0], &record)
	decode(record[9], &bindingFields)
	var binding profile.RecipientBinding
	decode(bindingFields[0], &binding.Class)
	decode(bindingFields[1], &binding.ProviderID)
	decode(bindingFields[2], &binding.LineageID)
	decode(bindingFields[3], &binding.ProfileNamespace)
	decode(bindingFields[4], &binding.Hint)
	decode(bindingFields[5], &binding.KeyID)
	decode(bindingFields[6], &binding.Epoch)
	decode(bindingFields[7], &binding.Revoked)
	intent, e := profile.VerifyIssuanceIntent(profile.OfflineIssuanceSpec{Profile: verified.Profile, Class: envelope.ArtifactDeviceRecipient, Audience: envelope.AudienceProvisionedDevice, Suite: envelope.SuiteClassicalV1, IssuerRole: profile.RoleIssuer, IssuerScope: delegation.Scope, IssuerKey: issuer, Recipient: &binding, MinimumGeneration: verified.Profile.Generation, Now: now.Unix()})
	check(e)
	sealer, e := profilehpke.NewSealer(binding, request.RecipientPublic)
	check(e)
	signer := productionFixtureIssuerV1{key, issuer.KeyID}
	receipt, e := profile.IssueOfflineChecked(intent, signer, signer, sealer)
	check(e)
	bundle[13] = encode(receipt.ExactArtifact())
	out := encode(bundle)
	record[4] = encode([]byte(out))
	record[13] = encode(policyBytes)
	record[14] = encode(policy.RelayAdmissionDigest[:])
	records[0] = encode(record)
	state[30] = encode(records)
	payload = encode(state)
	outer[1] = encode(payload)
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("kurd-selfhost/state-envelope/v2\x00"))
	mac.Write([]byte{0, 0, 0, 0, 0, 0, 0, 2})
	mac.Write(payload)
	outer[2] = encode(mac.Sum(nil))
	check(os.WriteFile(filepath.Join(dir, "state.kurd-state"), encode(outer), 0600))
	return out
}

type productionFixtureIssuerV1 struct {
	key *ecdsa.PrivateKey
	id  string
}

func (s productionFixtureIssuerV1) Sign(ref profile.KeyReference, message []byte) ([]byte, error) {
	if ref.KeyID != s.id {
		return nil, errors.New("fixture issuer mismatch")
	}
	digest := sha256.Sum256(message)
	r, v, e := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if e != nil {
		return nil, e
	}
	half := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if v.Cmp(half) > 0 {
		v.Sub(elliptic.P256().Params().N, v)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	v.FillBytes(out[32:])
	return out, nil
}
func (s productionFixtureIssuerV1) Verify(ref profile.KeyReference, message, signature []byte) error {
	digest := sha256.Sum256(message)
	if ref.KeyID != s.id || len(signature) != 64 || !ecdsa.Verify(&s.key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return errors.New("fixture signature invalid")
	}
	return nil
}

func productionPeerExchangeV1(ctx context.Context, listener net.Listener, snapshot *selfhost.RelayRuntimeSnapshotV1, now time.Time, rawMode bool) error {
	return productionControlledPeerExchangeV1(ctx, listener, snapshot, now, rawMode, "", nil, nil)
}
func productionControlledPeerExchangeV1(ctx context.Context, listener net.Listener, snapshot *selfhost.RelayRuntimeSnapshotV1, now time.Time, rawMode bool, fault string, reached chan<- struct{}, resume <-chan struct{}, continuation ...func(*auth.ProcessHandshakeResultV1, sessionplan.PlanV2, liveprogram.ProgramV1, io.ReadWriteCloser, [32]byte) error) error {
	raw, err := listener.Accept()
	if err != nil {
		return err
	}
	defer raw.Close()
	if d, ok := ctx.Deadline(); ok {
		raw.SetDeadline(d)
	}
	preface, err := sessionplan.ReadRelayAdmissionPrefaceV1(raw)
	if err != nil {
		return err
	}
	if fault == "tls-internal-close" {
		_, err = raw.Write([]byte("invalid local TLS fixture"))
		return err
	}
	a, ok := snapshot.AdmissionByProfileV1(preface.ProfileContentID, preface.ProfileGeneration)
	if !ok {
		return errors.New("peer admission missing")
	}
	plan, err := sessionplan.BuildRelayV2At(sessionplan.RelayAuthorityV2{ProfileContentID: a.ContentID, ProfileGeneration: a.Generation, ValidFrom: a.ValidFrom, ValidUntil: a.ValidUntil, RuntimePolicy: a.RuntimePolicy, StrategyIDs: a.StrategyIDs, RelayIDs: a.RelayIDs}, preface, now)
	if err != nil {
		return err
	}
	program, err := liveprogram.DecodeV1(a.RuntimePolicy.LiveProgram)
	if err != nil {
		return err
	}
	config, err := snapshot.ServerTLSConfigV1()
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range config.Certificates {
			if k, ok := c.PrivateKey.(ed25519.PrivateKey); ok {
				clear(k)
			}
		}
	}()
	carrier, err := tlstcp.Server(ctx, raw, config, plan.Digest, uint32(program.Limits.MaxFrameBytes))
	if err != nil {
		return err
	}
	defer carrier.Close()
	projected, err := auth.NewProjectedProcessHandshakeConfigV1(a.ClientAuthKeyID, a.RuntimePolicy.RelayAuthKeyID, program, "tls13-tcp")
	if err != nil {
		return err
	}
	cache, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		return err
	}
	handshake, err := kruntime.NewProcessWireRelayHandshakeV1(projected, auth.Dependencies{Identity: snapshot, Trust: snapshot}, cache, plan.Digest)
	if err != nil {
		return err
	}
	defer handshake.Close()
	receive := func() ([]byte, error) {
		f, e := carrier.Receive(ctx)
		if e != nil {
			return nil, e
		}
		defer clear(f.Payload)
		return wirev1.Encode(f)
	}
	send := func(b []byte) error {
		defer clear(b)
		f, e := wirev1.Decode(b)
		if e != nil {
			return e
		}
		defer clear(f.Payload)
		return carrier.Send(ctx, f)
	}
	ch, err := receive()
	if err != nil {
		return err
	}
	if fault == "auth" {
		close(reached)
		<-resume
	}
	sh, err := handshake.AcceptClientHello(ch)
	clear(ch)
	if err != nil {
		return err
	}
	if err = send(sh); err != nil {
		return err
	}
	cf, err := receive()
	if err != nil {
		return err
	}
	sf, result, err := handshake.AcceptClientFinish(cf)
	clear(cf)
	if err != nil {
		return err
	}
	defer result.Close()
	if err = send(sf); err != nil {
		return err
	}
	exporter, err := carrier.CarrierBinding()
	if err != nil {
		return err
	}
	stream, err := carrier.SelectRecordStreamV3(ctx, time.Minute)
	if err != nil {
		return err
	}
	if len(continuation) == 1 {
		return continuation[0](result, plan, program, stream, exporter)
	}
	var bind func([]byte, [32]byte) ([]byte, error)
	if rawMode {
		endpoint, e := kruntime.NewProcessRelayDuplexEndpointV1(result, plan.Digest, program)
		if e != nil {
			return e
		}
		defer endpoint.Abort()
		bind = endpoint.AcceptProfileBind
	} else {
		endpoint, e := kruntime.NewProcessRelayDuplexEndpointV3(result, plan.Digest, program, 1<<20, 16<<20)
		if e != nil {
			return e
		}
		defer endpoint.Abort()
		bind = endpoint.AcceptProfileBind
	}
	var prefix [4]byte
	if _, err = io.ReadFull(stream, prefix[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || size > 1<<20 {
		return errors.New("peer record size")
	}
	encoded := make([]byte, size)
	if _, err = io.ReadFull(stream, encoded); err != nil {
		return err
	}
	if fault == "bind" {
		close(reached)
		<-resume
	}
	ready, err := bind(encoded, exporter)
	clear(encoded)
	if err != nil {
		return err
	}
	defer clear(ready)
	binary.BigEndian.PutUint32(prefix[:], uint32(len(ready)))
	if _, err = stream.Write(prefix[:]); err != nil {
		return err
	}
	_, err = stream.Write(ready)
	if err == nil && fault == "run-hold" {
		close(reached)
		<-resume
	}
	return err
}

func TestProductionNetworkV1RejectsInvalidStageBeforeIO(t *testing.T) {
	for _, scenario := range []string{"out-of-order", "serial-exhaustion", "same-size-current"} {
		t.Run(scenario, func(t *testing.T) {
			a, platform, _, _, _ := productionSignedNetworkFixtureV1(t, false)
			transport, s := a.PrepareV1(context.Background(), productionNetworkFactoryV1{})
			if s != 0 {
				t.Fatal("prepare", s)
			}
			n := transport.(*productionAttemptTransportV1)
			if scenario == "out-of-order" {
				s = transport.AuthenticateTLSV1(context.Background())
			} else {
				fd, status := transport.SocketFDV1()
				if status != 0 || transport.ConfirmProtectedV1(fd) != 0 {
					t.Fatal("confirmation", status)
				}
				if scenario == "serial-exhaustion" {
					n.mu.Lock()
					n.serial = math.MaxUint64
					n.mu.Unlock()
				} else {
					platform.mu.Lock()
					platform.input.VerifyRequest[0] ^= 1
					platform.mu.Unlock()
				}
				s = transport.ConnectProtectedV1(context.Background())
			}
			if s != 3 {
				t.Fatal("invalid stage", s)
			}
			n.mu.Lock()
			connected := n.raw != nil || n.connectorActive
			n.mu.Unlock()
			if connected {
				t.Fatal("invalid stage reached connector")
			}
			if s = transport.FinishV1(); s != 0 {
				t.Fatal("finish", s)
			}
		})
	}
}

func TestProductionNetworkV1GenuineProtectedAttachment(t *testing.T) {
	for _, raw := range []bool{true, false} {
		t.Run(map[bool]string{true: "schema2", false: "schema3"}[raw], func(t *testing.T) {
			a, _, listener, snapshot, now := productionSignedNetworkFixtureV1(t, raw)
			transport, s := a.PrepareV1(context.Background(), productionNetworkFactoryV1{})
			if s != 0 {
				t.Fatal("prepare", s)
			}
			fd, s := transport.SocketFDV1()
			if s != 0 || fd < 0 {
				t.Fatal("publish", fd, s)
			}
			if s = transport.ConfirmProtectedV1(fd); s != 0 {
				t.Fatal("trusted local confirmation", s)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			peerDone := make(chan error, 1)
			go func() { peerDone <- productionPeerExchangeV1(ctx, listener, snapshot, now, raw) }()
			for _, stage := range []struct {
				name string
				run  func(context.Context) int32
			}{{"connect", transport.ConnectProtectedV1}, {"TLS", transport.AuthenticateTLSV1}, {"Kurd", transport.AuthenticateKurdV1}, {"attach", transport.AttachInstalledV1}} {
				if s = stage.run(ctx); s != 0 {
					transport.CloseWakeV1()
					transport.FinishV1()
					t.Fatal(stage.name, s)
				}
			}
			if err := <-peerDone; err != nil {
				t.Fatal("genuine peer", err)
			}
			if s = transport.FinishV1(); s != 0 {
				t.Fatal("finish", s)
			}
			select {
			case <-transport.DoneV1():
			default:
				t.Fatal("retirement not joined")
			}
		})
	}
}
