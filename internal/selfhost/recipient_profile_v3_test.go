// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
)

func servicesForIssuanceV3() *runtimepolicy.ServicesV1 {
	return &runtimepolicy.ServicesV1{Version: 1,
		Proxy: &runtimepolicy.ProxyV1{AddressKinds: []uint8{1, 2}, DestinationCIDRs: []runtimepolicy.PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}},
			DestinationPorts: []runtimepolicy.PortRangeV1{{First: 443, Last: 443}}, MaxConcurrentStreams: 4, MaxBufferBytes: 16777216, ConnectTimeoutMillis: 1000,
			IdleTimeoutSeconds: 30, MaxQueuedBytesPerDirection: 1024},
		Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}},
			MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 1, MaxOperationMillis: 1000},
		Update: &runtimepolicy.UpdateV1{
			URL: "https://updates.example/profile", MaxArtifactBytes: 65536, TimeoutMillis: 1000, MinCheckIntervalSeconds: 60,
		}}
}

func createForServicesV3(t *testing.T, dir, name string, now time.Time, services *runtimepolicy.ServicesV1) (IssuedProfile, enrollment.PublicRequestV1, enrollment.PrivateBundleV1) {
	t.Helper()
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clearEnrollmentPrivate(private) })
	wire, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(dir, CreateProfileOptions{Name: name, ValidFor: 24 * time.Hour, Now: now, RecipientRequest: wire,
		LiveProgram: testLiveProgramV1(t, 1701), RegistryDir: filepath.Join(filepath.Dir(dir), "registry"), Services: services})
	if err != nil {
		t.Fatal(err)
	}
	return issued, request, private
}

func TestV3OptInSealedBundleAndIndependentRelayAuthority(t *testing.T) {
	dir, recovery, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	services := servicesForIssuanceV3()
	issued, request, private := createForServicesV3(t, dir, "services", now, services)
	if services.Update.ProfileID != "" {
		t.Fatal("issuance mutated caller services")
	}
	_, verified, err := VerifyLiveBundleForRecipient(issued.Artifact, now, 1, request, private)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := runtimepolicy.DecodeV3At(verified.Profile.Policy, now)
	if err != nil || policy.Services.Update.ProfileID != issued.ProfileID {
		t.Fatalf("opt-in V3 binding failed: %v", err)
	}
	expectedServices := (runtimepolicy.PolicyV2{Services: services}).Clone().Services
	expectedServices.Update.ProfileID = issued.ProfileID
	if !reflect.DeepEqual(policy.Services, expectedServices) {
		t.Fatal("issuance changed signed proxy/probe/update authority")
	}
	bundle, _, err := verifyLiveBundleAuthority(issued.Artifact, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := encodeLiveBundle(bundle)
	if err != nil || bundle.Version != 2 || !bytes.Equal(canonical, issued.Artifact) || !bytes.Equal(verified.ExactArtifact, issued.Artifact) ||
		len(bundle.DelegationPayload) == 0 || len(bundle.RevocationPayload) == 0 || len(bundle.SealedProfile) == 0 {
		t.Fatal("complete canonical owner bundle changed")
	}
	if bytes.Contains(issued.Artifact, []byte(services.Update.URL)) || bytes.Contains(issued.Artifact, verified.Profile.Policy) {
		t.Fatal("outer bundle exposed sealed service authority")
	}
	tampered := bundle
	tampered.SealedProfile = bytes.Clone(bundle.SealedProfile)
	tampered.SealedProfile[len(tampered.SealedProfile)-1] ^= 1
	tamperedBytes, err := encodeLiveBundle(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyLiveBundleForRecipient(tamperedBytes, now, 1, request, private); err == nil {
		t.Fatal("tampered sealed services admitted")
	}
	state, master, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	zero(master)
	record := state.Profiles[profileIndex(state.Profiles, issued.ProfileID)]
	if !bytes.Equal(record.RuntimePolicy, verified.Profile.Policy) {
		t.Fatal("signed policy and issued record diverged")
	}
	overflowRecord := record
	overflowRecord.Generation = ^uint64(0)
	if _, _, err := replacementRuntimeIntent(overflowRecord, nil, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("V3 clearing overflow accepted")
	}
	badRecord := record
	badPolicy := policy.Clone()
	badPolicy.Services.Update.ProfileID = "profiles.other"
	badPolicy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestV3At(badPolicy, now)
	if err != nil {
		t.Fatal(err)
	}
	badRecord.RuntimePolicy, err = runtimepolicy.EncodeV3At(badPolicy, now)
	if err != nil {
		t.Fatal(err)
	}
	badRecord.RelayAdmissionDigest = bytes.Clone(badPolicy.RelayAdmissionDigest[:])
	if validateLiveProfileRecord(state, badRecord) == nil {
		t.Fatal("stored services escaped profile ID binding")
	}
	snapshot, err := OpenRelayRuntimeSnapshotV1(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	authority, ok := snapshot.AdmissionByProfileV1(issued.ContentID, issued.Generation)
	if !ok || !reflect.DeepEqual(authority.RuntimePolicy.Services, policy.Services) {
		t.Fatal("relay lost issued services")
	}
	digest := sha256.Sum256(issued.Artifact)
	receipt := lifecycle.VerifiedReceipt{ContentID: issued.ContentID, ProviderID: verified.Profile.ProviderID, LineageID: verified.Profile.LineageID,
		RootEpoch: verified.Profile.RootEpoch, RevocationEpoch: verified.Profile.RevocationEpoch, RecipientEpoch: 1, AuthenticatedArtifactSHA256: hex.EncodeToString(digest[:])}
	client, err := sessionplan.BuildV2At(sessionplan.RequestV2{Profile: verified.Profile, RuntimePolicy: policy, ActivationReceipt: receipt}, now)
	if err != nil {
		t.Fatal(err)
	}
	// The preface constructor uses real time; this synthetic fixture instead
	// supplies the same bounded claim and reconstructs at explicit trusted time.
	preface := sessionplan.RelayAdmissionPrefaceV1{Version: sessionplan.RelayAdmissionPrefaceVersionV1, ProfileContentID: issued.ContentID,
		ProfileGeneration: issued.Generation, ActivationReceiptDigest: client.ActivationReceiptDigest, PlanDigest: client.Digest,
		Requested: sessionplan.NarrowingRequestV2{StrategyID: client.StrategyID, EndpointIndexes: []uint8{0}, IPMode: client.IPMode, Routes: client.Routes,
			DNSServers: [][]byte{client.DNSIPv4[:]}, MTU: client.MTU, PayloadProtocols: client.PayloadProtocols, MaxQueuePackets: client.MaxQueuePackets,
			MaxIncompleteOps: client.MaxIncompleteOps, MaxReconnectAttempts: client.MaxReconnectAttempts}}
	relay, err := sessionplan.BuildRelayV2At(sessionplan.RelayAuthorityV2{ProfileContentID: authority.ContentID, ProfileGeneration: authority.Generation,
		ValidFrom: authority.ValidFrom, ValidUntil: authority.ValidUntil, RuntimePolicy: authority.RuntimePolicy, StrategyIDs: authority.StrategyIDs, RelayIDs: authority.RelayIDs}, preface, now)
	if err != nil {
		t.Fatalf("issued client/relay parity: %v", err)
	}
	// Private allocation provenance is intentionally different: only the client
	// has the canonical profile span. Compare all public authority fields and the
	// private policy through its validated accessor, then check sizing separately.
	clientValue, relayValue := reflect.ValueOf(client), reflect.ValueOf(relay)
	for i := 0; i < clientValue.NumField(); i++ {
		field := clientValue.Type().Field(i)
		if field.IsExported() && !reflect.DeepEqual(clientValue.Field(i).Interface(), relayValue.Field(i).Interface()) {
			t.Fatalf("issued client/relay field parity: %s", field.Name)
		}
	}
	clientPolicy, err := client.RuntimePolicyAt(now)
	if err != nil {
		t.Fatal(err)
	}
	defer clientPolicy.Destroy()
	relayPolicy, err := relay.RuntimePolicyAt(now)
	if err != nil {
		t.Fatal(err)
	}
	defer relayPolicy.Destroy()
	if !reflect.DeepEqual(clientPolicy, relayPolicy) {
		t.Fatal("issued client/relay policy parity")
	}
	canonicalProfile, err := envelope.EncodeCanonicalProfileV1(verified.Profile)
	if err != nil {
		t.Fatal(err)
	}
	profileLength := uint32(len(canonicalProfile))
	clear(canonicalProfile)
	clientFacts, clientOK := client.ConstructionFactsV2()
	relayFacts, relayOK := relay.ConstructionFactsV2()
	if !clientOK || !relayOK || clientFacts.ProfileBytes != profileLength || relayFacts.ProfileBytes != envelope.MaxPayloadBytes ||
		clientFacts.ProxyBufferBytes != services.Proxy.MaxBufferBytes || relayFacts.ProxyBufferBytes != clientFacts.ProxyBufferBytes {
		t.Fatal("client/relay construction provenance")
	}
	authority.RuntimePolicy.Services.Update.TimeoutMillis++
	again, ok := snapshot.AdmissionByProfileV1(issued.ContentID, issued.Generation)
	if !ok || again.RuntimePolicy.Services.Update.TimeoutMillis != 1000 {
		t.Fatal("snapshot service alias")
	}
	legacy, legacyRequest, legacyPrivate := createForServicesV3(t, dir, "legacy", now, nil)
	_, legacyVerified, err := VerifyLiveBundleForRecipient(legacy.Artifact, now, 1, legacyRequest, legacyPrivate)
	if err != nil {
		t.Fatal(err)
	}
	legacyPolicy, err := runtimepolicy.DecodeV2At(legacyVerified.Profile.Policy, now)
	if err != nil || legacyPolicy.Services != nil {
		t.Fatal("default gained services")
	}
	legacyBytes, err := runtimepolicy.EncodeV2At(legacyPolicy, now)
	if err != nil || !bytes.Equal(legacyBytes, legacyVerified.Profile.Policy) {
		t.Fatal("legacy V2 bytes changed")
	}
}

func activationRequestServicesV3(t *testing.T, issued IssuedProfile, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, now time.Time, current lifecycle.VerifiedState) profile.ActivationRequest {
	t.Helper()
	bundle, metadata, resolver, opener, err := liveRecipientProviders(issued.Artifact, now, 1, request, private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opener.Close() })
	verified, err := VerifyLiveAndroidArtifact(issued.Artifact, now, 1, resolver, opener)
	if err != nil {
		t.Fatal(err)
	}
	root, err := parseP256Public(bundle.RootPublicDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := parseP256Public(bundle.IssuerPublicDER)
	if err != nil {
		t.Fatal(err)
	}
	return profile.ActivationRequest{Artifact: issued.Artifact, Dispatch: metadata, Now: now.Unix(), Current: current, Root: bundle.Root,
		Delegation:  profile.SignedIssuerDelegationV1{Artifact: bundle.Delegation, RootKey: bundle.Root.Keys[0], Payload: bundle.DelegationPayload, Signature: bundle.DelegationSignature},
		Revocations: profile.SignedRevocationSetV1{Set: bundle.Revocations, RootKey: bundle.Root.Keys[0], Payload: bundle.RevocationPayload, Signature: bundle.RevocationSignature},
		Verifier:    p256Verifier{keys: map[string]*ecdsa.PublicKey{bundle.Root.Keys[0].KeyID: root, bundle.IssuerKey.KeyID: issuer}}, Resolver: resolver, OfflineOpener: opener,
		ContractVersion: verified.Profile.ContractVersion, MinSafetyFloor: verified.Profile.RequiredSafetyFloor, MinRootEpoch: verified.Profile.RootEpoch, MinRevocationEpoch: verified.Profile.RevocationEpoch,
		UnwrapArtifact: func(candidate []byte) ([]byte, error) {
			if !bytes.Equal(candidate, issued.Artifact) {
				return nil, ErrInvalidInput
			}
			return bytes.Clone(bundle.SealedProfile), nil
		}}
}

func TestV3ReplacementPreservesOrExplicitlyChangesServicesAndExactGeneration(t *testing.T) {
	for _, initialV3 := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "preserve"}[initialV3], func(t *testing.T) {
			dir, recovery, passphrase := initializedV2TestState(t)
			now := time.Unix(1_760_000_010, 0).UTC()
			if err := ConfirmRecovery(dir, recovery, passphrase, now); err != nil {
				t.Fatal(err)
			}
			var initial *runtimepolicy.ServicesV1
			if initialV3 {
				initial = servicesForIssuanceV3()
			}
			a, request, private := createForServicesV3(t, dir, "profile-a", now, initial)
			current, err := profile.VerifyInitialActivationAdmission(activationRequestServicesV3(t, a, request, private, now, lifecycle.VerifiedState{}))
			if err != nil {
				t.Fatal(err)
			}
			createForServicesV3(t, dir, "profile-b", now, nil)
			options := RotateProfileOptions{ProfileID: a.ProfileID, RecoveryPath: recovery, RecoveryPassphrase: passphrase, ValidFor: 24 * time.Hour, Now: now.Add(time.Minute), LiveProgram: testLiveProgramV1(t, 1702)}
			if !initialV3 {
				options.Services = servicesForIssuanceV3()
			}
			for step := 0; step < 3; step++ {
				if step == 1 {
					options.Services = servicesForIssuanceV3()
					options.Services.Update.TimeoutMillis = 2000
				}
				if step == 2 {
					options.Services = nil
					options.ClearServices = true
				}
				next, err := RotateProfile(dir, options)
				if err != nil {
					t.Fatal(err)
				}
				if next.Generation != a.Generation+1 {
					t.Fatalf("replacement generation=%d want=%d", next.Generation, a.Generation+1)
				}
				admission, err := profile.VerifyReplacementActivationAdmission(current, activationRequestServicesV3(t, next, request, private, options.Now, current.CurrentState()))
				if err != nil {
					t.Fatalf("native exact replacement rejected: %v", err)
				}
				p, err := runtimepolicy.DecodeRuntimeAt(admission.Profile().Policy, options.Now)
				if err != nil {
					t.Fatal(err)
				}
				if step == 2 {
					if p.SchemaVersion != 2 || p.Services != nil {
						t.Fatal("explicit clearing failed")
					}
				} else {
					want := uint32(1000)
					if step == 1 {
						want = 2000
					}
					if p.SchemaVersion != 3 || p.Services.Update.TimeoutMillis != want || p.Services.Update.ProfileID != a.ProfileID {
						t.Fatal("service preservation/replacement failed")
					}
				}
				state, master, err := loadState(dir)
				if err != nil {
					t.Fatal(err)
				}
				zero(master)
				if state.Generation != uint64(step+3) {
					t.Fatalf("deployment counter regressed: %d", state.Generation)
				}
				record := state.Profiles[profileIndex(state.Profiles, a.ProfileID)]
				if !profileAssignmentsMatch(state.Assignments, record) {
					t.Fatal("address generation diverged")
				}
				a, current = next, admission
				options.Now = options.Now.Add(time.Minute)
			}
		})
	}
}

func TestV3IssuanceRejectsInvalidServiceIntentWithoutStateChange(t *testing.T) {
	dir, recovery, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	a, _, _ := createForServicesV3(t, dir, "profile-a", now, servicesForIssuanceV3())
	before, master, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	zero(master)
	mismatch := servicesForIssuanceV3()
	mismatch.Update.ProfileID = "profiles.wrong"
	for _, opts := range []RotateProfileOptions{
		{Services: servicesForIssuanceV3(), ClearServices: true}, {Services: mismatch},
	} {
		opts.ProfileID = a.ProfileID
		opts.RecoveryPath = recovery
		opts.RecoveryPassphrase = passphrase
		opts.ValidFor = 24 * time.Hour
		opts.Now = now.Add(time.Minute)
		opts.LiveProgram = testLiveProgramV1(t, 1702)
		if _, err := RotateProfile(dir, opts); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid rotation accepted: %v", err)
		}
	}
	if _, err := CreateProfile(dir, CreateProfileOptions{Name: "authority", ValidFor: 24 * time.Hour, Now: now.Add(time.Minute), Services: servicesForIssuanceV3()}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("authority-only gained services: %v", err)
	}
	after, key, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	zero(key)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected service intent changed persisted state")
	}
}

func TestV3RecipientRotationPreservesServicesAndRejectsOldRecipient(t *testing.T) {
	dir, recovery, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	a, oldRequest, oldPrivate := createForServicesV3(t, dir, "profile-a", now, servicesForIssuanceV3())
	request, private, err := enrollment.Generate(now.Add(time.Minute), time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	options := RotateProfileOptions{ProfileID: a.ProfileID, RecoveryPath: recovery, RecoveryPassphrase: passphrase,
		ValidFor: 24 * time.Hour, Now: now.Add(time.Minute), LiveProgram: testLiveProgramV1(t, 1702), RecipientRequest: requestBytes,
		RegistryDir: filepath.Join(filepath.Dir(dir), "registry")}
	options.Services = servicesForIssuanceV3()
	options.Services.Update.ProfileID = "profiles.other"
	if _, err := RotateProfile(dir, options); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid recipient rotation: %v", err)
	}
	options.Services = nil
	next, err := RotateProfile(dir, options)
	if err != nil {
		t.Fatal(err)
	}
	_, verified, err := VerifyLiveBundleForRecipient(next.Artifact, now.Add(time.Minute), 1, request, private)
	if err != nil {
		t.Fatal(err)
	}
	p, err := runtimepolicy.DecodeV3At(verified.Profile.Policy, now.Add(time.Minute))
	if err != nil || p.Services.Update.ProfileID != a.ProfileID || p.Services.Update.TimeoutMillis != 1000 {
		t.Fatalf("recipient rotation lost services: %v", err)
	}
	if _, _, err := VerifyLiveBundleForRecipient(next.Artifact, now.Add(time.Minute), 1, oldRequest, oldPrivate); err == nil {
		t.Fatal("old recipient opened replacement")
	}
}

func TestV3RuntimeIntentOverflowAndCorruptPriorFailClosed(t *testing.T) {
	if _, _, err := replacementRuntimeIntent(profileRecord{Generation: ^uint64(0)}, servicesForIssuanceV3(), false); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("profile successor overflow accepted")
	}
	if _, _, err := replacementRuntimeIntent(profileRecord{Mode: profileModeLive, RuntimePolicy: []byte{1}, CreatedAt: 1}, servicesForIssuanceV3(), false); !errors.Is(err, ErrStateCorrupt) {
		t.Fatal("corrupt prior authority ignored")
	}
}

func TestV3InvalidInitialProfileBindingDoesNotConsumeRecipient(t *testing.T) {
	dir, recovery, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	wire, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	services := servicesForIssuanceV3()
	services.Update.ProfileID = "profiles.wrong"
	before, master, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	zero(master)
	opts := CreateProfileOptions{Name: "profile-a", ValidFor: 24 * time.Hour, Now: now, RecipientRequest: wire, LiveProgram: testLiveProgramV1(t, 1701),
		RegistryDir: filepath.Join(filepath.Dir(dir), "registry"), Services: services}
	if _, err := CreateProfile(dir, opts); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mismatched initial binding accepted: %v", err)
	}
	if services.Update.ProfileID != "profiles.wrong" {
		t.Fatal("rejected issuance mutated input")
	}
	after, key, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	zero(key)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected initial services changed persisted state")
	}
	services.Update.ProfileID = ""
	if _, err := CreateProfile(dir, opts); err != nil {
		t.Fatalf("failed issuance consumed recipient: %v", err)
	}
}

func TestV3SupportDoesNotGrantServicesOnLegacyReissue(t *testing.T) {
	dir, recovery, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	a, request, private := createForServicesV3(t, dir, "legacy-a", now, nil)
	createForServicesV3(t, dir, "legacy-b", now, nil)
	next, err := RotateProfile(dir, RotateProfileOptions{ProfileID: a.ProfileID, RecoveryPath: recovery, RecoveryPassphrase: passphrase,
		ValidFor: 24 * time.Hour, Now: now.Add(time.Minute), LiveProgram: testLiveProgramV1(t, 1702)})
	if err != nil {
		t.Fatal(err)
	}
	_, verified, err := VerifyLiveBundleForRecipient(next.Artifact, now.Add(time.Minute), 1, request, private)
	if err != nil {
		t.Fatal(err)
	}
	p, err := runtimepolicy.DecodeV2At(verified.Profile.Policy, now.Add(time.Minute))
	if err != nil || p.Services != nil || next.Generation != 3 {
		t.Fatalf("legacy issuance behavior changed: generation=%d err=%v", next.Generation, err)
	}
}
