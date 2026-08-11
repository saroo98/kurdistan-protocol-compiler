// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"kurdistan/internal/crypto/profilehpke"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
)

func TestEnrollmentRequestMapsToExactRetainedRecipientCapability(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	zero(master)
	request, private, err := enrollment.Generate(time.Unix(1_760_000_010, 0), time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for index := range private.RecipientPrivate {
			private.RecipientPrivate[index] = 0
		}
		for index := range private.ClientAuthSeed {
			private.ClientAuthSeed[index] = 0
		}
	}()
	record, recipientPublic, clientKeyID, clientPublic, err := recipientCapabilityFromRequest(state, request, 1)
	if err != nil {
		t.Fatal(err)
	}
	if record.Hint != request.RequestID || record.KeyID != request.RecipientKeyID || record.Epoch != 1 ||
		record.ProviderID != state.Delegation.Scope.ProviderID || record.LineageID != state.Delegation.Scope.LineageID || record.Namespace != state.Delegation.Scope.ProfileNamespace ||
		clientKeyID != request.ClientAuthKeyID || !bytes.Equal(recipientPublic, request.RecipientPublic) || !bytes.Equal(clientPublic, request.ClientAuthPublic) {
		t.Fatalf("mapped capability=%+v", record)
	}
	request.RecipientPublic[0] ^= 1
	request.ClientAuthPublic[0] ^= 1
	if bytes.Equal(recipientPublic, request.RecipientPublic) || bytes.Equal(clientPublic, request.ClientAuthPublic) {
		t.Fatal("stored public capabilities alias request memory")
	}
}

func TestLiveEnrollmentRequiresRootSignedRegistrarAuthority(t *testing.T) {
	dataDir, recoveryPath, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now); err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	registryDir := filepath.Join(t.TempDir(), "registry")
	authorityPath := filepath.Join(dataDir, recipientAuthorityFileName)
	if err := os.Remove(authorityPath); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateProfile(dataDir, CreateProfileOptions{Name: "missing-authority", ValidFor: 24 * time.Hour, Now: now, RecipientRequest: requestBytes, RegistryDir: registryDir}); !errors.Is(err, ErrRecipientAuthority) {
		t.Fatalf("missing registrar authority err=%v", err)
	}
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	zero(master)
	issuerProjection := profile.ScopedAuthorityArtifact{
		Role: profile.RoleRecipientRegistrar, RootEpoch: state.Delegation.RootEpoch,
		RootKeyID: state.Delegation.RootKeyID, SubjectKey: state.Delegation.IssuerKey,
		Scope: state.Delegation.Scope, ValidFrom: state.Delegation.ValidFrom,
		ValidUntil: state.Delegation.ValidUntil, AuthorizationEpoch: state.Delegation.DelegationEpoch,
	}
	forged, err := encodeCanonical(signedRecipientAuthorityV1{
		Schema: recipientAuthoritySchemaV1, Version: 1, Authority: issuerProjection,
		Payload: state.DelegationPayload, Signature: state.DelegationSig,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorityPath, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateProfile(dataDir, CreateProfileOptions{Name: "issuer-role-confusion", ValidFor: 24 * time.Hour, Now: now.Add(2 * time.Second), RecipientRequest: requestBytes, RegistryDir: registryDir}); !errors.Is(err, ErrRecipientAuthority) {
		t.Fatalf("issuer delegation substituted for registrar authority err=%v", err)
	}
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(authorityPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(authorityPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateProfile(dataDir, CreateProfileOptions{Name: "tampered-authority", ValidFor: 24 * time.Hour, Now: now.Add(4 * time.Second), RecipientRequest: requestBytes, RegistryDir: registryDir}); !errors.Is(err, ErrRecipientAuthority) {
		t.Fatalf("tampered registrar authority err=%v", err)
	}
}

func TestCreateLiveProfileSealsCanonicalPolicyForExactRecipient(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dataDir, filepath.Join(filepath.Dir(dataDir), "recovery.kurd-recovery"), []byte("state v2 test recovery passphrase"), now); err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(dataDir, CreateProfileOptions{
		Name: "device-one", ValidFor: 24 * time.Hour, Now: now,
		RecipientRequest: requestBytes, LiveProgram: testLiveProgramV1(t, 1701), RegistryDir: filepath.Join(t.TempDir(), "registry"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Mode != profileModeLive || !issued.Sealed || !issued.Connectable {
		t.Fatalf("unexpected issued mode: %+v", issued)
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	record := state.Profiles[profileIndex(state.Profiles, issued.ProfileID)]
	if record.Mode != profileModeLive || len(record.AssignedIPv4) != 4 || len(record.AssignedIPv6) != 0 || len(state.RecipientUses.Records) != 1 {
		t.Fatalf("unexpected live record: %+v", record)
	}
	bundle, dispatch, err := verifyLiveBundleAuthority(issued.Artifact, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	binding := record.Recipient.binding()
	opener, err := profilehpke.NewOpener(binding, private.RecipientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Close()
	rootPublic, _ := parseP256Public(bundle.RootPublicDER)
	issuerPublic, _ := parseP256Public(bundle.IssuerPublicDER)
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{bundle.Root.Keys[0].KeyID: rootPublic, bundle.IssuerKey.KeyID: issuerPublic}}
	verified, err := profile.VerifyOffline(profile.OfflineVerifyRequest{
		Artifact: bundle.SealedProfile, Class: dispatch.Class, Audience: dispatch.AudienceClass,
		Suite: envelope.SuiteClassicalV1, IssuerRole: profile.RoleIssuer, IssuerScope: bundle.Delegation.Scope,
		IssuerKey: bundle.IssuerKey, Now: now.Unix(), MinimumGeneration: 1, MinimumSafetyFloor: 1,
		MinimumRootEpoch: bundle.Root.Epoch, MinimumRevocationEpoch: bundle.Revocations.Epoch,
	}, verifier, exactRecipientResolver{binding: binding}, opener)
	if err != nil {
		t.Fatal(err)
	}
	androidVerified, err := VerifyLiveAndroidArtifact(issued.Artifact, now, issued.Generation, exactRecipientResolver{binding: binding}, opener)
	if err != nil || androidVerified.Profile.ContentID != issued.ContentID || !bytes.Equal(androidVerified.ExactArtifact, issued.Artifact) {
		t.Fatalf("live Android verification err=%v", err)
	}
	session, err := NewAndroidLiveActivationSession(issued.Artifact, now, lifecycle.VerifiedState{}, exactRecipientResolver{binding: binding}, opener)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	command, ok := session.Next()
	if !ok || command.Kind != profile.ActivationCommandSnapshot {
		t.Fatalf("first activation command=%+v", command)
	}
	if err := session.Submit(command, profile.ActivationCommandResult{}); err != nil {
		t.Fatal(err)
	}
	command, ok = session.Next()
	if !ok || command.Kind != profile.ActivationCommandStageCandidate || !bytes.Equal(command.Record.Artifact, issued.Artifact) {
		t.Fatalf("live activation did not stage exact owner bundle: %+v", command)
	}
	policy, err := runtimepolicy.DecodeV2At(verified.Profile.Policy, now)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := runtimepolicy.EncodeV2At(policy, now)
	if err != nil || !bytes.Equal(canonical, record.RuntimePolicy) || policy.RelayAdmissionDigest != bytesToDigest(record.RelayAdmissionDigest) {
		t.Fatalf("runtime policy mismatch err=%v", err)
	}
	program, err := liveprogram.DecodeV1(policy.LiveProgram)
	if err != nil || sha256.Sum256(policy.LiveProgram) != policy.LiveProgramSHA256 || program.SourceGenerationHash == ([32]byte{}) {
		t.Fatalf("live program verification err=%v", err)
	}
	for _, secret := range [][]byte{[]byte(state.Endpoint), record.ClientAuthPublic, state.RelayPublic, record.RuntimePolicy} {
		if bytes.Contains(issued.Artifact, secret) {
			t.Fatal("live outer bundle exposed protected deployment material")
		}
	}
}

func TestBuildRuntimePolicyV2DoesNotAuthorizeIPv4ICMPForIPv6OnlyProfile(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	now := time.Unix(1_760_000_010, 0).UTC()
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	program := testLiveProgramV1(t, 1705)
	policy, _, err := buildRuntimePolicyV2(
		&state,
		request,
		nil,
		netip.MustParseAddr("fd4b:7572:6400::2").AsSlice(),
		program,
		sha256.Sum256(program),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []runtimepolicy.PayloadProtocolV2{
		runtimepolicy.PayloadProtocolICMPv6,
		runtimepolicy.PayloadProtocolTCP,
		runtimepolicy.PayloadProtocolUDP,
	}
	if !reflect.DeepEqual(policy.AllowedProtocols, want) {
		t.Fatalf("IPv6-only payload protocols=%v want=%v", policy.AllowedProtocols, want)
	}
}

func TestRotateAndRevokeLiveProfileInvalidatePriorArtifacts(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	recoveryPath := filepath.Join(filepath.Dir(dataDir), "recovery.kurd-recovery")
	registryDir := filepath.Join(t.TempDir(), "registry")
	now := time.Unix(1_760_100_000, 0).UTC()
	passphrase := []byte("state v2 test recovery passphrase")
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now); err != nil {
		t.Fatal(err)
	}
	requestOne, privateOne, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(privateOne)
	requestOneBytes, _ := enrollment.EncodeRequestV1(requestOne)
	first, err := CreateProfile(dataDir, CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now, RecipientRequest: requestOneBytes, LiveProgram: testLiveProgramV1(t, 1702), RegistryDir: registryDir})
	if err != nil {
		t.Fatal(err)
	}
	requestTwo, privateTwo, err := enrollment.Generate(now.Add(time.Minute), time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(privateTwo)
	requestTwoBytes, _ := enrollment.EncodeRequestV1(requestTwo)
	second, err := RotateProfile(dataDir, RotateProfileOptions{
		ProfileID: first.ProfileID, RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase,
		ValidFor: 24 * time.Hour, Now: now.Add(time.Minute), RecipientRequest: requestTwoBytes, LiveProgram: testLiveProgramV1(t, 1703), RegistryDir: registryDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ProfileID != first.ProfileID || second.Generation != first.Generation+1 || second.ContentID == first.ContentID {
		t.Fatalf("unexpected rotation first=%+v second=%+v", first, second)
	}
	if _, err := VerifyLiveBundleAgainstCurrentState(dataDir, first.Artifact, now.Add(2*time.Minute)); !errors.Is(err, ErrRollback) {
		t.Fatalf("old live artifact remained current: %v", err)
	}
	if _, err := VerifyLiveBundleAgainstCurrentState(dataDir, second.Artifact, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("new live artifact not current: %v", err)
	}
	if _, err := RotateProfile(dataDir, RotateProfileOptions{
		ProfileID: second.ProfileID, RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase,
		ValidFor: 24 * time.Hour, Now: now.Add(2 * time.Minute), RecipientRequest: requestTwoBytes, LiveProgram: testLiveProgramV1(t, 1704), RegistryDir: registryDir,
	}); !errors.Is(err, ErrRecipientReplay) {
		t.Fatalf("recipient replay during rotation err=%v", err)
	}
	if err := RevokeProfile(dataDir, RevokeProfileOptions{ProfileID: second.ProfileID, RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase, Now: now.Add(3 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLiveBundleAgainstCurrentState(dataDir, second.Artifact, now.Add(4*time.Minute)); !errors.Is(err, ErrRollback) {
		t.Fatalf("revoked live artifact remained current: %v", err)
	}
}

func TestRevokeLiveProfileCompactsStoredArtifactAndPreservesSummary(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	recoveryPath := filepath.Join(filepath.Dir(dataDir), "recovery.kurd-recovery")
	registryDir := filepath.Join(t.TempDir(), "registry")
	now := time.Unix(1_760_200_000, 0).UTC()
	passphrase := []byte("state v2 test recovery passphrase")
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now); err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(dataDir, CreateProfileOptions{
		Name: "disposable-phone", ValidFor: 24 * time.Hour, Now: now,
		RecipientRequest: requestBytes, LiveProgram: testLiveProgramV1(t, 1711), RegistryDir: registryDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(dataDir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := RevokeProfile(dataDir, RevokeProfileOptions{
		ProfileID: issued.ProfileID, RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase, Now: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	record := state.Profiles[profileIndex(state.Profiles, issued.ProfileID)]
	if !record.Revoked || len(record.Artifact) != 0 || len(record.RuntimePolicy) != 0 ||
		len(record.RecipientPublic) != 0 || len(record.ClientAuthPublic) != 0 ||
		len(record.RelayAdmissionDigest) != 0 || len(record.AssignedIPv4) != 0 || len(record.AssignedIPv6) != 0 {
		t.Fatalf("revoked live record retained sensitive or bulky material: %+v", record)
	}
	stored, err := LoadProfile(dataDir, issued.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Revoked || stored.Connectable || !stored.Sealed || len(stored.Artifact) != 0 || stored.URI != "" || len(stored.QRChunks) != 0 {
		t.Fatalf("revoked summary=%+v", stored)
	}
	after, err := os.Stat(filepath.Join(dataDir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() >= before.Size() {
		t.Fatalf("revocation did not compact state: before=%d after=%d", before.Size(), after.Size())
	}
}

func TestFailedCapacityTransactionDoesNotConsumeRecipientCapability(t *testing.T) {
	dataDir, recoveryPath, passphrase := initializedV2TestState(t)
	registryDir := filepath.Join(t.TempDir(), "registry")
	now := time.Unix(1_760_300_000, 0).UTC()
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now); err != nil {
		t.Fatal(err)
	}
	padding, err := CreateProfile(dataDir, CreateProfileOptions{Name: "capacity-padding", ValidFor: 24 * time.Hour, Now: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	index := profileIndex(state.Profiles, padding.ProfileID)
	if index < 0 {
		zero(master)
		t.Fatal("padding profile missing")
	}
	originalArtifact := bytes.Clone(state.Profiles[index].Artifact)
	low, high, best := 1, maxStateBytes, 0
	for low <= high {
		middle := low + (high-low)/2
		state.Profiles[index].Artifact = bytes.Repeat([]byte{0x42}, middle)
		payload, encodeErr := encodeCanonical(state)
		if encodeErr != nil {
			zero(master)
			t.Fatal(encodeErr)
		}
		envelope, encodeErr := encodeCanonical(stateEnvelope{Version: stateVersionV2, Payload: payload, MAC: stateMACV2(master, payload)})
		if encodeErr != nil {
			zero(master)
			t.Fatal(encodeErr)
		}
		if len(envelope) <= maxStateBytes-1024 {
			best = middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best == 0 {
		zero(master)
		t.Fatal("could not construct near-capacity state")
	}
	state.Profiles[index].Artifact = bytes.Repeat([]byte{0x42}, best)
	if err := saveState(dataDir, master, state); err != nil {
		zero(master)
		t.Fatal(err)
	}
	zero(master)

	request, private, err := enrollment.Generate(now.Add(2*time.Second), time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	options := CreateProfileOptions{
		Name: "capacity-failed", ValidFor: 24 * time.Hour, Now: now.Add(2 * time.Second),
		RecipientRequest: requestBytes, LiveProgram: testLiveProgramV1(t, 1712), RegistryDir: registryDir,
	}
	if _, err := CreateProfile(dataDir, options); !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("near-capacity create error = %v, want capacity exhausted", err)
	}
	state, master, err = loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	index = profileIndex(state.Profiles, padding.ProfileID)
	state.Profiles[index].Artifact = originalArtifact
	if err := saveState(dataDir, master, state); err != nil {
		zero(master)
		t.Fatal(err)
	}
	zero(master)
	options.Name = "capacity-retry"
	options.Now = now.Add(3 * time.Second)
	if _, err := CreateProfile(dataDir, options); err != nil {
		t.Fatalf("recipient capability remained consumed after rolled-back state transaction: %v", err)
	}
}

type exactRecipientResolver struct{ binding profile.RecipientBinding }

func testLiveProgramV1(t *testing.T, seed int64) []byte {
	t.Helper()
	model, err := compiler.Generate(seed)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{
		Profile: model, ClientMandatoryFeatures: append([]string(nil), capabilities[:2]...),
		RelayMandatoryFeatures: append([]string(nil), capabilities[:2]...), SelectedFeatures: append([]string(nil), capabilities...),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := liveprogram.EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (resolver exactRecipientResolver) ResolveRecipient(class envelope.ArtifactClass, hint string) (profile.RecipientBinding, error) {
	return profile.ResolveRecipientBinding([]profile.RecipientBinding{resolver.binding}, class, hint)
}

func bytesToDigest(value []byte) (result [32]byte) {
	copy(result[:], value)
	return result
}
