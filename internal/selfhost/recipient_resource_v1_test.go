// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"errors"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"kurdistan/internal/crypto/profilehpke"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
)

func resourceRecipientFixture(t *testing.T, services *runtimepolicy.ServicesV1) (IssuedProfile, enrollment.PublicRequestV1, enrollment.PrivateBundleV1, time.Time, string) {
	t.Helper()
	dir, recovery, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	issued, request, private := createForServicesV3(t, dir, "resource", now, services)
	return issued, request, private, now, dir
}

func TestResourcePreflightEncryptedFailureProvenanceAcrossAdmission(t *testing.T) {
	issued, request, private, now, dir := resourceRecipientFixture(t, servicesForIssuanceV3())
	b, _, resolver, opener, err := liveRecipientProvidersWithResourceMode(issued.Artifact, now, 1, request, private, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Destroy()
	activation, err := liveActivationRequestWithResourceMode(issued.Artifact, now, lifecycle.VerifiedState{}, resolver, opener, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	current, err := profile.VerifyInitialActivationAdmission(activation)
	if err != nil {
		t.Fatal(err)
	}
	activation.Current = current.CurrentState()
	if _, err := profile.VerifyActivationAdmission(activation); err != nil {
		t.Fatalf("exact current: %v", err)
	}
	sealed, err := envelope.ParseSealedProfileOpaque(b.SealedProfile)
	if err != nil {
		t.Fatal(err)
	}
	binding := resolver.(liveRecipientResolver).binding
	plain, err := opener.opener.OpenOffline(binding, sealed.Protected, sealed.Encapsulation, sealed.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	signed, err := envelope.ParseSignedProfileOpaque(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signed.Payload)
	state, master, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	issuerDER, err := openWithKey(master, state.IssuerSecret, []byte(state.DeploymentID+"|"+state.IssuerKey.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(issuerDER)
	key, err := parseP256Private(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := profilehpke.NewSealer(binding, request.RecipientPublic)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformedKind := range []string{"schema", "size", "byte-array"} {
		var fields map[uint64]cbor.RawMessage
		if err := cbor.Unmarshal(signed.Payload, &fields); err != nil {
			t.Fatal(err)
		}
		originalPolicy := fields[20]
		badPolicy := []byte{0xa0}
		if malformedKind == "size" {
			badPolicy = make([]byte, 65537)
		}
		fields[20], _ = encodeCanonical(badPolicy)
		if malformedKind == "byte-array" {
			var validPolicy []byte
			if err := cbor.Unmarshal(originalPolicy, &validPolicy); err != nil {
				t.Fatal(err)
			}
			if len(validPolicy) >= 2048 {
				t.Fatalf("fixture policy exceeds coercion regression cap: %d", len(validPolicy))
			}
			values := make([]uint64, len(validPolicy))
			for i, b := range validPolicy {
				values[i] = uint64(b)
			}
			fields[20], _ = encodeCanonical(values)
		}
		payload, _ := encodeCanonical(fields)
		structure, err := envelope.BuildCOSESigStructure(signed.Protected, payload)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := (p256Signer{keyID: b.IssuerKey.KeyID, key: key}).Sign(b.IssuerKey, structure)
		if err != nil {
			t.Fatal(err)
		}
		malformed, err := envelope.BuildTaggedCOSESign1(signed.Protected, payload, sig)
		if err != nil {
			t.Fatal(err)
		}
		enc, cipher, err := sealer.SealOffline(binding, sealed.Protected, malformed)
		if err != nil {
			t.Fatal(err)
		}
		badBundle := b
		badBundle.SealedProfile, err = envelope.BuildSealedFrame(sealed.Protected, enc, cipher)
		if err != nil {
			t.Fatal(err)
		}
		bad, _ := encodeCanonical(badBundle)
		borrowed := bytes.Clone(bad)
		want := ErrInvalidInput
		if malformedKind == "size" {
			want = errLiveResourceSize
		}
		if _, err := verifyLiveAndroidArtifactWithResourceMode(bad, now, 1, resolver, opener, liveResourceTypedFirstV1); !errors.Is(err, want) {
			t.Fatalf("structural failure masked: %v", err)
		}
		for _, replacement := range []bool{false, true} {
			a := activation
			a.Artifact = bad
			var stages []profile.ActivationStage
			a.Observe = func(stage profile.ActivationStage) { stages = append(stages, stage) }
			if replacement {
				_, err = profile.VerifyReplacementActivationAdmission(current, a)
			} else {
				_, err = profile.VerifyActivationAdmission(a)
			}
			if err == nil || !errors.Is(opener.resourceError(), want) {
				t.Fatalf("admission lost structural provenance: %v", err)
			}
			if !reflect.DeepEqual(stages, []profile.ActivationStage{profile.StageOuterParsed}) {
				t.Fatalf("generic signed/profile validation reached: %v", stages)
			}
		}
		if !bytes.Equal(bad, borrowed) {
			t.Fatal("borrowed artifact was cleared")
		}
		// A later healthy operation must not inherit the prior operation's fact.
		if _, err := verifyLiveAndroidArtifactWithResourceMode(issued.Artifact, now, 1, resolver, opener, liveResourceTypedFirstV1); err != nil || opener.resourceError() != nil {
			t.Fatalf("stale failure: %v", err)
		}
	}
}

func TestResourcePreflightRecipientStructBoundsAndBorrowedOwnership(t *testing.T) {
	issued, request, private, now, _ := resourceRecipientFixture(t, nil)
	for _, mutate := range []func(*enrollment.PublicRequestV1){
		func(r *enrollment.PublicRequestV1) { r.RecipientKeyID = string(bytes.Repeat([]byte{'x'}, 100000)) },
		func(r *enrollment.PublicRequestV1) { r.ClientAuthKeyID = string(bytes.Repeat([]byte{'x'}, 100000)) },
		func(r *enrollment.PublicRequestV1) { r.Nonce = make([]byte, 33) },
	} {
		r := request
		mutate(&r)
		if _, _, _, _, err := liveRecipientProvidersWithResourceMode(issued.Artifact, now, 1, r, private, liveResourceTypedFirstV1); err == nil {
			t.Fatal("oversized borrowed struct admitted")
		}
	}
	large := make([]byte, 32, 1<<20)
	copy(large, private.RecipientPrivate)
	p := private
	p.RecipientPrivate = large
	_, _, resolver, opener, err := liveRecipientProvidersWithResourceMode(issued.Artifact, now, 1, request, p, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyLiveAndroidArtifactWithResourceMode(issued.Artifact, now, 1, resolver, opener.opener, liveResourceTypedFirstV1); err == nil {
		t.Fatal("unwrapped provider admitted")
	}
	opener.Destroy()
	opener.Destroy()
	if !bytes.Equal(large, private.RecipientPrivate) {
		t.Fatal("borrowed excess-capacity key mutated")
	}
}

func TestResourcePreflightOwnedRecipientMatchesLegacyAndReopens(t *testing.T) {
	for _, services := range []*runtimepolicy.ServicesV1{nil, servicesForIssuanceV3()} {
		issued, request, private, now, _ := resourceRecipientFixture(t, services)
		_, _, resolver, opener, err := liveRecipientProvidersWithResourceMode(issued.Artifact, now, 1, request, private, liveResourceTypedFirstV1)
		if err != nil {
			t.Fatal(err)
		}
		defer opener.Destroy()
		got, err := verifyLiveAndroidArtifactWithResourceMode(issued.Artifact, now, 1, resolver, opener, liveResourceTypedFirstV1)
		if err != nil {
			t.Fatal(err)
		}
		_, legacy, err := VerifyLiveBundleForRecipient(issued.Artifact, now, 1, request, private)
		if err != nil || !reflect.DeepEqual(got, legacy) {
			t.Fatalf("typed/legacy mismatch: %v", err)
		}
		// Shape-admitted failures retain the legacy decision. Measurements are
		// operation allocation observations, not retained or peak-memory limits.
		for _, failure := range []string{"signature", "hpke", "authority", "expiry"} {
			b, _ := decodeLiveBundle(issued.Artifact)
			at := now
			switch failure {
			case "signature":
				b.DelegationSignature[0] ^= 1
			case "hpke":
				sealed, parseErr := envelope.ParseSealedProfileOpaque(b.SealedProfile)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				sealed.Ciphertext[0] ^= 1
				b.SealedProfile, err = envelope.BuildSealedFrame(sealed.Protected, sealed.Encapsulation, sealed.Ciphertext)
				if err != nil {
					t.Fatal(err)
				}
			case "authority":
				b.RootFingerprint = string(bytes.Repeat([]byte{'0'}, 64))
			case "expiry":
				at = time.Unix(b.Revocations.ExpiresAt, 0)
			}
			bad, encodeErr := encodeCanonical(b)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			_, legacyErr := VerifyLiveAndroidArtifact(bad, at, 1, resolver, opener.opener)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, typedErr := verifyLiveAndroidArtifactWithResourceMode(bad, at, 1, resolver, opener, liveResourceTypedFirstV1)
			runtime.ReadMemStats(&after)
			if legacyErr == nil || typedErr == nil || typedErr.Error() != legacyErr.Error() || opener.resourceError() != nil {
				t.Fatalf("%s legacy=%v typed=%v resource=%v", failure, legacyErr, typedErr, opener.resourceError())
			}
			t.Logf("%s services=%t input=%d warm-after-fixture alloc-bytes=%d alloc-objects=%d", failure, services != nil, len(bad), after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs)
		}
		activation, err := liveActivationRequestWithResourceMode(issued.Artifact, now, lifecycle.VerifiedState{}, resolver, opener, liveResourceTypedFirstV1)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := activation.UnwrapArtifact(issued.Artifact)
		if err != nil || len(inner) == 0 {
			t.Fatalf("reopen: %v", err)
		}
		clear(inner)
		b, _ := decodeLiveBundle(issued.Artifact)
		b.SealedProfile = []byte{0xa0}
		bad, _ := encodeCanonical(b)
		if _, err := activation.UnwrapArtifact(bad); err == nil {
			t.Fatal("reopen bypassed shape")
		}
		opener.Destroy()
		opener.Destroy()
		if _, err := verifyLiveAndroidArtifactWithResourceMode(issued.Artifact, now, 1, resolver, opener, liveResourceTypedFirstV1); err == nil {
			t.Fatal("destroyed opener reused")
		}
		if len(private.RecipientPrivate) != 32 || bytes.Equal(private.RecipientPrivate, make([]byte, 32)) {
			t.Fatal("borrowed private input cleared")
		}
	}
}
