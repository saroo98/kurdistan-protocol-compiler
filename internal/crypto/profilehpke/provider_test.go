// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profilehpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

func TestOfflineAdapterRoundTripClonesKeysAndCloses(t *testing.T) {
	private, public := testRecipientKey(t, 0x31)
	binding := testBinding(envelope.ArtifactDeviceRecipient, "recipient_hint_0001", 7)
	binding.KeyID = testRecipientKeyID(public)
	publicInput, privateInput := bytes.Clone(public), bytes.Clone(private)
	sealer, err := NewSealer(binding, publicInput)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := NewOpener(binding, privateInput)
	if err != nil {
		t.Fatal(err)
	}
	clear(publicInput)
	clear(privateInput)
	outer := testOuterProtected(t, binding)
	plaintext := []byte("signed profile bytes")
	encapsulation, ciphertext, err := sealer.SealOffline(binding, outer, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(encapsulation) != envelope.HPKEP256EncSize || len(ciphertext) != len(plaintext)+envelope.HPKEAEADTagSize {
		t.Fatalf("unexpected HPKE sizes: enc=%d ciphertext=%d", len(encapsulation), len(ciphertext))
	}
	opened, err := opener.OpenOffline(binding, outer, encapsulation, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("opened plaintext differs")
	}
	secondEncapsulation, _, err := sealer.SealOffline(binding, outer, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encapsulation, secondEncapsulation) {
		t.Fatal("fresh seal reused its encapsulation")
	}

	opener.Close()
	if !allZero(opener.recipientPrivate) {
		t.Fatal("close did not clear retained private bytes")
	}
	if _, err := opener.OpenOffline(binding, outer, encapsulation, ciphertext); !IsCategory(err, ErrorClosed) {
		t.Fatalf("open after close error = %v", err)
	}
	opener.Close()
}

func TestOfflineAdapterRejectsBindingKeyAndContextConfusion(t *testing.T) {
	private, public := testRecipientKey(t, 0x42)
	binding := testBinding(envelope.ArtifactDeviceRecipient, "recipient_hint_0002", 4)
	binding.KeyID = testRecipientKeyID(public)
	sealer, err := NewSealer(binding, public)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := NewOpener(binding, private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opener.Close)
	outer := testOuterProtected(t, binding)
	encapsulation, ciphertext, err := sealer.SealOffline(binding, outer, []byte("profile"))
	if err != nil {
		t.Fatal(err)
	}

	wrongBinding := binding
	wrongBinding.Class = envelope.ArtifactEncryptedBackup
	if _, _, err := sealer.SealOffline(wrongBinding, outer, []byte("profile")); !IsCategory(err, ErrorInvalidBinding) {
		t.Fatalf("wrong binding seal error = %v", err)
	}
	if _, err := opener.OpenOffline(wrongBinding, outer, encapsulation, ciphertext); !IsCategory(err, ErrorInvalidBinding) {
		t.Fatalf("wrong binding open error = %v", err)
	}
	wrongOuter := append(bytes.Clone(outer), 0)
	if _, err := opener.OpenOffline(binding, wrongOuter, encapsulation, ciphertext); !IsCategory(err, ErrorOpenFailed) {
		t.Fatalf("wrong context open error = %v", err)
	}
	wrongPrivate, _ := testRecipientKey(t, 0x43)
	if _, err := NewOpener(binding, wrongPrivate); !IsCategory(err, ErrorInvalidBinding) {
		t.Fatalf("wrong private key binding error = %v", err)
	}
	if _, err := opener.OpenOffline(binding, outer, encapsulation[:len(encapsulation)-1], ciphertext); !IsCategory(err, ErrorInvalidInput) {
		t.Fatalf("short encapsulation error = %v", err)
	}
	if _, _, err := sealer.SealOffline(binding, outer, nil); !IsCategory(err, ErrorInvalidInput) {
		t.Fatalf("empty plaintext error = %v", err)
	}

	if _, err := NewSealer(binding, make([]byte, envelope.HPKEP256EncSize)); !IsCategory(err, ErrorInvalidKey) {
		t.Fatalf("zero public key error = %v", err)
	}
	if _, err := NewSealer(binding, public[1:]); !IsCategory(err, ErrorInvalidKey) {
		t.Fatalf("compressed public key error = %v", err)
	}
	if _, err := NewOpener(binding, make([]byte, 32)); !IsCategory(err, ErrorInvalidKey) {
		t.Fatalf("zero private key error = %v", err)
	}
	wrongKeyID := binding
	wrongKeyID.KeyID = "recipient.0000000000000000"
	if _, err := NewSealer(wrongKeyID, public); !IsCategory(err, ErrorInvalidBinding) {
		t.Fatalf("wrong recipient key ID error = %v", err)
	}
	revoked := binding
	revoked.Revoked = true
	if _, err := NewSealer(revoked, public); !IsCategory(err, ErrorInvalidBinding) {
		t.Fatalf("revoked binding error = %v", err)
	}
}

func TestOfflineOpenerMatchesIndependentPhase8Vectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "evidence", "phase8-independent-interop-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Fixtures []struct {
			Kind              string `json:"kind"`
			ID                string `json:"id"`
			ArtifactClass     string `json:"artifact_class"`
			Audience          string `json:"audience"`
			RecipientHint     string `json:"recipient_hint"`
			RecipientEpoch    uint64 `json:"recipient_epoch"`
			RecipientIKMHex   string `json:"recipient_ikm_hex"`
			OuterProtectedHex string `json:"outer_protected_hex"`
			InfoHex           string `json:"info_hex"`
			AADHex            string `json:"aad_hex"`
			EncHex            string `json:"enc_hex"`
			CiphertextHex     string `json:"ciphertext_hex"`
			PlaintextHex      string `json:"plaintext_hex"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	covered := map[envelope.ArtifactClass]bool{}
	for _, fixture := range report.Fixtures {
		if fixture.Kind != "hpke-open" {
			continue
		}
		t.Run(fixture.ID, func(t *testing.T) {
			ikm := mustHex(t, fixture.RecipientIKMHex)
			key, err := hpke.DHKEM(ecdh.P256()).DeriveKeyPair(ikm)
			clear(ikm)
			if err != nil {
				t.Fatal(err)
			}
			private, err := key.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			binding := testBinding(envelope.ArtifactClass(fixture.ArtifactClass), fixture.RecipientHint, fixture.RecipientEpoch)
			binding.KeyID = testRecipientKeyID(key.PublicKey().Bytes())
			opener, err := NewOpener(binding, private)
			clear(private)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(opener.Close)
			outer := mustHex(t, fixture.OuterProtectedHex)
			info, err := envelope.BuildHPKEInfo(outer)
			if err != nil || !bytes.Equal(info, mustHex(t, fixture.InfoHex)) {
				t.Fatalf("normative info mismatch: %v", err)
			}
			aad, err := envelope.BuildHPKEAAD(outer)
			if err != nil || !bytes.Equal(aad, mustHex(t, fixture.AADHex)) {
				t.Fatalf("normative AAD mismatch: %v", err)
			}
			opened, err := opener.OpenOffline(binding, outer, mustHex(t, fixture.EncHex), mustHex(t, fixture.CiphertextHex))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(opened, mustHex(t, fixture.PlaintextHex)) {
				t.Fatal("independent fixture plaintext mismatch")
			}
			covered[binding.Class] = true
		})
	}
	for _, class := range []envelope.ArtifactClass{envelope.ArtifactDeviceRecipient, envelope.ArtifactEncryptedBackup, envelope.ArtifactProviderGroup} {
		if !covered[class] {
			t.Fatalf("no independent HPKE vector covered %s", class)
		}
	}
}

func testRecipientKey(t testing.TB, fill byte) (private, public []byte) {
	t.Helper()
	ikm := bytes.Repeat([]byte{fill}, 32)
	key, err := hpke.DHKEM(ecdh.P256()).DeriveKeyPair(ikm)
	clear(ikm)
	if err != nil {
		t.Fatal(err)
	}
	private, err = key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return private, key.PublicKey().Bytes()
}

func testBinding(class envelope.ArtifactClass, hint string, epoch uint64) profile.RecipientBinding {
	return profile.RecipientBinding{Class: class, ProviderID: "provider.test", LineageID: "lineage.test", ProfileNamespace: "profiles.", Hint: hint, Epoch: epoch}
}

func testRecipientKeyID(public []byte) string {
	digest := sha256.Sum256(public)
	return "recipient." + hex.EncodeToString(digest[:8])
}

func testOuterProtected(t testing.TB, binding profile.RecipientBinding) []byte {
	t.Helper()
	audience := envelope.AudienceProvisionedDevice
	if binding.Class == envelope.ArtifactEncryptedBackup {
		audience = envelope.AudienceProvisionedBackupKey
	} else if binding.Class == envelope.ArtifactProviderGroup {
		audience = envelope.AudienceProvisionedGroup
	}
	outer, err := envelope.BuildSealProtected(envelope.ArtifactMetadata{Class: binding.Class, AudienceClass: audience, RecipientHint: binding.Hint, RecipientEpoch: binding.Epoch})
	if err != nil {
		t.Fatal(err)
	}
	return outer
}

func mustHex(t testing.TB, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func allZero(value []byte) bool {
	return bytes.Equal(value, make([]byte, len(value)))
}

func TestErrorTextIsCategorical(t *testing.T) {
	err := &Error{Category: ErrorInvalidKey}
	if got := err.Error(); got != "profile hpke: invalid-key" {
		t.Fatalf("error text = %q", got)
	}
	if ErrorInvalidKey.String() != "invalid-key" || !errors.Is(err, err) {
		t.Fatal("error category is not stable")
	}
}
