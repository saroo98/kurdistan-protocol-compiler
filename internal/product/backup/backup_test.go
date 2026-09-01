// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestBackupV2AuthenticatedPayloadCannotClaimLegacyHeader(t *testing.T) {
	plaintext, err := encodePayload(keyPayloadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	salt, nonce := make([]byte, SaltBytes), make([]byte, NonceBytes)
	header := encodeHeader(1, ArgonMemoryKiB, ArgonIterations, ArgonThreads, salt, nonce, len(plaintext)+16)
	key := argon2.IDKey([]byte(testPassphrase), salt, ArgonIterations, ArgonMemoryKiB, ArgonThreads, KeyBytes)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	encoded := append(header, aead.Seal(nil, nonce, plaintext, header)...)
	if _, _, err := OpenPreview(testPassphrase, encoded); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("authenticated version mismatch=%v", err)
	}
}

func TestRecipientMetadataCopiesAndWipesWithoutGrantingLegacyBindings(t *testing.T) {
	payload := keyPayloadFixture(t)
	keys, err := DecodeRecipientKeyRecords(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].SourceVersion != 2 || keys[0].SourceStatus != 4 || keys[0].SourceProfiles[0] != "a" {
		t.Fatal("source metadata lost")
	}
	payload.Records[1].ExactBytes[30] = 9
	if keys[0].PublicRequest[0] != 1 {
		t.Fatal("material aliases input")
	}
	request, privateBytes := keys[0].PublicRequest, keys[0].PrivateBundle
	keys[0].Destroy()
	if request[0] != 0 || privateBytes[0] != 0 || keys[0].SourceVersion != 0 {
		t.Fatal("destroy did not wipe")
	}
	legacyRaw, _ := hex.DecodeString("4b434b320201016b00000000000000010000000000000002000101000102")
	legacy := Payload{Version: 1, Records: []Record{{Kind: RecordLocalAlias, LocalID: "recipient-keys-v2", ExactBytes: legacyRaw}}}
	keys, err = DecodeRecipientKeyRecords(legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer keys[0].Destroy()
	if keys[0].SourceVersion != 1 || keys[0].SourceStatus != 0 || len(keys[0].SourceProfiles) != 0 {
		t.Fatal("legacy metadata invented")
	}
}

func TestRecipientV2RejectsDuplicateKeyMaterialAndProfileOwnership(t *testing.T) {
	for _, variant := range []string{"id", "public", "private", "profile"} {
		t.Run(variant, func(t *testing.T) {
			payload := keyPayloadFixture(t)
			payload.Records = append(payload.Records, Record{Kind: RecordNativeProfile, LocalID: "b", Generation: 1, ExactBytes: []byte("y")})
			raw := payload.Records[1].ExactBytes
			second := bytes.Clone(raw[6:])
			second[1] = 'l'
			second[21] = 'b'
			second[24] = 3
			second[27] = 4
			switch variant {
			case "id":
				second[1] = 'k'
			case "public":
				second[24] = 1
			case "private":
				second[27] = 2
			case "profile":
				second[21] = 'a'
			}
			raw[5] = 2
			payload.Records[1].ExactBytes = append(raw, second...)
			if err := ValidatePayload(payload); err == nil {
				t.Fatal("duplicate accepted")
			}
		})
	}
}

const testPassphrase = "correct horse battery staple"

func TestBackupCanonicalDecoderRejectsUnknownDuplicateAndOversizedClaims(t *testing.T) {
	for _, fixture := range []string{
		"a3010201020280", "a201030280", "a20118020280", "a20102028000",
		"a20102029881", "a201020281a30103026161045affffffff",
	} {
		raw, err := hex.DecodeString(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodePayload(raw); err == nil {
			t.Fatalf("noncanonical or unbounded claim accepted: %s", fixture)
		}
	}
}

func TestBackupV2TamperedHeaderAndCiphertextNeverOpen(t *testing.T) {
	encoded, err := CreateWithRandom(bytes.NewReader(bytes.Repeat([]byte{7}, 28)), testPassphrase, keyPayloadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{7, 9, fixedHeaderBytes, len(encoded) - 1} {
		mutated := bytes.Clone(encoded)
		mutated[offset] ^= 1
		if opened, _, err := OpenPreview(testPassphrase, mutated); err == nil {
			opened.Destroy()
			t.Fatalf("v2 tamper %d accepted", offset)
		}
	}
}

func TestBackupV2UsesDistinctAuthenticatedHeaderAndMatchingPayloadVersion(t *testing.T) {
	payload := testPayload()
	payload.Version = 2
	encoded, err := CreateWithRandom(bytes.NewReader(bytes.Repeat([]byte{0x29}, SaltBytes+NonceBytes)), testPassphrase, payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded[:8]) != "KURDBK2\x00" || binary.BigEndian.Uint16(encoded[8:10]) != 2 {
		t.Fatal("v2 silently emitted legacy header")
	}
	opened, preview, err := OpenPreview(testPassphrase, encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Destroy()
	if preview.Version != "kurd-backup-v2" {
		t.Fatalf("preview version=%s", preview.Version)
	}
	restored, err := Restore(opened, preview, &acceptingVerifier{})
	if err != nil || restored.Version != 2 {
		t.Fatalf("v2 restore=%d %v", restored.Version, err)
	}
	destroyPayload(&restored)
}

func TestBackupLegacyCanonicalSourceGolden(t *testing.T) {
	payload := Payload{Version: 1, Records: []Record{{Kind: RecordLocalAlias, LocalID: "a", ExactBytes: []byte("x")}}}
	raw, err := encodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(raw) != "a201010281a30103026161044178" {
		t.Fatalf("legacy canonical bytes changed: %x", raw)
	}
	encoded, err := CreateWithRandom(bytes.NewReader(bytes.Repeat([]byte{0x11}, SaltBytes+NonceBytes)), testPassphrase, payload)
	if err != nil {
		t.Fatal(err)
	}
	const golden = "4b555244424b310000010101000100000000000301100c000000001e1111111111111111111111111111111111111111111111111111111166d08be8dd9de2cada85cc64f3b2f99b1efb09c91d40ef3f1bc806d91d83"
	if hex.EncodeToString(encoded) != golden {
		t.Fatal("source-proven v1 ciphertext changed")
	}
	original, err := hex.DecodeString(golden)
	if err != nil {
		t.Fatal(err)
	}
	opened, preview, err := OpenPreview(testPassphrase, original)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Destroy()
	if preview.Version != LegacyVersion {
		t.Fatal("legacy import mislabeled")
	}
}

func keyPayloadFixture(t *testing.T) Payload {
	t.Helper()
	raw, err := hex.DecodeString("4b434b330301016b0400000000000000010000000000000002010161000101000102")
	if err != nil {
		t.Fatal(err)
	}
	return Payload{Version: 2, Records: []Record{{Kind: RecordNativeProfile, LocalID: "a", Generation: 1, ExactBytes: []byte("x")}, {Kind: RecordLocalAlias, LocalID: "recipient-keys-v3", ExactBytes: raw}}}
}

func TestBackupV2RejectsUnboundPendingAndAmbiguousKeyMetadata(t *testing.T) {
	for _, mutation := range []string{"pending", "missing_profile", "unknown_inner", "truncated", "trailing", "wrong_outer", "legacy_id", "duplicate_record"} {
		t.Run(mutation, func(t *testing.T) {
			payload := keyPayloadFixture(t)
			raw := payload.Records[1].ExactBytes
			switch mutation {
			case "pending":
				raw[8] = 1
			case "missing_profile":
				raw[27] = 'b'
			case "unknown_inner":
				raw[4] = 4
			case "truncated":
				payload.Records[1].ExactBytes = raw[:len(raw)-1]
			case "trailing":
				payload.Records[1].ExactBytes = append(raw, 0)
			case "wrong_outer":
				payload.Version = 1
			case "legacy_id":
				payload.Records[1].LocalID = "recipient-keys-v2"
			case "duplicate_record":
				payload.Records = append(payload.Records, payload.Records[1])
			}
			if _, err := encodePayload(payload); err == nil {
				t.Fatal("invalid recipient backup metadata accepted")
			}
		})
	}
}

type acceptingVerifier struct {
	minimum uint64
	seen    int
}

func (v *acceptingVerifier) VerifyBackupRecord(record Record) error {
	v.seen++
	if record.Generation != 0 && record.Generation < v.minimum {
		return errors.New("rollback")
	}
	return nil
}

func testPayload() Payload {
	return Payload{
		Version: 1,
		Records: []Record{
			{
				Kind:       RecordNativeProfile,
				LocalID:    "018f0f47-aaaa-bbbb-cccc-001122334455",
				Generation: 7,
				ExactBytes: []byte("opaque-signed-profile"),
			},
			{
				Kind:       RecordVerifiedReceipt,
				LocalID:    "018f0f47-aaaa-bbbb-cccc-001122334455",
				Generation: 7,
				ExactBytes: []byte("opaque-verified-receipt"),
			},
			{
				Kind:       RecordNonsecretSettings,
				LocalID:    "settings",
				ExactBytes: []byte("offline-preferences"),
			},
		},
	}
}

func TestKurdBackupV1RoundTripAndSelectiveVerifier(t *testing.T) {
	encoded, err := CreateWithRandom(
		bytes.NewReader(bytes.Repeat([]byte{0x5a}, SaltBytes+NonceBytes)),
		testPassphrase,
		testPayload(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("opaque-signed-profile")) ||
		bytes.Contains(encoded, []byte(testPassphrase)) {
		t.Fatal("backup leaked plaintext")
	}
	opened, preview, err := OpenPreview(testPassphrase, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if preview.RecordCount != 3 || preview.KindCounts[RecordNativeProfile] != 1 {
		t.Fatalf("preview=%+v", preview)
	}
	verifier := &acceptingVerifier{minimum: 7}
	restored, err := Restore(opened, preview, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.seen != len(restored.Records) ||
		!bytes.Equal(restored.Records[0].ExactBytes, testPayload().Records[0].ExactBytes) {
		t.Fatal("restore did not return verified exact records")
	}
}

func TestKurdBackupV1RejectsWrongPassphraseTamperAndTruncation(t *testing.T) {
	encoded, err := CreateWithRandom(
		bytes.NewReader(bytes.Repeat([]byte{0x33}, SaltBytes+NonceBytes)),
		testPassphrase,
		testPayload(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenPreview("wrong passphrase with length", encoded); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong passphrase error=%v", err)
	}
	for _, index := range []int{0, 11, fixedHeaderBytes, len(encoded) - 1} {
		mutated := bytes.Clone(encoded)
		mutated[index] ^= 0xff
		if _, _, err := OpenPreview(testPassphrase, mutated); err == nil {
			t.Fatalf("tamper at %d accepted", index)
		}
	}
	for _, length := range []int{0, fixedHeaderBytes - 1, len(encoded) - 1} {
		if _, _, err := OpenPreview(testPassphrase, encoded[:length]); err == nil {
			t.Fatalf("truncation at %d accepted", length)
		}
	}
}

func TestKurdBackupV1RejectsResourceParametersBeforeKDF(t *testing.T) {
	encoded, err := CreateWithRandom(
		bytes.NewReader(bytes.Repeat([]byte{0x44}, SaltBytes+NonceBytes)),
		testPassphrase,
		testPayload(),
	)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		offset int
		value  uint32
	}{
		{"memory-below-floor", 12, ArgonMemoryKiB - 1},
		{"memory-above-ceiling", 12, MaxArgonMemoryKiB + 1},
		{"iterations-below-floor", 16, ArgonIterations - 1},
		{"iterations-above-ceiling", 16, MaxArgonIterations + 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			mutated := bytes.Clone(encoded)
			binary.BigEndian.PutUint32(mutated[test.offset:test.offset+4], test.value)
			if _, _, err := OpenPreview(testPassphrase, mutated); !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestKurdBackupV1RejectsRollbackAndPreviewSubstitution(t *testing.T) {
	encoded, err := CreateWithRandom(
		bytes.NewReader(bytes.Repeat([]byte{0x66}, SaltBytes+NonceBytes)),
		testPassphrase,
		testPayload(),
	)
	if err != nil {
		t.Fatal(err)
	}
	opened, preview, err := OpenPreview(testPassphrase, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(opened, preview, &acceptingVerifier{minimum: 8}); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("rollback error=%v", err)
	}
	substituted := clonePreview(preview)
	substituted.RecordCount++
	if _, err := Restore(opened, substituted, &acceptingVerifier{minimum: 7}); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("substitution error=%v", err)
	}
}

func TestKurdBackupV1PassphrasePolicyIsExactUTF8(t *testing.T) {
	for _, passphrase := range []string{
		"short",
		string(bytes.Repeat([]byte{0xff}, 12)),
		string(bytes.Repeat([]byte{'a'}, MaximumPassBytes+1)),
	} {
		if _, err := CreateWithRandom(bytes.NewReader(make([]byte, 64)), passphrase, testPayload()); !errors.Is(err, ErrInvalidPassphrase) {
			t.Fatalf("passphrase error=%v", err)
		}
	}
	composed := "éééééééééééé"
	decomposed := "e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301"
	encoded, err := CreateWithRandom(
		bytes.NewReader(bytes.Repeat([]byte{0x77}, SaltBytes+NonceBytes)),
		composed,
		testPayload(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenPreview(decomposed, encoded); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("normalization was applied: %v", err)
	}
}
