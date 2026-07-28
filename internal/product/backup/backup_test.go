// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package backup

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

const testPassphrase = "correct horse battery staple"

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
