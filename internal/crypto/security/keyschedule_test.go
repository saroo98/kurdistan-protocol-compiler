// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// TestKeyScheduleReferenceOracleRFC5869Vector pins the independent test oracle to RFC
// 5869 test case 1, the same fixed case carried by the locally installed source
// at C:/Program Files/Go/src/crypto/hkdf/hkdf_test.go; crypto/hkdf is available
// from Go 1.24. The oracle does not call crypto/hkdf or a production helper.
func TestKeyScheduleReferenceOracleRFC5869Vector(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := mustDecodeHex(t, "000102030405060708090a0b0c")
	info := mustDecodeHex(t, "f0f1f2f3f4f5f6f7f8f9")
	prk := manualHKDFExtractSHA256(ikm, salt)
	assertBytesEqual(t, "RFC5869 case 1 PRK", prk, mustDecodeHex(t,
		"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"))
	okm := manualHKDFExpandSHA256(prk, info, 42)
	assertBytesEqual(t, "RFC5869 case 1 OKM", okm, mustDecodeHex(t,
		"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"+
			"34007208d5b887185865"))
}

func TestPolicyMatrixOwnerWitnessLiteralKeyScheduleSentinelV1(t *testing.T) {
	caseID := "pm-owner:suite/kdf_hkdf_sha256"
	base := vectorScheduleInput()
	valid, err := DeriveKeyScheduleV1(base)
	if err != nil || len(valid.ClientWriteKey) != keyScheduleKeyBytes || len(valid.ClientNonceBase) != keyScheduleNonceBytes {
		t.Fatalf("%s valid KDF owner reached=%#v err=%v", caseID, valid, err)
	}
	valid.Destroy()
	for _, tc := range []struct {
		name   string
		mutate func(*KeyScheduleInput)
		cause  error
	}{
		{"application-secret-length", func(v *KeyScheduleInput) { v.ApplicationSecret = v.ApplicationSecret[:31] }, ErrInvalidConfig},
		{"transcript-length", func(v *KeyScheduleInput) { v.TranscriptHash = v.TranscriptHash[:31] }, ErrInvalidTranscript},
		{"KDF-suite", func(v *KeyScheduleInput) { v.Suite.KDF = "unknown" }, ErrInvalidSuite},
	} {
		t.Run(caseID+"/"+tc.name, func(t *testing.T) {
			input := vectorScheduleInput()
			mutations := 0
			tc.mutate(&input)
			mutations++
			_, actual := DeriveKeyScheduleV1(input)
			if mutations != 1 || actual == nil || !errors.Is(actual, ErrKDFInvalid) || !errors.Is(actual, tc.cause) || actual.Error() != "kdf_invalid" {
				t.Fatalf("mutations=%d error=%v cause=%v", mutations, actual, tc.cause)
			}
		})
	}
}

func TestKeyScheduleV1VectorEpochZeroAndOne(t *testing.T) {
	vector := manualProjectVector()
	for name, item := range map[string]struct {
		got  []byte
		want string
	}{
		"handshake salt":   {vector.handshakeSalt, "8917f989222f630909aa354cc3e4c970fbe94ad0858c4c1a66535c798e43c5b3"},
		"handshake PRK":    {vector.handshakePRK, "f026023d3f9fa683fb20424b1fab17d4b12c4cf9724ef44a04b12d9687697282"},
		"application salt": {vector.applicationSalt, "ca3af6fb5c5a13f7ba6b9876ce4396f241197bd77ed41bddd5e054600e75e77a"},
		"epoch PRK 0":      {vector.epochPRK0, "a4cd590ccb61771311d4fe1c81304015c182bdfebad18c808019963d85652c87"},
		"next salt":        {vector.nextSalt, "cb30bea151da286e1bfe18b2bb10b919319427d2564182481acf6bb1cc2ea2ba"},
		"epoch PRK 1":      {vector.epochPRK1, "5c6d141e5236854d7b658a77a3a9ef3a90b406984ade50f5acf2fd631a72b6f9"},
	} {
		assertBytesEqual(t, name, item.got, mustDecodeHex(t, item.want))
	}

	// These project constants were cross-derived with an independent local .NET
	// HMAC-SHA256 implementation; epoch 0 also matches the repository's prior
	// frozen key-schedule vector.
	epoch0Want := fixedScheduleVector{
		clientKey:   "bb45c7926e9ffc26430a589a0dba3fc36b01c05f51663ec5d5dfa1da4e3f103f",
		serverKey:   "867b20adb0075b714b5c6ff4450790463eb763c14f587b231a9abe0e8e368431",
		clientNonce: "9a82475a1929c9f333ab769c",
		serverNonce: "98a074755c9e48deaa89e071",
		exporter:    "817caaecab812449fe6fbf2cb5ee8a615b9b73aad6ffe31165ef1aa3f960acc2",
		rekey:       "ad54f9d229f229e0a6b56ba1f374a8611e16ef99ff38691a3de01fab94dae598",
	}
	epoch1Want := fixedScheduleVector{
		clientKey:   "72ec7d696db153a626c53b8ef1ccdd403121c6269e365fdf87d743e75842df37",
		serverKey:   "ad74a529d8c0529a997b41c17f715899a21da956012701d9549637201dcb2dcd",
		clientNonce: "5d5c260c7d1314129290454d",
		serverNonce: "5e3d60181390c87f81bfa263",
		exporter:    "5d283809d01071c7bf1a9603cce1acad1573447016bd4c88c71c8b86cb9a28b7",
		rekey:       "0e04654654837e132e0eaeded7ac15e7c8fdcd2555057a0c7ad341601af6eb3f",
	}
	assertManualScheduleVector(t, "manual epoch 0", vector.epoch0, epoch0Want)
	assertManualScheduleVector(t, "manual epoch 1", vector.epoch1, epoch1Want)

	ownedApplicationSecret := append([]byte(nil), vector.epochPRK0...)
	got0, err := DeriveKeyScheduleV1(KeyScheduleInput{
		ApplicationSecret: ownedApplicationSecret,
		TranscriptHash:    append([]byte(nil), vector.transcript...),
		Suite:             DefaultSuite(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !allBytesZero(ownedApplicationSecret) {
		t.Fatal("DeriveKeyScheduleV1 did not wipe the transferred application secret")
	}
	if got0.Epoch != 0 {
		t.Fatalf("epoch = %d, want 0", got0.Epoch)
	}
	assertKeyScheduleVector(t, "production epoch 0", got0, epoch0Want)
	assertScheduleMatchesManual(t, "production/manual epoch 0", got0, vector.epoch0)

	got1, err := RatchetKeyScheduleV1(got0)
	if err != nil {
		t.Fatal(err)
	}
	if got1.Epoch != 1 {
		t.Fatalf("epoch = %d, want 1", got1.Epoch)
	}
	assertKeyScheduleVector(t, "production epoch 1", got1, epoch1Want)
	assertScheduleMatchesManual(t, "production/manual epoch 1", got1, vector.epoch1)
}

type manualProjectVectorValues struct {
	transcript      []byte
	handshakeSalt   []byte
	handshakePRK    []byte
	applicationSalt []byte
	epochPRK0       []byte
	nextSalt        []byte
	epochPRK1       []byte
	epoch0          manualScheduleVector
	epoch1          manualScheduleVector
}

type manualScheduleVector struct {
	clientKey   []byte
	serverKey   []byte
	clientNonce []byte
	serverNonce []byte
	exporter    []byte
	rekey       []byte
}

type fixedScheduleVector struct {
	clientKey   string
	serverKey   string
	clientNonce string
	serverNonce string
	exporter    string
	rekey       string
}

func manualProjectVector() manualProjectVectorValues {
	dh := vectorRange(0x00)
	profileHash := vectorRange(0x20)
	clientNonce := vectorRange(0x40)
	serverNonce := vectorRange(0x60)
	clientPublic := vectorRange(0x80)
	serverPublic := vectorRange(0xa0)
	transcript := vectorRange(0xc0)

	handshakeSalt := manualDomainHash("kurdistan/hkdf/v1/handshake-salt",
		profileHash, clientNonce, serverNonce, clientPublic, serverPublic)
	handshakePRK := manualHKDFExtractSHA256(dh, handshakeSalt)
	applicationSalt := manualDomainHash("kurdistan/hkdf/v1/application-salt", transcript, profileHash)
	epochPRK0 := manualHKDFExtractSHA256(handshakePRK, applicationSalt)
	epoch0 := manualDeriveSchedule(epochPRK0, transcript, 0)
	next := manualU64(1)
	nextSalt := manualDomainHash("kurdistan/hkdf/v1/rekey-salt", transcript, next)
	epochPRK1 := manualHKDFExtractSHA256(epoch0.rekey, nextSalt)
	epoch1 := manualDeriveSchedule(epochPRK1, transcript, 1)
	return manualProjectVectorValues{
		transcript:      transcript,
		handshakeSalt:   handshakeSalt,
		handshakePRK:    handshakePRK,
		applicationSalt: applicationSalt,
		epochPRK0:       epochPRK0,
		nextSalt:        nextSalt,
		epochPRK1:       epochPRK1,
		epoch0:          epoch0,
		epoch1:          epoch1,
	}
}

func manualDeriveSchedule(prk, transcript []byte, epoch uint64) manualScheduleVector {
	return manualScheduleVector{
		clientKey:   manualHKDFExpandSHA256(prk, manualScheduleInfo("kurdistan/hkdf/v1/c2s-key", transcript, epoch), 32),
		serverKey:   manualHKDFExpandSHA256(prk, manualScheduleInfo("kurdistan/hkdf/v1/s2c-key", transcript, epoch), 32),
		clientNonce: manualHKDFExpandSHA256(prk, manualScheduleInfo("kurdistan/hkdf/v1/c2s-nonce", transcript, epoch), 12),
		serverNonce: manualHKDFExpandSHA256(prk, manualScheduleInfo("kurdistan/hkdf/v1/s2c-nonce", transcript, epoch), 12),
		exporter:    manualHKDFExpandSHA256(prk, manualScheduleInfo("kurdistan/hkdf/v1/exporter", transcript, epoch), 32),
		rekey:       manualHKDFExpandSHA256(prk, manualScheduleInfo("kurdistan/hkdf/v1/rekey", transcript, epoch), 32),
	}
}

func manualHKDFExtractSHA256(secret, salt []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(secret)
	return mac.Sum(nil)
}

func manualHKDFExpandSHA256(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		out = append(out, previous...)
	}
	return append([]byte(nil), out[:length]...)
}

func manualDomainHash(label string, parts ...[]byte) []byte {
	encoded := manualLP([]byte(label))
	for _, part := range parts {
		encoded = append(encoded, manualLP(part)...)
	}
	sum := sha256.Sum256(encoded)
	return append([]byte(nil), sum[:]...)
}

func manualScheduleInfo(label string, transcript []byte, epoch uint64) []byte {
	encoded := manualLP([]byte(label))
	encoded = append(encoded, transcript...)
	return append(encoded, manualU64(epoch)...)
}

func manualLP(value []byte) []byte {
	encoded := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint32(encoded, uint32(len(value)))
	return append(encoded, value...)
}

func manualU64(value uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return encoded
}

func assertKeyScheduleVector(t *testing.T, name string, got KeySchedule, want fixedScheduleVector) {
	t.Helper()
	assertBytesEqual(t, name+" client key", got.ClientWriteKey, mustDecodeHex(t, want.clientKey))
	assertBytesEqual(t, name+" server key", got.ServerWriteKey, mustDecodeHex(t, want.serverKey))
	assertBytesEqual(t, name+" client nonce", got.ClientNonceBase, mustDecodeHex(t, want.clientNonce))
	assertBytesEqual(t, name+" server nonce", got.ServerNonceBase, mustDecodeHex(t, want.serverNonce))
	assertBytesEqual(t, name+" exporter", got.ExporterSecret, mustDecodeHex(t, want.exporter))
	assertBytesEqual(t, name+" rekey", got.rekeySecret, mustDecodeHex(t, want.rekey))
}

func assertManualScheduleVector(t *testing.T, name string, got manualScheduleVector, want fixedScheduleVector) {
	t.Helper()
	assertBytesEqual(t, name+" client key", got.clientKey, mustDecodeHex(t, want.clientKey))
	assertBytesEqual(t, name+" server key", got.serverKey, mustDecodeHex(t, want.serverKey))
	assertBytesEqual(t, name+" client nonce", got.clientNonce, mustDecodeHex(t, want.clientNonce))
	assertBytesEqual(t, name+" server nonce", got.serverNonce, mustDecodeHex(t, want.serverNonce))
	assertBytesEqual(t, name+" exporter", got.exporter, mustDecodeHex(t, want.exporter))
	assertBytesEqual(t, name+" rekey", got.rekey, mustDecodeHex(t, want.rekey))
}

func assertScheduleMatchesManual(t *testing.T, name string, got KeySchedule, want manualScheduleVector) {
	t.Helper()
	assertBytesEqual(t, name+" client key", got.ClientWriteKey, want.clientKey)
	assertBytesEqual(t, name+" server key", got.ServerWriteKey, want.serverKey)
	assertBytesEqual(t, name+" client nonce", got.ClientNonceBase, want.clientNonce)
	assertBytesEqual(t, name+" server nonce", got.ServerNonceBase, want.serverNonce)
	assertBytesEqual(t, name+" exporter", got.ExporterSecret, want.exporter)
	assertBytesEqual(t, name+" rekey", got.rekeySecret, want.rekey)
}

func assertBytesEqual(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %x, want %x", name, got, want)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func allBytesZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func vectorRange(start byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func TestKeyScheduleV1OwnershipAndDestruction(t *testing.T) {
	input := vectorScheduleInput()
	originalSecret := append([]byte(nil), input.ApplicationSecret...)
	var internalSecret []byte
	schedule, err := deriveKeyScheduleV1(input, func(secret []byte) {
		internalSecret = secret
	})
	if err != nil {
		t.Fatal(err)
	}
	if !allBytesZero(input.ApplicationSecret) {
		t.Fatal("successful derivation did not wipe transferred application secret")
	}
	if len(internalSecret) != sha256.Size || !allBytesZero(internalSecret) {
		t.Fatal("successful derivation did not wipe its internal application-secret copy")
	}
	if allBytesZero(originalSecret) {
		t.Fatal("test vector unexpectedly contained an all-zero application secret")
	}
	forcedInput := vectorScheduleInput()
	forcedOwned := forcedInput.ApplicationSecret
	var forcedInternal []byte
	var forcedPartial [][]byte
	forcedCalls := 0
	forcedExpand := func(_ []byte, _ string, _ [sha256.Size]byte, _ uint64, length int) ([]byte, error) {
		forcedCalls++
		if forcedCalls == 3 {
			return nil, errors.New("forced initial expand failure")
		}
		value := bytes.Repeat([]byte{byte(forcedCalls)}, length)
		forcedPartial = append(forcedPartial, value)
		return value, nil
	}
	failed, err := deriveKeyScheduleV1WithExpand(forcedInput, func(secret []byte) {
		forcedInternal = secret
	}, forcedExpand)
	assertKDFError(t, err, ErrInvalidConfig)
	if !reflect.DeepEqual(failed, KeySchedule{}) {
		t.Fatalf("failed initial derivation returned partial schedule: %#v", failed)
	}
	if !allBytesZero(forcedOwned) || len(forcedInternal) != sha256.Size || !allBytesZero(forcedInternal) {
		t.Fatal("failed initial derivation did not wipe caller and internal application secrets")
	}
	for index, output := range forcedPartial {
		if !allBytesZero(output) {
			t.Fatalf("failed initial derivation did not wipe partial output %d", index)
		}
	}

	for _, tc := range []struct {
		name      string
		mutate    func(*KeyScheduleInput)
		wantCause error
	}{
		{"bad_application_secret", func(in *KeyScheduleInput) { in.ApplicationSecret = bytes.Repeat([]byte{0x41}, 31) }, ErrInvalidConfig},
		{"bad_transcript", func(in *KeyScheduleInput) { in.TranscriptHash = nil }, ErrInvalidTranscript},
		{"bad_suite", func(in *KeyScheduleInput) { in.Suite.KDF = "unknown" }, ErrInvalidSuite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := vectorScheduleInput()
			tc.mutate(&bad)
			owned := bad.ApplicationSecret
			_, err := DeriveKeyScheduleV1(bad)
			assertKDFError(t, err, tc.wantCause)
			if !allBytesZero(owned) {
				t.Fatal("failed derivation did not wipe transferred application secret")
			}
		})
	}

	aliases := [][]byte{
		schedule.ClientWriteKey,
		schedule.ServerWriteKey,
		schedule.ClientNonceBase,
		schedule.ServerNonceBase,
		schedule.ExporterSecret,
		schedule.rekeySecret,
	}
	schedule.Destroy()
	if !reflect.DeepEqual(schedule, KeySchedule{}) {
		t.Fatalf("Destroy left schedule state: %#v", schedule)
	}
	for index, alias := range aliases {
		if !allBytesZero(alias) {
			t.Fatalf("Destroy did not wipe output %d", index)
		}
	}
	schedule.Destroy()
	var nilSchedule *KeySchedule
	nilSchedule.Destroy()
}

func TestKeyScheduleV1InputAndOutputLimits(t *testing.T) {
	validPRK := mustDecodeHex(t, "a4cd590ccb61771311d4fe1c81304015c182bdfebad18c808019963d85652c87")
	var transcript [sha256.Size]byte
	copy(transcript[:], vectorRange(0xc0))
	for _, output := range []struct {
		label  string
		length int
	}{
		{keyLabelC2SKey, keyScheduleKeyBytes},
		{keyLabelS2CKey, keyScheduleKeyBytes},
		{keyLabelC2SNonce, keyScheduleNonceBytes},
		{keyLabelS2CNonce, keyScheduleNonceBytes},
		{keyLabelExporter, keyScheduleKeyBytes},
		{keyLabelRekey, keyScheduleKeyBytes},
	} {
		value, err := expandKeyScheduleV1(validPRK, output.label, transcript, 0, output.length)
		if err != nil || len(value) != output.length {
			t.Fatalf("valid %s output: len=%d err=%v", output.label, len(value), err)
		}
		for _, length := range []int{-1, 0, output.length - 1, output.length + 1, 255*sha256.Size + 1, math.MaxInt} {
			value, err := expandKeyScheduleV1(validPRK, output.label, transcript, 0, length)
			assertKDFError(t, err, ErrInvalidConfig)
			if value != nil {
				t.Fatalf("invalid output length %d returned key material", length)
			}
		}
	}
	if value, err := expandKeyScheduleV1(validPRK, "kurdistan/hkdf/v1/unknown", transcript, 0, keyScheduleKeyBytes); value != nil {
		t.Fatal("unknown label returned key material")
	} else {
		assertKDFError(t, err, ErrInvalidConfig)
	}

	for name, prk := range map[string][]byte{
		"nil":      nil,
		"short":    bytes.Repeat([]byte{1}, sha256.Size-1),
		"long":     bytes.Repeat([]byte{1}, sha256.Size+1),
		"all_zero": make([]byte, sha256.Size),
	} {
		t.Run("prk_"+name, func(t *testing.T) {
			value, err := expandKeyScheduleV1(prk, keyLabelC2SKey, transcript, 0, keyScheduleKeyBytes)
			assertKDFError(t, err, ErrInvalidConfig)
			if value != nil {
				t.Fatal("malformed PRK returned key material")
			}
		})
	}
	if value, err := expandKeyScheduleV1(validPRK, keyLabelC2SKey, [sha256.Size]byte{}, 0, keyScheduleKeyBytes); value != nil {
		t.Fatal("zero transcript returned key material")
	} else {
		assertKDFError(t, err, ErrInvalidTranscript)
	}

	for name, mutate := range map[string]func(*KeyScheduleInput){
		"nil_secret":   func(in *KeyScheduleInput) { in.ApplicationSecret = nil },
		"short_secret": func(in *KeyScheduleInput) { in.ApplicationSecret = bytes.Repeat([]byte{1}, sha256.Size-1) },
		"long_secret":  func(in *KeyScheduleInput) { in.ApplicationSecret = bytes.Repeat([]byte{1}, sha256.Size+1) },
		"zero_secret":  func(in *KeyScheduleInput) { in.ApplicationSecret = make([]byte, sha256.Size) },
		"nil_th4":      func(in *KeyScheduleInput) { in.TranscriptHash = nil },
		"short_th4":    func(in *KeyScheduleInput) { in.TranscriptHash = bytes.Repeat([]byte{1}, sha256.Size-1) },
		"long_th4":     func(in *KeyScheduleInput) { in.TranscriptHash = bytes.Repeat([]byte{1}, sha256.Size+1) },
		"zero_th4":     func(in *KeyScheduleInput) { in.TranscriptHash = make([]byte, sha256.Size) },
	} {
		t.Run(name, func(t *testing.T) {
			input := vectorScheduleInput()
			mutate(&input)
			owned := input.ApplicationSecret
			_, err := DeriveKeyScheduleV1(input)
			want := ErrInvalidConfig
			if strings.Contains(name, "th4") {
				want = ErrInvalidTranscript
			}
			assertKDFError(t, err, want)
			if !allBytesZero(owned) {
				t.Fatal("invalid input did not consume owned secret")
			}
		})
	}

	invalidAll := vectorScheduleInput()
	invalidAll.ApplicationSecret = nil
	invalidAll.TranscriptHash = nil
	invalidAll.Suite.KDF = "unknown"
	_, err := DeriveKeyScheduleV1(invalidAll)
	assertKDFError(t, err, ErrInvalidConfig)
	invalidTranscriptAndSuite := vectorScheduleInput()
	invalidTranscriptAndSuite.TranscriptHash = nil
	invalidTranscriptAndSuite.Suite.KDF = "unknown"
	_, err = DeriveKeyScheduleV1(invalidTranscriptAndSuite)
	assertKDFError(t, err, ErrInvalidTranscript)
	invalidSuite := vectorScheduleInput()
	invalidSuite.Suite.KDF = "unknown"
	_, err = DeriveKeyScheduleV1(invalidSuite)
	assertKDFError(t, err, ErrInvalidSuite)
}

func TestKeyScheduleV1DerivationAndSeparation(t *testing.T) {
	first := deriveVectorSchedule(t)
	second := deriveVectorSchedule(t)
	if !keySchedulesEqual(first, second) {
		t.Fatal("identical inputs did not reproduce the key schedule")
	}
	assertScheduleDomainsSeparated(t, first)

	next, err := RatchetKeyScheduleV1(first)
	if err != nil {
		t.Fatal(err)
	}
	assertScheduleDomainsSeparated(t, next)
	assertEveryOutputChanged(t, "epoch", first, next)

	secretChangedInput := vectorScheduleInput()
	secretChangedInput.ApplicationSecret[0] ^= 0xff
	secretChanged, err := DeriveKeyScheduleV1(secretChangedInput)
	if err != nil {
		t.Fatal(err)
	}
	assertEveryOutputChanged(t, "application secret", first, secretChanged)
	transcriptChangedInput := vectorScheduleInput()
	transcriptChangedInput.TranscriptHash[0] ^= 0xff
	transcriptChanged, err := DeriveKeyScheduleV1(transcriptChangedInput)
	if err != nil {
		t.Fatal(err)
	}
	assertEveryOutputChanged(t, "TH4/policy", first, transcriptChanged)

	baseRaw := rawProjectVector()
	basePRK := manualEpochZeroPRK(baseRaw)
	baseSchedule, err := DeriveKeyScheduleV1(KeyScheduleInput{
		ApplicationSecret: append([]byte(nil), basePRK...),
		TranscriptHash:    append([]byte(nil), baseRaw.transcript[:]...),
		Suite:             DefaultSuite(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name   string
		mutate func(*rawFormulaVector)
	}{
		{"profile", func(v *rawFormulaVector) { v.profileHash[0] ^= 1 }},
		{"client_nonce", func(v *rawFormulaVector) { v.clientNonce[0] ^= 1 }},
		{"server_nonce", func(v *rawFormulaVector) { v.serverNonce[0] ^= 1 }},
		{"client_share", func(v *rawFormulaVector) { v.clientPublic[0] ^= 1 }},
		{"server_share", func(v *rawFormulaVector) { v.serverPublic[0] ^= 1 }},
		{"role_order", func(v *rawFormulaVector) {
			v.clientNonce, v.serverNonce = v.serverNonce, v.clientNonce
			v.clientPublic, v.serverPublic = v.serverPublic, v.clientPublic
		}},
		{"transcript", func(v *rawFormulaVector) { v.transcript[0] ^= 1 }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changedRaw := baseRaw
			mutation.mutate(&changedRaw)
			changedPRK := manualEpochZeroPRK(changedRaw)
			changed, err := DeriveKeyScheduleV1(KeyScheduleInput{
				ApplicationSecret: changedPRK,
				TranscriptHash:    changedRaw.transcript[:],
				Suite:             DefaultSuite(),
			})
			if err != nil {
				t.Fatal(err)
			}
			assertEveryOutputChanged(t, mutation.name, baseSchedule, changed)
		})
	}
}

func TestKeyScheduleV1RatchetLimitsAndFailureWipes(t *testing.T) {
	current := deriveVectorSchedule(t)
	before := cloneKeySchedule(current)
	var observedSuccess []byte
	next, err := ratchetKeyScheduleV1(current, func(prk []byte) {
		observedSuccess = prk
	}, expandKeyScheduleV1)
	if err != nil {
		t.Fatal(err)
	}
	if len(observedSuccess) != sha256.Size || !allBytesZero(observedSuccess) {
		t.Fatal("successful ratchet did not wipe next epoch PRK")
	}
	if !keySchedulesEqual(current, before) {
		t.Fatal("ratchet mutated or wiped the current schedule before lifecycle commit")
	}
	if next.Epoch != current.Epoch+1 {
		t.Fatalf("ratchet epoch = %d, want %d", next.Epoch, current.Epoch+1)
	}

	var observedFailure []byte
	var partialOutputs [][]byte
	expandCalls := 0
	forcedExpand := func(_ []byte, _ string, _ [sha256.Size]byte, _ uint64, length int) ([]byte, error) {
		expandCalls++
		if expandCalls == 3 {
			return nil, errors.New("forced test failure")
		}
		value := bytes.Repeat([]byte{byte(expandCalls)}, length)
		partialOutputs = append(partialOutputs, value)
		return value, nil
	}
	failed, err := ratchetKeyScheduleV1(current, func(prk []byte) {
		observedFailure = prk
	}, forcedExpand)
	assertKDFError(t, err, ErrInvalidConfig)
	if !reflect.DeepEqual(failed, KeySchedule{}) {
		t.Fatalf("failed ratchet returned partial schedule: %#v", failed)
	}
	if len(observedFailure) != sha256.Size || !allBytesZero(observedFailure) {
		t.Fatal("failed ratchet did not wipe next epoch PRK")
	}
	for index, output := range partialOutputs {
		if !allBytesZero(output) {
			t.Fatalf("failed ratchet did not wipe partial output %d", index)
		}
	}
	if !keySchedulesEqual(current, before) {
		t.Fatal("failed ratchet mutated or wiped the current schedule")
	}

	correspondingCurrent := [][]byte{
		current.ClientWriteKey,
		current.ServerWriteKey,
		current.ClientNonceBase,
		current.ServerNonceBase,
		current.ExporterSecret,
		current.rekeySecret,
	}
	var observedCollapsedPRK []byte
	var collapsedOutputs [][]byte
	collapsedIndex := 0
	collapsedExpand := func(_ []byte, _ string, _ [sha256.Size]byte, _ uint64, length int) ([]byte, error) {
		if collapsedIndex >= len(correspondingCurrent) || len(correspondingCurrent[collapsedIndex]) != length {
			return nil, errors.New("unexpected collapsed-output request")
		}
		value := append([]byte(nil), correspondingCurrent[collapsedIndex]...)
		collapsedOutputs = append(collapsedOutputs, value)
		collapsedIndex++
		return value, nil
	}
	collapsed, err := ratchetKeyScheduleV1(current, func(prk []byte) {
		observedCollapsedPRK = prk
	}, collapsedExpand)
	assertKDFError(t, err, ErrInvalidConfig)
	if !reflect.DeepEqual(collapsed, KeySchedule{}) {
		t.Fatalf("cross-epoch collapse returned schedule: %#v", collapsed)
	}
	if len(observedCollapsedPRK) != sha256.Size || !allBytesZero(observedCollapsedPRK) {
		t.Fatal("cross-epoch collapse did not wipe next epoch PRK")
	}
	if collapsedIndex != len(correspondingCurrent) {
		t.Fatalf("cross-epoch collapse expanded %d outputs, want %d", collapsedIndex, len(correspondingCurrent))
	}
	for index, output := range collapsedOutputs {
		if !allBytesZero(output) {
			t.Fatalf("cross-epoch collapse did not wipe pending output %d", index)
		}
	}
	if !keySchedulesEqual(current, before) {
		t.Fatal("cross-epoch collapse mutated or wiped the current schedule")
	}

	for _, tc := range []struct {
		name      string
		mutate    func(*KeySchedule)
		wantCause error
	}{
		{"legacy", func(k *KeySchedule) { k.exactV1 = false }, ErrInvalidConfig},
		{"skipped_epoch", func(k *KeySchedule) { k.Epoch += 2 }, ErrInvalidConfig},
		{"bound_epoch", func(k *KeySchedule) { k.boundEpoch++ }, ErrInvalidConfig},
		{"suite", func(k *KeySchedule) { k.Suite.KDF = "unknown" }, ErrInvalidSuite},
		{"transcript", func(k *KeySchedule) { k.transcriptHash = [sha256.Size]byte{} }, ErrInvalidTranscript},
		{"client_key", func(k *KeySchedule) { k.ClientWriteKey = nil }, ErrInvalidConfig},
		{"server_key", func(k *KeySchedule) { k.ServerWriteKey = nil }, ErrInvalidConfig},
		{"client_nonce", func(k *KeySchedule) { k.ClientNonceBase = nil }, ErrInvalidConfig},
		{"server_nonce", func(k *KeySchedule) { k.ServerNonceBase = nil }, ErrInvalidConfig},
		{"exporter", func(k *KeySchedule) { k.ExporterSecret = nil }, ErrInvalidConfig},
		{"rekey", func(k *KeySchedule) { k.rekeySecret = nil }, ErrInvalidConfig},
		{"zero_key", func(k *KeySchedule) { k.ClientWriteKey = make([]byte, keyScheduleKeyBytes) }, ErrInvalidConfig},
		{"zero_nonce", func(k *KeySchedule) { k.ClientNonceBase = make([]byte, keyScheduleNonceBytes) }, ErrInvalidConfig},
		{"collapsed_key", func(k *KeySchedule) { k.ServerWriteKey = append([]byte(nil), k.ClientWriteKey...) }, ErrInvalidConfig},
		{"collapsed_nonce", func(k *KeySchedule) { k.ServerNonceBase = append([]byte(nil), k.ClientNonceBase...) }, ErrInvalidConfig},
		{"overflow", func(k *KeySchedule) { k.Epoch, k.boundEpoch = math.MaxUint64, math.MaxUint64 }, ErrInvalidConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := cloneKeySchedule(current)
			tc.mutate(&invalid)
			unchanged := cloneKeySchedule(invalid)
			result, err := RatchetKeyScheduleV1(invalid)
			assertKDFError(t, err, tc.wantCause)
			if !reflect.DeepEqual(result, KeySchedule{}) {
				t.Fatalf("invalid ratchet returned schedule: %#v", result)
			}
			if !keySchedulesEqual(invalid, unchanged) {
				t.Fatal("invalid ratchet mutated its source")
			}
		})
	}
}

func TestLegacyKeyScheduleVectorAndExactV1Rejection(t *testing.T) {
	secret := []byte("legacy byte compatibility secret")
	transcript := strings.Repeat("a", 64)
	legacy, err := DeriveKeySchedule(secret, transcript, DefaultSuite())
	if err != nil {
		t.Fatal(err)
	}
	for name, vector := range map[string]struct {
		got  []byte
		want string
	}{
		"client_write":      {legacy.ClientWriteKey, "3f2242fe87bc0065e8d42632f38d4fbbba97044c7151dd9c0d2b424712186e07"},
		"server_write":      {legacy.ServerWriteKey, "e8aabd79a4bbcc3f2d2054da521d4ee152af1e43207ef6acf2279c4c2ed4702a"},
		"client_nonce_base": {legacy.ClientNonceBase, "c294f3a48d85eaa9bf52084b"},
		"server_nonce_base": {legacy.ServerNonceBase, "30185dfceabe2e46b9f99c08"},
		"exporter_secret":   {legacy.ExporterSecret, "03f2a5ff1d72e48a4a1986ec45f7733bc67a73bf410535a5fb0184b70db80af6"},
	} {
		if want := mustDecodeHex(t, vector.want); !bytes.Equal(vector.got, want) {
			t.Fatalf("legacy %s = %x, want %x", name, vector.got, want)
		}
	}
	if legacy.exactV1 || legacy.rekeySecret != nil {
		t.Fatal("legacy compatibility schedule was marked as exact v1")
	}
	if _, err := RatchetKeyScheduleV1(legacy); err == nil {
		t.Fatal("legacy compatibility schedule ratcheted as exact v1")
	} else {
		assertKDFError(t, err, ErrInvalidConfig)
	}
	if _, err := DeriveKeySchedule(make([]byte, 32), transcript, DefaultSuite()); err != nil {
		t.Fatalf("legacy all-zero input behavior drifted: %v", err)
	}
	trace, err := json.Marshal(KeyScheduleTrace(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(trace, []byte("rekey_secret")) {
		t.Fatalf("legacy trace shape drifted: %s", trace)
	}
}

func TestKeyScheduleV1TraceJSONAndErrorHygiene(t *testing.T) {
	input := vectorScheduleInput()
	applicationSecret := append([]byte(nil), input.ApplicationSecret...)
	schedule, err := DeriveKeyScheduleV1(input)
	if err != nil {
		t.Fatal(err)
	}
	jsonInput := vectorScheduleInput()
	inputJSON, err := json.Marshal(jsonInput)
	if err != nil {
		t.Fatal(err)
	}
	scheduleJSON, err := json.Marshal(schedule)
	if err != nil {
		t.Fatal(err)
	}
	traceJSON, err := json.Marshal(KeyScheduleTrace(schedule))
	if err != nil {
		t.Fatal(err)
	}
	formatted := []byte(fmt.Sprintf("%v|%+v|%#v|%v|%+v|%#v", jsonInput, jsonInput, jsonInput, schedule, schedule, schedule))

	badOwned := []byte("application-secret-error-canary-123")
	badCanary := append([]byte(nil), badOwned...)
	_, kdfErr := DeriveKeyScheduleV1(KeyScheduleInput{
		ApplicationSecret: badOwned,
		TranscriptHash:    append([]byte(nil), jsonInput.TranscriptHash...),
		Suite:             DefaultSuite(),
	})
	assertKDFError(t, kdfErr, ErrInvalidConfig)
	if !allBytesZero(badOwned) {
		t.Fatal("error path did not wipe canary secret")
	}
	errorJSON, err := json.Marshal(kdfErr)
	if err != nil {
		t.Fatal(err)
	}
	errorText := []byte(fmt.Sprintf("%v|%+v|%#v|%s", kdfErr, kdfErr, kdfErr, errorJSON))

	surfaces := map[string][]byte{
		"input_json":    inputJSON,
		"schedule_json": scheduleJSON,
		"trace":         traceJSON,
		"formatted":     formatted,
		"error":         errorText,
	}
	secrets := [][]byte{
		applicationSecret,
		jsonInput.TranscriptHash,
		schedule.ClientWriteKey,
		schedule.ServerWriteKey,
		schedule.ClientNonceBase,
		schedule.ServerNonceBase,
		schedule.ExporterSecret,
		schedule.rekeySecret,
		badCanary,
	}
	for surfaceName, surface := range surfaces {
		for secretIndex, secret := range secrets {
			assertNoSecretRepresentation(t, surfaceName, surface, secretIndex, secret)
		}
	}
	if string(errorText) != "kdf_invalid|kdf_invalid|kdf_invalid|{}" {
		t.Fatalf("KDF error exposed detail: %s", errorText)
	}
	if bytes.Contains(inputJSON, []byte(`"application_secret"`)) || bytes.Contains(inputJSON, []byte(`"transcript_hash"`)) {
		t.Fatalf("KeyScheduleInput JSON exposed private fields: %s", inputJSON)
	}
	for _, field := range [][]byte{[]byte(`"epoch"`), []byte(`"client_write_key"`), []byte(`"server_write_key"`), []byte(`"client_nonce_base"`), []byte(`"server_nonce_base"`), []byte(`"exporter_secret"`), []byte(`"rekey_secret"`)} {
		if bytes.Contains(scheduleJSON, field) {
			t.Fatalf("KeySchedule JSON exposed private field %s: %s", field, scheduleJSON)
		}
	}
}

type rawFormulaVector struct {
	sharedSecret [sha256.Size]byte
	profileHash  [sha256.Size]byte
	clientNonce  [sha256.Size]byte
	serverNonce  [sha256.Size]byte
	clientPublic [sha256.Size]byte
	serverPublic [sha256.Size]byte
	transcript   [sha256.Size]byte
}

func rawProjectVector() rawFormulaVector {
	var vector rawFormulaVector
	copy(vector.sharedSecret[:], vectorRange(0x00))
	copy(vector.profileHash[:], vectorRange(0x20))
	copy(vector.clientNonce[:], vectorRange(0x40))
	copy(vector.serverNonce[:], vectorRange(0x60))
	copy(vector.clientPublic[:], vectorRange(0x80))
	copy(vector.serverPublic[:], vectorRange(0xa0))
	copy(vector.transcript[:], vectorRange(0xc0))
	return vector
}

func manualEpochZeroPRK(vector rawFormulaVector) []byte {
	handshakeSalt := manualDomainHash(
		"kurdistan/hkdf/v1/handshake-salt",
		vector.profileHash[:],
		vector.clientNonce[:],
		vector.serverNonce[:],
		vector.clientPublic[:],
		vector.serverPublic[:],
	)
	handshakePRK := manualHKDFExtractSHA256(vector.sharedSecret[:], handshakeSalt)
	applicationSalt := manualDomainHash("kurdistan/hkdf/v1/application-salt", vector.transcript[:], vector.profileHash[:])
	return manualHKDFExtractSHA256(handshakePRK, applicationSalt)
}

func vectorScheduleInput() KeyScheduleInput {
	vector := manualProjectVector()
	return KeyScheduleInput{
		ApplicationSecret: append([]byte(nil), vector.epochPRK0...),
		TranscriptHash:    append([]byte(nil), vector.transcript...),
		Suite:             DefaultSuite(),
	}
}

func deriveVectorSchedule(t *testing.T) KeySchedule {
	t.Helper()
	schedule, err := DeriveKeyScheduleV1(vectorScheduleInput())
	if err != nil {
		t.Fatal(err)
	}
	return schedule
}

func cloneKeySchedule(schedule KeySchedule) KeySchedule {
	schedule.ClientWriteKey = append([]byte(nil), schedule.ClientWriteKey...)
	schedule.ServerWriteKey = append([]byte(nil), schedule.ServerWriteKey...)
	schedule.ClientNonceBase = append([]byte(nil), schedule.ClientNonceBase...)
	schedule.ServerNonceBase = append([]byte(nil), schedule.ServerNonceBase...)
	schedule.ExporterSecret = append([]byte(nil), schedule.ExporterSecret...)
	schedule.rekeySecret = append([]byte(nil), schedule.rekeySecret...)
	return schedule
}

func keySchedulesEqual(left, right KeySchedule) bool {
	return left.Suite == right.Suite &&
		left.Epoch == right.Epoch &&
		left.transcriptHash == right.transcriptHash &&
		left.boundEpoch == right.boundEpoch &&
		left.exactV1 == right.exactV1 &&
		bytes.Equal(left.ClientWriteKey, right.ClientWriteKey) &&
		bytes.Equal(left.ServerWriteKey, right.ServerWriteKey) &&
		bytes.Equal(left.ClientNonceBase, right.ClientNonceBase) &&
		bytes.Equal(left.ServerNonceBase, right.ServerNonceBase) &&
		bytes.Equal(left.ExporterSecret, right.ExporterSecret) &&
		bytes.Equal(left.rekeySecret, right.rekeySecret)
}

func assertScheduleDomainsSeparated(t *testing.T, schedule KeySchedule) {
	t.Helper()
	keys := [][]byte{schedule.ClientWriteKey, schedule.ServerWriteKey, schedule.ExporterSecret, schedule.rekeySecret}
	for left := 0; left < len(keys); left++ {
		for right := left + 1; right < len(keys); right++ {
			if bytes.Equal(keys[left], keys[right]) {
				t.Fatalf("equal-length output domains %d and %d collapsed", left, right)
			}
		}
	}
	if bytes.Equal(schedule.ClientNonceBase, schedule.ServerNonceBase) {
		t.Fatal("client/server nonce domains collapsed")
	}
}

func assertEveryOutputChanged(t *testing.T, mutation string, before, after KeySchedule) {
	t.Helper()
	beforeOutputs := [][]byte{before.ClientWriteKey, before.ServerWriteKey, before.ClientNonceBase, before.ServerNonceBase, before.ExporterSecret, before.rekeySecret}
	afterOutputs := [][]byte{after.ClientWriteKey, after.ServerWriteKey, after.ClientNonceBase, after.ServerNonceBase, after.ExporterSecret, after.rekeySecret}
	for index := range beforeOutputs {
		if bytes.Equal(beforeOutputs[index], afterOutputs[index]) {
			t.Fatalf("%s mutation did not change output %d", mutation, index)
		}
	}
}

func assertKDFError(t *testing.T, err, cause error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected KDF error")
	}
	if !errors.Is(err, ErrKDFInvalid) || !errors.Is(err, cause) {
		t.Fatalf("error %v does not match ErrKDFInvalid and %v", err, cause)
	}
	var typed *KDFError
	if !errors.As(err, &typed) {
		t.Fatalf("error %T is not *KDFError", err)
	}
	if err.Error() != "kdf_invalid" || fmt.Sprintf("%#v", err) != "kdf_invalid" {
		t.Fatalf("KDF error formatting exposed detail: %v / %#v", err, err)
	}
}

func assertNoSecretRepresentation(t *testing.T, surfaceName string, surface []byte, secretIndex int, secret []byte) {
	t.Helper()
	if len(secret) == 0 {
		return
	}
	hexValue := hex.EncodeToString(secret)
	escaped, err := json.Marshal(string(secret))
	if err != nil {
		t.Fatal(err)
	}
	representations := [][]byte{
		secret,
		[]byte(hexValue),
		[]byte(strings.ToUpper(hexValue)),
		[]byte(base64.StdEncoding.EncodeToString(secret)),
		escaped,
		bytes.Trim(escaped, `"`),
	}
	for _, representation := range representations {
		if len(representation) > 0 && bytes.Contains(surface, representation) {
			t.Fatalf("%s leaked representation of secret %d", surfaceName, secretIndex)
		}
	}
}
