// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/cryptotest"
)

func TestMandatoryV1SuiteHasNoFallback(t *testing.T) {
	want := Suite{
		ID:                 SuiteClassicalV1,
		SignatureAlgorithm: COSEAlgorithmES256,
		HPKEMode:           HPKEModeBase,
		HPKEKEM:            HPKEKEMP256SHA256,
		HPKEKDF:            HPKEKDFSHA256,
		HPKEAEAD:           HPKEAEADAES256GCM,
	}
	if got := MandatoryV1Suite(); got != want {
		t.Fatalf("MandatoryV1Suite() = %+v, want %+v", got, want)
	}
	if err := ValidateSuiteID(SuiteClassicalV1); err != nil {
		t.Fatal(err)
	}
	for _, id := range []SuiteID{0, SuiteReservedPQV1, SuiteReservedHybridV1, 0xffff} {
		if err := ValidateSuiteID(id); !errors.Is(err, ErrUnsupportedSuite) {
			t.Fatalf("ValidateSuiteID(0x%04x) = %v, want ErrUnsupportedSuite", id, err)
		}
	}
}

func TestES256RawSignatureIsFixedWidthLowS(t *testing.T) {
	n := p256Order()
	highS := new(big.Int).Sub(n, big.NewInt(1))
	encoded, err := EncodeRawES256Signature(big.NewInt(1), highS)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != ES256RawSignatureSize {
		t.Fatalf("signature size = %d", len(encoded))
	}
	_, s, err := DecodeRawES256Signature(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("normalized S = %v, want 1", s)
	}
	highRaw := make([]byte, ES256RawSignatureSize)
	big.NewInt(1).FillBytes(highRaw[:32])
	highS.FillBytes(highRaw[32:])
	if _, _, err := DecodeRawES256Signature(highRaw); err == nil {
		t.Fatal("accepted high-S signature")
	}
}

func TestHPKEContextBudgetExhaustsAfterOneMessage(t *testing.T) {
	budget := NewHPKEContextBudget()
	if err := budget.Consume(); err != nil {
		t.Fatal(err)
	}
	if err := budget.Consume(); !errors.Is(err, ErrHPKEContextExhausted) {
		t.Fatalf("second Consume() = %v, want ErrHPKEContextExhausted", err)
	}
}

func TestCoreDeterministicCBORRejectsAmbiguity(t *testing.T) {
	valid, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixturePublicMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCoreDeterministicCBOR(valid); err != nil {
		t.Fatal(err)
	}
	overNested := append(bytes.Repeat([]byte{0x81}, MaxCBORNestedLevels+1), 0x00)
	invalid := map[string][]byte{
		"duplicate map key":   {0xa2, 0x01, 0x01, 0x01, 0x02},
		"indefinite array":    {0x9f, 0x01, 0xff},
		"trailing data":       {0x01, 0x02},
		"invalid UTF-8":       {0x61, 0xff},
		"non-minimal integer": {0x18, 0x17},
		"floating point":      {0xf9, 0x3c, 0x00},
		"unapproved tag":      {0xd1, 0x00},
		"bignum":              {0xc2, 0x41, 0x01},
		"excess nesting":      overNested,
		"oversized":           make([]byte, MaxTotalInputBytes+1),
	}
	for name, data := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateCoreDeterministicCBOR(data); err == nil {
				t.Fatal("accepted prohibited CBOR")
			}
		})
	}
}

func TestIssuerSignedMetadataMatchesOuterAfterOpen(t *testing.T) {
	metadata := fixtureDeviceMetadata()
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), metadata)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeRawES256Signature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	signedObject, err := BuildTaggedCOSESign1(protected, []byte{0xa0}, signature)
	if err != nil {
		t.Fatal(err)
	}
	outerProtected, err := BuildSealProtected(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOpenedArtifactMetadataBinding(signedObject, outerProtected); err != nil {
		t.Fatal(err)
	}
}

func TestIssuerSignedMetadataRejectsOuterRewrapBeforeStateUse(t *testing.T) {
	metadata := fixtureDeviceMetadata()
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), metadata)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeRawES256Signature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	signedObject, err := BuildTaggedCOSESign1(protected, []byte{0xa0}, signature)
	if err != nil {
		t.Fatal(err)
	}
	base := map[uint64]any{
		1: string(metadata.Class),
		2: metadata.AudienceClass,
		3: []byte(metadata.RecipientHint),
		4: metadata.RecipientEpoch,
	}
	mutations := map[string]func(map[uint64]any){
		"class":          func(v map[uint64]any) { v[1] = string(ArtifactProviderGroup) },
		"audience":       func(v map[uint64]any) { v[2] = AudienceProvisionedGroup },
		"recipient hint": func(v map[uint64]any) { v[3] = []byte("fixture_hint_changed") },
		"recipient epoch": func(v map[uint64]any) {
			v[4] = metadata.RecipientEpoch + 1
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fields := make(map[uint64]any, len(base))
			for key, value := range base {
				fields[key] = value
			}
			mutate(fields)
			metadataBytes, err := marshalDeterministic(fields)
			if err != nil {
				t.Fatal(err)
			}
			outerProtected, err := marshalDeterministic(map[uint64]any{
				1: SealFormatVersion,
				2: uint64(SuiteClassicalV1),
				3: SignedObjectContentType,
				4: metadataBytes,
			})
			if err != nil {
				t.Fatal(err)
			}
			stateUses := 0
			if err := ValidateOpenedArtifactMetadataBinding(signedObject, outerProtected); err == nil {
				// State use belongs strictly after this fail-closed check.
				stateUses++
			} else if !errors.Is(err, ErrMetadataMismatch) {
				t.Fatalf("rewrap error = %v, want ErrMetadataMismatch", err)
			}
			if stateUses != 0 {
				t.Fatalf("rewrapped metadata reached state %d times", stateUses)
			}
		})
	}
}

func TestOpenedArtifactMetadataBindingRejectsSignedPublicInSealedOuter(t *testing.T) {
	metadata := fixturePublicMetadata()
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), metadata)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeRawES256Signature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	signedObject, err := BuildTaggedCOSESign1(protected, []byte{0xa0}, signature)
	if err != nil {
		t.Fatal(err)
	}
	metadataBytes, err := BuildArtifactMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	craftedOuter, err := marshalDeterministic(map[uint64]any{
		1: SealFormatVersion,
		2: uint64(SuiteClassicalV1),
		3: SignedObjectContentType,
		4: metadataBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOpenedArtifactMetadataBinding(signedObject, craftedOuter); err == nil || !strings.Contains(err.Error(), "signed-public") {
		t.Fatalf("sealed signed-public metadata error = %v", err)
	}
}

func TestSignedAndSealedMarshaledSizeBoundaries(t *testing.T) {
	signature, err := EncodeRawES256Signature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, MaxPayloadBytes)
	protectedAtBoundary := make([]byte, 4019)
	signed, err := BuildTaggedCOSESign1(protectedAtBoundary, payload, signature)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed) != MaxSignedObjectBytes {
		t.Fatalf("signed boundary = %d bytes, want %d", len(signed), MaxSignedObjectBytes)
	}
	if _, err := BuildTaggedCOSESign1(make([]byte, len(protectedAtBoundary)+1), payload, signature); !errors.Is(err, ErrArtifactSizeLimit) {
		t.Fatalf("signed one-over error = %v, want ErrArtifactSizeLimit", err)
	}
	if _, err := BuildTaggedCOSESign1([]byte{0xa0}, make([]byte, MaxPayloadBytes+1), signature); err == nil {
		t.Fatal("payload one-over accepted")
	}

	outerProtected := make([]byte, MaxOuterProtectedBytes)
	enc := make([]byte, HPKEP256EncSize)
	ciphertextAtBoundary := make([]byte, MaxCiphertextBytes-1)
	sealed, err := BuildSealedFrame(outerProtected, enc, ciphertextAtBoundary)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != MaxSealedFrameBytes {
		t.Fatalf("sealed boundary = %d bytes, want %d", len(sealed), MaxSealedFrameBytes)
	}
	if _, err := BuildSealedFrame(outerProtected, enc, make([]byte, MaxCiphertextBytes)); !errors.Is(err, ErrArtifactSizeLimit) {
		t.Fatalf("sealed one-over error = %v, want ErrArtifactSizeLimit", err)
	}
	if _, err := BuildSealedFrame([]byte{0xa0}, enc, make([]byte, MaxCiphertextBytes+1)); err == nil {
		t.Fatal("ciphertext one-over accepted")
	}
	for label, maximum := range map[string]int{
		"payload":       MaxPayloadBytes,
		"signed object": MaxSignedObjectBytes,
		"ciphertext":    MaxCiphertextBytes,
		"sealed frame":  MaxSealedFrameBytes,
		"total input":   MaxTotalInputBytes,
	} {
		if err := validateInputSize(label, maximum, maximum); err != nil {
			t.Fatalf("%s exact boundary: %v", label, err)
		}
		if err := validateInputSize(label, maximum+1, maximum); !errors.Is(err, ErrArtifactSizeLimit) {
			t.Fatalf("%s one-over error = %v", label, err)
		}
	}
}

func TestHPKEFreshEncapsulationIsUnique(t *testing.T) {
	key := deriveFixtureHPKEKey(t, []byte("phase8 repeated encapsulation recipient key material"))
	info := []byte("phase8 repeated encapsulation test")
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		enc, _, err := hpke.NewSender(key.PublicKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), info)
		if err != nil {
			t.Fatal(err)
		}
		encoded := string(enc)
		if _, duplicate := seen[encoded]; duplicate {
			t.Fatalf("duplicate HPKE encapsulation at iteration %d", i)
		}
		seen[encoded] = struct{}{}
	}
}

func TestGo126DeterministicRandomnessIsTestScoped(t *testing.T) {
	key := deriveFixtureHPKEKey(t, []byte("phase8 deterministic test recipient key material"))
	cryptotest.SetGlobalRandom(t, 802)
	enc1, _, err := hpke.NewSender(key.PublicKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	cryptotest.SetGlobalRandom(t, 802)
	enc2, _, err := hpke.NewSender(key.PublicKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc1, enc2) {
		t.Fatal("testing/cryptotest failed to reproduce the deterministic fixture stream")
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(content, []byte("testing/cryptotest")) {
			t.Fatalf("production file %s imports deterministic test randomness", entry.Name())
		}
	}
}

func TestPhase8SignerEntropyFailureFailsClosed(t *testing.T) {
	if os.Getenv("PHASE8_ENTROPY_FAILURE_HELPER") != "" {
		cryptorand.Reader = failingReader{}
		switch os.Getenv("PHASE8_ENTROPY_FAILURE_HELPER") {
		case "signer":
			priv := fixtureECDSAKey()
			digest := sha256.Sum256([]byte("phase8 signer entropy failure"))
			if _, _, err := ecdsa.Sign(cryptorand.Reader, priv, digest[:]); err != nil {
				os.Exit(0)
			}
			os.Exit(90)
		default:
			os.Exit(91)
		}
	}

	command := exec.Command(os.Args[0], "-test.run=^TestPhase8SignerEntropyFailureFailsClosed$")
	command.Env = append(envWithout("GODEBUG", "PHASE8_ENTROPY_FAILURE_HELPER"), "GODEBUG=cryptocustomrand=1", "PHASE8_ENTROPY_FAILURE_HELPER=signer")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("signer entropy failure did not fail closed: %v\n%s", err, output)
	}
}

func TestES256ProductionModeIsRandomizedAndVerifiable(t *testing.T) {
	priv := fixtureECDSAKey()
	digest := sha256.Sum256([]byte("phase8 randomized ES256 signing evidence"))
	r1, s1, err := ecdsa.Sign(cryptorand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	r2, s2, err := ecdsa.Sign(cryptorand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig1, err := EncodeRawES256Signature(r1, s1)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := EncodeRawES256Signature(r2, s2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sig1, sig2) {
		t.Fatal("two randomized ES256 signatures were identical")
	}
	for _, signature := range [][]byte{sig1, sig2} {
		r, s, err := DecodeRawES256Signature(signature)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
			t.Fatal("normalized raw ES256 signature failed verification")
		}
	}
}

func TestIndependentInteropReportReproducesMandatorySuite(t *testing.T) {
	report := loadInteropReport(t)
	if report.Schema != "kurdistan.phase8.independent-interop-report.v1" || report.SuiteID != uint16(SuiteClassicalV1) {
		t.Fatalf("unexpected report identity: schema=%q suite=%d", report.Schema, report.SuiteID)
	}
	if report.Independent.ProductionCodeShared != 0 || len(report.Fixtures) < 5 {
		t.Fatalf("independence=%d fixtures=%d", report.Independent.ProductionCodeShared, len(report.Fixtures))
	}
	if report.Summary.FixtureCount != len(report.Fixtures) || !report.Summary.MandatorySuiteExercised || report.Summary.Mismatches != 0 || report.Summary.UnexpectedAccepts != 0 {
		t.Fatalf("invalid reproduction summary: %+v", report.Summary)
	}
	verifyIndependentScriptHash(t, report)

	fixtures := make(map[string]interopFixture, len(report.Fixtures))
	for _, fixture := range report.Fixtures {
		fixtures[fixture.ID] = fixture
	}

	protectedFixture := fixtures["canonical-protected-headers-v1"]
	protected := mustHex(t, protectedFixture.OutputHex)
	gotProtected, err := BuildSignedProtectedHeaders(mustHex(t, protectedFixture.KeyIDHex), fixtureDeviceMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotProtected, protected) {
		t.Fatalf("protected bytes mismatch\n got %x\nwant %x", gotProtected, protected)
	}

	sigFixture := fixtures["canonical-sig-structure-v1"]
	gotSigStructure, err := BuildCOSESigStructure(mustHex(t, sigFixture.ProtectedHex), mustHex(t, sigFixture.PayloadHex))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSigStructure, mustHex(t, sigFixture.OutputHex)) {
		t.Fatal("Sig_structure mismatch with independent Python cbor2")
	}

	coseFixture := fixtures["canonical-tagged-cose-sign1-v1"]
	gotCOSE, err := BuildTaggedCOSESign1(mustHex(t, coseFixture.ProtectedHex), mustHex(t, coseFixture.PayloadHex), mustHex(t, coseFixture.SignatureHex))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCOSE, mustHex(t, coseFixture.OutputHex)) {
		t.Fatal("tagged COSE_Sign1 mismatch with independent Python cbor2")
	}
	if err := ValidateCoreDeterministicCBOR(gotCOSE); err != nil {
		t.Fatal(err)
	}

	verifySignatureFixture(t, fixtures["es256-raw-low-s-verify-v1"])
	verifyHPKEFixture(t, fixtures["hpke-open-device-v1"])
	verifyHPKEFixture(t, fixtures["hpke-open-backup-v1"])
	classCounts := map[ArtifactClass]int{}
	for _, fixture := range report.Fixtures {
		if fixture.ArtifactClass == "" {
			continue
		}
		classCounts[ArtifactClass(fixture.ArtifactClass)]++
		switch fixture.Kind {
		case "artifact-signed-public":
			verifySignedPublicArtifactFixture(t, fixture)
		case "hpke-open":
			verifyHPKEFixture(t, fixture)
		default:
			t.Fatalf("unknown release artifact fixture kind %q", fixture.Kind)
		}
	}
	for _, class := range []ArtifactClass{ArtifactSignedPublic, ArtifactProviderGroup, ArtifactDeviceRecipient, ArtifactEncryptedBackup} {
		if classCounts[class] < 5 {
			t.Fatalf("independent fixture count for %s = %d, want at least 5", class, classCounts[class])
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func deriveFixtureHPKEKey(t *testing.T, ikm []byte) hpke.PrivateKey {
	t.Helper()
	key, err := hpke.DHKEM(ecdh.P256()).DeriveKeyPair(ikm)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func fixtureECDSAKey() *ecdsa.PrivateKey {
	d := new(big.Int).SetBytes([]byte("phase8 fixture ecdsa private scalar"))
	n := p256Order()
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
}

type interopReport struct {
	Schema      string `json:"schema"`
	SuiteID     uint16 `json:"suite_id"`
	Independent struct {
		Script               string `json:"script"`
		ScriptSHA256         string `json:"script_sha256"`
		ProductionCodeShared int    `json:"production_code_shared"`
		Libraries            []struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			WheelSHA256 string `json:"wheel_sha256"`
		} `json:"libraries"`
	} `json:"independent_implementation"`
	Summary struct {
		FixtureCount            int  `json:"fixture_count"`
		UnexpectedAccepts       int  `json:"unexpected_accepts"`
		Mismatches              int  `json:"mismatches"`
		MandatorySuiteExercised bool `json:"mandatory_suite_exercised"`
	} `json:"reproduction_summary"`
	Fixtures []interopFixture `json:"fixtures"`
}

type interopFixture struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	Direction         string `json:"direction"`
	KeyIDHex          string `json:"key_id_hex"`
	OutputHex         string `json:"output_hex"`
	ProtectedHex      string `json:"protected_hex"`
	PayloadHex        string `json:"payload_hex"`
	MessageHex        string `json:"message_hex"`
	SignatureHex      string `json:"signature_hex"`
	PublicXHex        string `json:"public_x_hex"`
	PublicYHex        string `json:"public_y_hex"`
	RecipientIKMHex   string `json:"recipient_ikm_hex"`
	OuterProtectedHex string `json:"outer_protected_hex"`
	InfoHex           string `json:"info_hex"`
	AADHex            string `json:"aad_hex"`
	EncHex            string `json:"enc_hex"`
	CiphertextHex     string `json:"ciphertext_hex"`
	PlaintextHex      string `json:"plaintext_hex"`
	SealedFrameHex    string `json:"sealed_frame_hex"`
	ArtifactClass     string `json:"artifact_class"`
	Audience          string `json:"audience"`
	RecipientHint     string `json:"recipient_hint"`
	RecipientEpoch    uint64 `json:"recipient_epoch"`
}

func loadInteropReport(t *testing.T) interopReport {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "evidence", "phase8-independent-interop-report.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report interopReport
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func verifyIndependentScriptHash(t *testing.T, report interopReport) {
	t.Helper()
	if len(report.Independent.Libraries) != 3 {
		t.Fatalf("independent library count = %d", len(report.Independent.Libraries))
	}
	for _, library := range report.Independent.Libraries {
		if library.Name == "" || library.Version == "" || len(library.WheelSHA256) != 64 {
			t.Fatalf("incomplete independent library identity: %+v", library)
		}
	}
	scriptPath := filepath.Join("..", "..", "..", filepath.FromSlash(report.Independent.Script))
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != report.Independent.ScriptSHA256 {
		t.Fatal("independent fixture script hash does not match the report")
	}
}

func verifySignatureFixture(t *testing.T, fixture interopFixture) {
	t.Helper()
	if fixture.Kind != "signature-verify" || !strings.Contains(fixture.Direction, "Python cryptography") {
		t.Fatalf("invalid signature fixture provenance: %+v", fixture)
	}
	r, s, err := DecodeRawES256Signature(mustHex(t, fixture.SignatureHex))
	if err != nil {
		t.Fatal(err)
	}
	public := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(mustHex(t, fixture.PublicXHex)),
		Y:     new(big.Int).SetBytes(mustHex(t, fixture.PublicYHex)),
	}
	message := mustHex(t, fixture.MessageHex)
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(public, digest[:], r, s) {
		t.Fatal("Go crypto/ecdsa rejected the independent raw ES256 fixture")
	}
}

func verifyHPKEFixture(t *testing.T, fixture interopFixture) {
	t.Helper()
	if fixture.Kind != "hpke-open" || !strings.Contains(fixture.Direction, "Python pyhpke") {
		t.Fatalf("invalid HPKE fixture provenance: %+v", fixture)
	}
	metadata := ArtifactMetadata{Class: ArtifactClass(fixture.ArtifactClass), AudienceClass: fixture.Audience, RecipientHint: fixture.RecipientHint, RecipientEpoch: fixture.RecipientEpoch}
	if fixture.ID == "hpke-open-device-v1" {
		metadata = ArtifactMetadata{Class: ArtifactDeviceRecipient, AudienceClass: AudienceProvisionedDevice, RecipientHint: "fixture_hint_0001", RecipientEpoch: 7}
	}
	if fixture.ID == "hpke-open-backup-v1" {
		metadata = ArtifactMetadata{Class: ArtifactEncryptedBackup, AudienceClass: AudienceProvisionedBackupKey, RecipientHint: "fixture_hint_0002", RecipientEpoch: 9}
	}
	outerProtected, err := BuildSealProtected(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(outerProtected, mustHex(t, fixture.OuterProtectedHex)) {
		t.Fatal("outer protected bytes mismatch with independent Python cbor2")
	}
	key := deriveFixtureHPKEKey(t, mustHex(t, fixture.RecipientIKMHex))
	recipient, err := hpke.NewRecipient(
		mustHex(t, fixture.EncHex),
		key,
		hpke.HKDFSHA256(),
		hpke.AES256GCM(),
		mustHex(t, fixture.InfoHex),
	)
	if err != nil {
		t.Fatal(err)
	}
	budget := NewHPKEContextBudget()
	if err := budget.Consume(); err != nil {
		t.Fatal(err)
	}
	plaintext, err := recipient.Open(mustHex(t, fixture.AADHex), mustHex(t, fixture.CiphertextHex))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, mustHex(t, fixture.PlaintextHex)) {
		t.Fatal("Go crypto/hpke opened different plaintext")
	}
	if err := ValidateOpenedArtifactMetadataBinding(plaintext, outerProtected); err != nil {
		t.Fatalf("opened independent fixture metadata binding: %v", err)
	}
	if err := budget.Consume(); !errors.Is(err, ErrHPKEContextExhausted) {
		t.Fatal("HPKE fixture context was reusable")
	}
	info, err := BuildHPKEInfo(mustHex(t, fixture.OuterProtectedHex))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(info, mustHex(t, fixture.InfoHex)) {
		t.Fatal("HPKE info mismatch")
	}
	aad, err := BuildHPKEAAD(mustHex(t, fixture.OuterProtectedHex))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aad, mustHex(t, fixture.AADHex)) {
		t.Fatal("HPKE AAD mismatch")
	}
	frame, err := BuildSealedFrame(mustHex(t, fixture.OuterProtectedHex), mustHex(t, fixture.EncHex), mustHex(t, fixture.CiphertextHex))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame, mustHex(t, fixture.SealedFrameHex)) {
		t.Fatal("sealed frame mismatch with independent Python cbor2")
	}
	if err := ValidateCoreDeterministicCBOR(frame); err != nil {
		t.Fatal(err)
	}
}

func verifySignedPublicArtifactFixture(t *testing.T, fixture interopFixture) {
	t.Helper()
	if fixture.ArtifactClass != string(ArtifactSignedPublic) || fixture.Audience != AudiencePublic || !strings.Contains(fixture.Direction, "Python cbor2/cryptography") {
		t.Fatalf("invalid signed-public fixture provenance: %+v", fixture)
	}
	parsed, err := ParseSignedProfileOpaque(mustHex(t, fixture.OutputHex))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Protected, mustHex(t, fixture.ProtectedHex)) || !bytes.Equal(parsed.Payload, mustHex(t, fixture.PayloadHex)) || !bytes.Equal(parsed.Signature, mustHex(t, fixture.SignatureHex)) {
		t.Fatal("independent signed-public exact bytes mismatch")
	}
	context, err := DecodeSignedProtectedContextV1(parsed.Protected)
	if err != nil || context.Metadata != fixturePublicMetadata() {
		t.Fatalf("signed-public protected context: %+v %v", context, err)
	}
	message, err := BuildCOSESigStructure(parsed.Protected, parsed.Payload)
	if err != nil || !bytes.Equal(message, mustHex(t, fixture.MessageHex)) {
		t.Fatal("independent Sig_structure mismatch")
	}
	verifySignatureFixture(t, interopFixture{Kind: "signature-verify", Direction: "Python cryptography", MessageHex: fixture.MessageHex, SignatureHex: fixture.SignatureHex, PublicXHex: fixture.PublicXHex, PublicYHex: fixture.PublicYHex})
}

func fixturePublicMetadata() ArtifactMetadata {
	return ArtifactMetadata{Class: ArtifactSignedPublic, AudienceClass: AudiencePublic}
}

func fixtureDeviceMetadata() ArtifactMetadata {
	return ArtifactMetadata{Class: ArtifactDeviceRecipient, AudienceClass: AudienceProvisionedDevice, RecipientHint: "fixture_hint_0001", RecipientEpoch: 7}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func envWithout(names ...string) []string {
	blocked := make(map[string]struct{}, len(names))
	for _, name := range names {
		blocked[strings.ToUpper(name)] = struct{}{}
	}
	filtered := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, skip := blocked[strings.ToUpper(name)]; !skip {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
