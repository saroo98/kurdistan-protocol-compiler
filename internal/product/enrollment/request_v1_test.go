// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package enrollment

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"kurdistan/internal/crypto/profilehpke"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

func TestGenerateEncodeVerifyAndPossessKeys(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	request, bundle, err := Generate(now, 6*time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAndVerifyRequestV1(encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, request) {
		t.Fatal("verified request differs from generated request")
	}
	if len(encoded) > MaxRequestBytes || decoded.CreatedAt != now.Unix() || decoded.ExpiresAt != now.Add(6*time.Hour).Unix() {
		t.Fatal("generated request has wrong size or validity")
	}

	recipient, err := hpke.DHKEM(ecdh.P256()).NewPrivateKey(bundle.RecipientPrivate)
	if err != nil || !bytes.Equal(recipient.PublicKey().Bytes(), request.RecipientPublic) {
		t.Fatalf("recipient possession mismatch: %v", err)
	}
	clientPrivate := ed25519.NewKeyFromSeed(bundle.ClientAuthSeed)
	defer clear(clientPrivate)
	if !bytes.Equal(clientPrivate.Public().(ed25519.PublicKey), request.ClientAuthPublic) {
		t.Fatal("client-auth possession mismatch")
	}

	binding := enrollmentBinding(request.RecipientKeyID)
	sealer, err := profilehpke.NewSealer(binding, request.RecipientPublic)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := profilehpke.NewOpener(binding, bundle.RecipientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opener.Close)
	outer, err := envelope.BuildSealProtected(envelope.ArtifactMetadata{Class: binding.Class, AudienceClass: envelope.AudienceProvisionedDevice, RecipientHint: binding.Hint, RecipientEpoch: binding.Epoch})
	if err != nil {
		t.Fatal(err)
	}
	encapsulation, ciphertext, err := sealer.SealOffline(binding, outer, encoded)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := opener.OpenOffline(binding, outer, encapsulation, ciphertext)
	if err != nil || !bytes.Equal(opened, encoded) {
		t.Fatalf("generated recipient could not open request bytes: %v", err)
	}

	decoded.RecipientPublic[0] ^= 1
	decoded.ClientAuthPublic[0] ^= 1
	decoded.Nonce[0] ^= 1
	decoded.Signature[0] ^= 1
	if bytes.Equal(decoded.RecipientPublic, request.RecipientPublic) || bytes.Equal(decoded.ClientAuthPublic, request.ClientAuthPublic) || bytes.Equal(decoded.Nonce, request.Nonce) || bytes.Equal(decoded.Signature, request.Signature) {
		t.Fatal("decoded request aliases generated request")
	}
}

func TestGenerateUsesExactInjectedEntropyAndDerivedIDs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	entropy := make([]byte, 96)
	for i := range entropy {
		entropy[i] = byte(i + 1)
	}
	first, firstBundle, err := Generate(now, time.Hour, bytes.NewReader(entropy))
	if err != nil {
		t.Fatal(err)
	}
	second, secondBundle, err := Generate(now, time.Hour, bytes.NewReader(entropy))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(firstBundle, secondBundle) {
		t.Fatal("identical injected entropy produced different enrollment material")
	}
	if first.RecipientKeyID != recipientKeyIDForTest(first.RecipientPublic) || first.ClientAuthKeyID != clientKeyIDForTest(first.ClientAuthPublic) || first.RequestID != requestIDForTest(first) {
		t.Fatal("generated identifiers do not use the frozen derivations")
	}
	if !bytes.Equal(firstBundle.ClientAuthSeed, entropy[32:64]) || !bytes.Equal(first.Nonce, entropy[64:96]) {
		t.Fatal("generation did not consume exact 32-byte entropy segments")
	}
	encoded, err := EncodeRequestV1(first)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(encoded, &fields); err != nil || len(fields) != 15 {
		t.Fatalf("request wire map: %v", err)
	}
	for label := uint64(1); label <= 15; label++ {
		if _, ok := fields[label]; !ok {
			t.Fatalf("request missing frozen label %d", label)
		}
	}
	var version, suite, kem, kdf, aead uint64
	var clientAlgorithm int64
	if cbor.Unmarshal(fields[1], &version) != nil || cbor.Unmarshal(fields[5], &suite) != nil || cbor.Unmarshal(fields[6], &kem) != nil || cbor.Unmarshal(fields[7], &kdf) != nil || cbor.Unmarshal(fields[8], &aead) != nil || cbor.Unmarshal(fields[9], &clientAlgorithm) != nil {
		t.Fatal("request suite labels have wrong direct types")
	}
	if version != RequestVersionV1 || suite != uint64(envelope.SuiteClassicalV1) || kem != uint64(envelope.HPKEKEMP256SHA256) || kdf != uint64(envelope.HPKEKDFSHA256) || aead != uint64(envelope.HPKEAEADAES256GCM) || clientAlgorithm != ClientAuthAlgorithmEd25519 {
		t.Fatal("request suite labels changed")
	}
}

func TestDeterministicEnrollmentVectorV1(t *testing.T) {
	entropy := make([]byte, 96)
	for i := range entropy {
		entropy[i] = byte(i + 1)
	}
	request, bundle, err := Generate(time.Unix(1_700_000_000, 0), time.Hour, bytes.NewReader(entropy))
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, err := EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := EncodePrivateBundleV1(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(requestBytes), "af010102784035643131316132386663343765326131643230313833633031633764653064633461333034396537643535646464613430353664353065663934643933383537031a6553f100041a6553ff10050106100701080209270a584104e3da718b2efbffd3090f42975151c18429c8071f14918336d1c92805fd8b2fbf323fd6144b2a3f9b49288635094aa06d7e4570007fcc7f1f9b238ca198a2d5e10b781a726563697069656e742e326666316662363930363662666334630c5820e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f00d782063393435636266326135363032303032313431653266623964313730353464360e58204142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f600f58407667ae6363b484582a12c8e7f4942706867d64495f2a29863414ffef94fe6331cacd775b2cda85488c1bd0061e9173865b4295de5e76d56b428fbfad5a63fd05"; got != want {
		t.Fatalf("request vector = %s", got)
	}
	if got, want := hex.EncodeToString(bundleBytes), "a301010258200491568cbed1b140219c72c4ba2d94f59568059012f62bf6951dc91aaebf5ea60358202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"; got != want {
		t.Fatalf("bundle vector = %s", got)
	}
}

func TestRequestRejectsSuiteBindingSignatureAndTimeMutations(t *testing.T) {
	now := time.Unix(1_700_100_000, 0)
	request, _, err := Generate(now, time.Hour, bytes.NewReader(bytes.Repeat([]byte{0x51}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutation := range map[string]struct {
		label uint64
		value any
		want  ErrorCategory
	}{
		"suite":                {5, uint64(envelope.SuiteReservedPQV1), ErrorUnsupportedSuite},
		"kem":                  {6, uint64(0x20), ErrorUnsupportedSuite},
		"kdf":                  {7, uint64(0x02), ErrorUnsupportedSuite},
		"aead":                 {8, uint64(0x01), ErrorUnsupportedSuite},
		"client algorithm":     {9, int64(-7), ErrorUnsupportedSuite},
		"recipient key id":     {11, "recipient.0000000000000000", ErrorKeyID},
		"client-auth key id":   {13, "00000000000000000000000000000000", ErrorKeyID},
		"request id":           {2, string(bytes.Repeat([]byte{'0'}, 64)), ErrorKeyID},
		"zero recipient key":   {10, make([]byte, 65), ErrorInvalidValue},
		"zero client key":      {12, make([]byte, 32), ErrorInvalidValue},
		"zero nonce":           {14, make([]byte, 32), ErrorInvalidValue},
		"signature substitute": {15, make([]byte, ed25519.SignatureSize), ErrorSignature},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := mutateRequestField(t, encoded, mutation.label, mutation.value)
			if _, err := DecodeAndVerifyRequestV1(mutated, now); !IsCategory(err, mutation.want) {
				t.Fatalf("mutation error = %v, want %s", err, mutation.want)
			}
		})
	}

	if _, err := DecodeAndVerifyRequestV1(encoded, now.Add(-time.Second)); !IsCategory(err, ErrorNotYetValid) {
		t.Fatalf("future request error = %v", err)
	}
	if _, err := DecodeAndVerifyRequestV1(encoded, now.Add(time.Hour)); !IsCategory(err, ErrorExpired) {
		t.Fatalf("expired request error = %v", err)
	}
	tooLong := mutateRequestField(t, encoded, 4, request.CreatedAt+MaxValiditySeconds+1)
	if _, err := DecodeAndVerifyRequestV1(tooLong, now); !IsCategory(err, ErrorInvalidValue) {
		t.Fatalf("excess validity error = %v", err)
	}
	wrongRole := request
	other, _, err := Generate(now, time.Hour, bytes.NewReader(bytes.Repeat([]byte{0x52}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	wrongRole.Signature = bytes.Clone(other.Signature)
	wrongRoleEncoded := requestMapBytes(t, wrongRole)
	if _, err := DecodeAndVerifyRequestV1(wrongRoleEncoded, now); !IsCategory(err, ErrorSignature) {
		t.Fatalf("role-confused signature error = %v", err)
	}
}

func TestRequestAndPrivateBundleRejectMalleableOrOversizedCBOR(t *testing.T) {
	now := time.Unix(1_700_200_000, 0)
	request, bundle, err := Generate(now, time.Hour, bytes.NewReader(bytes.Repeat([]byte{0x61}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	for name, malformed := range map[string][]byte{
		"empty":          nil,
		"oversized":      make([]byte, MaxRequestBytes+1),
		"duplicate key":  {0xa2, 0x01, 0x01, 0x01, 0x01},
		"indefinite map": {0xbf, 0x01, 0x01, 0xff},
		"tag":            {0xc1, 0xa0},
		"nonminimal":     {0xa1, 0x18, 0x01, 0x01},
		"trailing":       append(bytes.Clone(encoded), 0),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAndVerifyRequestV1(malformed, now); err == nil {
				t.Fatal("malleable request accepted")
			}
		})
	}

	bundleEncoded, err := EncodePrivateBundleV1(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundleEncoded) > MaxPrivateBundleBytes {
		t.Fatal("private bundle exceeds ceiling")
	}
	decoded, err := DecodePrivateBundleV1(bundleEncoded)
	if err != nil || !reflect.DeepEqual(decoded, bundle) {
		t.Fatalf("private bundle round trip: %v", err)
	}
	decoded.RecipientPrivate[0] ^= 1
	decoded.ClientAuthSeed[0] ^= 1
	if bytes.Equal(decoded.RecipientPrivate, bundle.RecipientPrivate) || bytes.Equal(decoded.ClientAuthSeed, bundle.ClientAuthSeed) {
		t.Fatal("private bundle decode aliases caller data")
	}
	for name, malformed := range map[string][]byte{
		"empty":         nil,
		"oversized":     make([]byte, MaxPrivateBundleBytes+1),
		"duplicate key": {0xa2, 0x01, 0x01, 0x01, 0x01},
		"tag":           {0xc1, 0xa0},
		"trailing":      append(bytes.Clone(bundleEncoded), 0),
	} {
		t.Run("bundle "+name, func(t *testing.T) {
			if _, err := DecodePrivateBundleV1(malformed); err == nil {
				t.Fatal("malleable private bundle accepted")
			}
		})
	}
	if _, err := EncodePrivateBundleV1(PrivateBundleV1{RecipientPrivate: make([]byte, 32), ClientAuthSeed: make([]byte, 32)}); !IsCategory(err, ErrorInvalidValue) {
		t.Fatalf("zero private bundle error = %v", err)
	}
}

func TestGenerateRejectsInvalidTimeAndShortEntropy(t *testing.T) {
	now := time.Unix(1_700_300_000, 0)
	for name, validity := range map[string]time.Duration{
		"zero":         0,
		"negative":     -time.Second,
		"subsecond":    time.Second + time.Nanosecond,
		"over 24 hour": 24*time.Hour + time.Second,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Generate(now, validity, bytes.NewReader(make([]byte, 96))); !IsCategory(err, ErrorInvalidValue) {
				t.Fatalf("validity error = %v", err)
			}
		})
	}
	if _, _, err := Generate(now, time.Hour, bytes.NewReader(make([]byte, 95))); !IsCategory(err, ErrorInvalidValue) {
		t.Fatalf("short entropy error = %v", err)
	}
}

func TestProductionEnrollmentAndHPKEPackagesExcludeTestProviders(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	for _, relative := range []string{
		"internal/crypto/profilehpke/provider.go",
		"internal/product/enrollment/request_v1.go",
	} {
		path := filepath.Join(root, filepath.FromSlash(relative))
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"phase8issuance", "deterministicHPKESeal", "testOnlySeed", "testing/cryptotest"} {
			if bytes.Contains(source, []byte(forbidden)) {
				t.Fatalf("%s contains test-only provider token %q", relative, forbidden)
			}
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			value := strings.Trim(imported.Path.Value, `"`)
			if value == "math/rand" || value == "testing" || strings.Contains(value, "/internal/testkit") {
				t.Fatalf("%s imports forbidden production dependency %q", relative, value)
			}
		}
		if relative == "internal/product/enrollment/request_v1.go" {
			full, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
			if err != nil {
				t.Fatal(err)
			}
			readerParameters := 0
			ast.Inspect(full, func(node ast.Node) bool {
				function, ok := node.(*ast.FuncDecl)
				if !ok || function.Type.Params == nil {
					return true
				}
				for _, field := range function.Type.Params.List {
					selector, ok := field.Type.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					identifier, identOK := selector.X.(*ast.Ident)
					if identOK && identifier.Name == "io" && selector.Sel.Name == "Reader" {
						readerParameters++
						if function.Name.Name != "Generate" {
							t.Fatalf("io.Reader exposed by %s", function.Name.Name)
						}
					}
				}
				return true
			})
			if readerParameters != 1 {
				t.Fatalf("production enrollment io.Reader parameter count = %d", readerParameters)
			}
		}
	}
}

func mutateRequestField(t testing.TB, encoded []byte, label uint64, value any) []byte {
	t.Helper()
	var fields map[uint64]any
	if err := cbor.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	fields[label] = value
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := mode.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}

func requestMapBytes(t testing.TB, request PublicRequestV1) []byte {
	t.Helper()
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := mode.Marshal(map[uint64]any{
		1: RequestVersionV1, 2: request.RequestID, 3: request.CreatedAt, 4: request.ExpiresAt,
		5: uint64(envelope.SuiteClassicalV1), 6: uint64(envelope.HPKEKEMP256SHA256), 7: uint64(envelope.HPKEKDFSHA256), 8: uint64(envelope.HPKEAEADAES256GCM), 9: ClientAuthAlgorithmEd25519,
		10: bytes.Clone(request.RecipientPublic), 11: request.RecipientKeyID, 12: bytes.Clone(request.ClientAuthPublic), 13: request.ClientAuthKeyID, 14: bytes.Clone(request.Nonce), 15: bytes.Clone(request.Signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func recipientKeyIDForTest(public []byte) string {
	digest := sha256.Sum256(public)
	return "recipient." + hex.EncodeToString(digest[:8])
}

func clientKeyIDForTest(public []byte) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:16])
}

func requestIDForTest(request PublicRequestV1) string {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	identity, err := mode.Marshal(map[uint64]any{
		1: RequestVersionV1, 3: request.CreatedAt, 4: request.ExpiresAt,
		5: uint64(envelope.SuiteClassicalV1), 6: uint64(envelope.HPKEKEMP256SHA256), 7: uint64(envelope.HPKEKDFSHA256), 8: uint64(envelope.HPKEAEADAES256GCM), 9: ClientAuthAlgorithmEd25519,
		10: bytes.Clone(request.RecipientPublic), 11: request.RecipientKeyID, 12: bytes.Clone(request.ClientAuthPublic), 13: request.ClientAuthKeyID, 14: bytes.Clone(request.Nonce),
	})
	if err != nil {
		panic(err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kurdistan-vpn/enrollment/request-id/v1\x00"))
	_, _ = hash.Write(identity)
	return hex.EncodeToString(hash.Sum(nil))
}

func enrollmentBinding(keyID string) profile.RecipientBinding {
	return profile.RecipientBinding{Class: envelope.ArtifactDeviceRecipient, ProviderID: "provider.test", LineageID: "lineage.test", ProfileNamespace: "profiles.", Hint: "enrollment_hint_0001", KeyID: keyID, Epoch: 1}
}
