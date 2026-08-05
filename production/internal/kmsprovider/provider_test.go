// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package kmsprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

const testVersion = "projects/kvpn-prod-trust/locations/europe-west2/keyRings/issuer-ring/cryptoKeys/profile-issuer/cryptoKeyVersions/7"

type fakeRPC struct {
	private *ecdsa.PrivateKey
	key     *kmspb.CryptoKey
	version *kmspb.CryptoKeyVersion
	public  *kmspb.PublicKey
	sign    func(*kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
}

func newFakeRPC(t *testing.T) *fakeRPC {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	crc := checksum(pemBytes)
	rpc := &fakeRPC{
		private: private,
		key: &kmspb.CryptoKey{
			Name:    testVersion[:len(testVersion)-len("/cryptoKeyVersions/7")],
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		},
		version: &kmspb.CryptoKeyVersion{
			Name: testVersion, State: kmspb.CryptoKeyVersion_ENABLED,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
			Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		},
		public: &kmspb.PublicKey{
			Name: testVersion, Pem: string(pemBytes), PemCrc32C: wrapperspb.Int64(int64(crc)),
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
			Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		},
	}
	rpc.sign = func(request *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
		digest := request.GetDigest().GetSha256()
		if request.GetName() != testVersion || len(digest) != sha256.Size ||
			request.GetDigestCrc32C() == nil || uint32(request.GetDigestCrc32C().Value) != checksum(digest) {
			return nil, errors.New("bad request")
		}
		r, s, err := ecdsa.Sign(rand.Reader, private, digest)
		if err != nil {
			return nil, err
		}
		// Exercise the adapter's mandatory high-S canonicalization.
		if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) <= 0 {
			s.Sub(elliptic.P256().Params().N, s)
		}
		encoded, err := asn1.Marshal(derSignature{R: r, S: s})
		if err != nil {
			return nil, err
		}
		return &kmspb.AsymmetricSignResponse{
			Name: testVersion, Signature: encoded,
			SignatureCrc32C:      wrapperspb.Int64(int64(checksum(encoded))),
			VerifiedDigestCrc32C: true, ProtectionLevel: kmspb.ProtectionLevel_HSM,
		}, nil
	}
	return rpc
}

func (rpc *fakeRPC) GetCryptoKey(context.Context, string) (*kmspb.CryptoKey, error) {
	return rpc.key, nil
}
func (rpc *fakeRPC) GetCryptoKeyVersion(context.Context, string) (*kmspb.CryptoKeyVersion, error) {
	return rpc.version, nil
}
func (rpc *fakeRPC) GetPublicKey(context.Context, string) (*kmspb.PublicKey, error) {
	return rpc.public, nil
}
func (rpc *fakeRPC) AsymmetricSign(_ context.Context, request *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return rpc.sign(request)
}

func checksum(value []byte) uint32 {
	return crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli))
}

func testProvider(t *testing.T, rpc *fakeRPC) *Provider {
	t.Helper()
	catalog, err := NewCatalog([]Binding{{
		KeyID: "issuer-key-7", VersionResource: testVersion,
		ExpectedProjectID: "kvpn-prod-trust", Role: RoleIssuer,
	}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(rpc, catalog, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestProviderSignsCanonicalRawAndVerifies(t *testing.T) {
	rpc := newFakeRPC(t)
	provider := testProvider(t, rpc)
	reference := profile.KeyReference{KeyID: "issuer-key-7", SuiteID: uint16(envelope.SuiteClassicalV1)}
	message := []byte("bounded profile signature structure")
	signature, err := provider.Sign(reference, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != envelope.ES256RawSignatureSize {
		t.Fatalf("signature length=%d", len(signature))
	}
	if err := provider.Verify(reference, message, signature); err != nil {
		t.Fatal(err)
	}
	if err := provider.Verify(reference, []byte("changed"), signature); !errors.Is(err, ErrRejected) {
		t.Fatalf("changed message error=%v", err)
	}
}

func TestAuthorizedSignerBindsRoleOperationApprovalAndExactMessage(t *testing.T) {
	rpc := newFakeRPC(t)
	provider := testProvider(t, rpc)
	message := []byte("exact signed structure")
	digest := sha256.Sum256(message)
	signer, err := provider.Bind(SigningAuthorization{
		Role: RoleIssuer, OperationID: "operation-123", ApprovalID: "approval-123",
		ExpectedMessageSHA256: fmt.Sprintf("%x", digest[:]), TrustedSequence: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	reference := profile.KeyReference{KeyID: "issuer-key-7", SuiteID: 1}
	if _, err := signer.Sign(reference, message); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(reference, []byte("substituted")); !errors.Is(err, ErrRejected) {
		t.Fatalf("substitution error=%v", err)
	}
	wrongRole, err := provider.Bind(SigningAuthorization{
		Role: RoleAudit, OperationID: "operation-123", ApprovalID: "approval-123",
		ExpectedMessageSHA256: fmt.Sprintf("%x", digest[:]), TrustedSequence: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongRole.Sign(reference, message); !errors.Is(err, ErrRejected) {
		t.Fatalf("role error=%v", err)
	}
}

func TestProviderRejectsWrongKMSPropertiesAndIntegrity(t *testing.T) {
	cases := map[string]func(*fakeRPC){
		"key purpose":     func(rpc *fakeRPC) { rpc.key.Purpose = kmspb.CryptoKey_ENCRYPT_DECRYPT },
		"version state":   func(rpc *fakeRPC) { rpc.version.State = kmspb.CryptoKeyVersion_DISABLED },
		"software key":    func(rpc *fakeRPC) { rpc.version.ProtectionLevel = kmspb.ProtectionLevel_SOFTWARE },
		"algorithm":       func(rpc *fakeRPC) { rpc.version.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256 },
		"public name":     func(rpc *fakeRPC) { rpc.public.Name += "-wrong" },
		"public checksum": func(rpc *fakeRPC) { rpc.public.PemCrc32C.Value++ },
		"response checksum": func(rpc *fakeRPC) {
			original := rpc.sign
			rpc.sign = func(request *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
				response, err := original(request)
				if response != nil {
					response.SignatureCrc32C.Value++
				}
				return response, err
			}
		},
		"digest unverified": func(rpc *fakeRPC) {
			original := rpc.sign
			rpc.sign = func(request *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
				response, err := original(request)
				if response != nil {
					response.VerifiedDigestCrc32C = false
				}
				return response, err
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rpc := newFakeRPC(t)
			mutate(rpc)
			provider := testProvider(t, rpc)
			_, err := provider.Sign(profile.KeyReference{KeyID: "issuer-key-7", SuiteID: 1}, []byte("message"))
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProviderRejectsMalformedDERAndUnknownReferences(t *testing.T) {
	rpc := newFakeRPC(t)
	rpc.sign = func(*kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
		bad := append([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, 0)
		return &kmspb.AsymmetricSignResponse{Name: testVersion, Signature: bad,
			SignatureCrc32C: wrapperspb.Int64(int64(checksum(bad))), VerifiedDigestCrc32C: true,
			ProtectionLevel: kmspb.ProtectionLevel_HSM}, nil
	}
	provider := testProvider(t, rpc)
	if _, err := provider.Sign(profile.KeyReference{KeyID: "issuer-key-7", SuiteID: 1}, []byte("message")); !errors.Is(err, ErrRejected) {
		t.Fatalf("malformed DER error=%v", err)
	}
	if _, err := provider.Sign(profile.KeyReference{KeyID: "missing", SuiteID: 1}, []byte("message")); !errors.Is(err, ErrRejected) {
		t.Fatalf("unknown key error=%v", err)
	}
	if _, err := provider.Sign(profile.KeyReference{KeyID: "issuer-key-7", SuiteID: 99}, []byte("message")); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong suite error=%v", err)
	}
}

func TestCatalogRejectsAliasAndResourceConflicts(t *testing.T) {
	valid := Binding{KeyID: "issuer-key-7", VersionResource: testVersion, ExpectedProjectID: "kvpn-prod-trust", Role: RoleIssuer}
	if _, err := NewCatalog([]Binding{valid, valid}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("duplicate error=%v", err)
	}
	wrongProject := valid
	wrongProject.ExpectedProjectID = "other-project"
	if _, err := NewCatalog([]Binding{wrongProject}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("project error=%v", err)
	}
	wrongRole := valid
	wrongRole.Role = "unbounded"
	if _, err := NewCatalog([]Binding{wrongRole}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("role error=%v", err)
	}
}
