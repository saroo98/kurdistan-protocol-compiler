// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package lifecycle

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"hash/crc32"
	"math/big"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/production/internal/kmsprovider"
)

const lifecycleKeyVersion = "projects/kvpn-prod-trust/locations/europe-west2/keyRings/issuer-ring/cryptoKeys/profile-issuer/cryptoKeyVersions/7"

type lifecycleRPC struct {
	private *ecdsa.PrivateKey
	public  string
}

func newLifecycleRPC(t *testing.T) *lifecycleRPC {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &lifecycleRPC{private: private, public: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))}
}

func (rpc *lifecycleRPC) GetCryptoKey(context.Context, string) (*kmspb.CryptoKey, error) {
	return &kmspb.CryptoKey{Name: lifecycleKeyVersion[:len(lifecycleKeyVersion)-len("/cryptoKeyVersions/7")], Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN}, nil
}
func (rpc *lifecycleRPC) GetCryptoKeyVersion(context.Context, string) (*kmspb.CryptoKeyVersion, error) {
	return &kmspb.CryptoKeyVersion{Name: lifecycleKeyVersion, State: kmspb.CryptoKeyVersion_ENABLED, ProtectionLevel: kmspb.ProtectionLevel_HSM, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256}, nil
}
func (rpc *lifecycleRPC) GetPublicKey(context.Context, string) (*kmspb.PublicKey, error) {
	return &kmspb.PublicKey{Name: lifecycleKeyVersion, Pem: rpc.public, PemCrc32C: wrapperspb.Int64(int64(lifecycleCRC([]byte(rpc.public)))), ProtectionLevel: kmspb.ProtectionLevel_HSM, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256}, nil
}
func (rpc *lifecycleRPC) AsymmetricSign(_ context.Context, request *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	digest := request.GetDigest().GetSha256()
	r, s, err := ecdsa.Sign(rand.Reader, rpc.private, digest)
	if err != nil {
		return nil, err
	}
	encoded, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	if err != nil {
		return nil, err
	}
	return &kmspb.AsymmetricSignResponse{Name: lifecycleKeyVersion, Signature: encoded, SignatureCrc32C: wrapperspb.Int64(int64(lifecycleCRC(encoded))), VerifiedDigestCrc32C: true, ProtectionLevel: kmspb.ProtectionLevel_HSM}, nil
}

func lifecycleCRC(value []byte) uint32 {
	return crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli))
}

func TestIssueUsesPhase8ConstructionAndRealVerifier(t *testing.T) {
	rpc := newLifecycleRPC(t)
	catalog, err := kmsprovider.NewCatalog([]kmsprovider.Binding{{KeyID: "issuer-key-0001", VersionResource: lifecycleKeyVersion, ExpectedProjectID: "kvpn-prod-trust", Role: kmsprovider.RoleIssuer}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := kmsprovider.New(rpc, catalog, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewIssuer(provider)
	if err != nil {
		t.Fatal(err)
	}
	spec := validSpec()
	artifact, receipt, err := issuer.Issue(context.Background(), IssueRequest{Spec: spec, OperationID: "operation-123", ApprovalID: "approval-123", TrustedSequence: 11})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact) == 0 || receipt.Schema != "phase16-profile-issuance-receipt-v1" || receipt.ArtifactSHA256 == "" || receipt.Inspection.Generation != 7 {
		t.Fatalf("receipt=%+v", receipt)
	}
	bad := spec
	bad.Profile.Generation = 8
	bad.MinimumGeneration = 8
	if _, _, err := issuer.Issue(context.Background(), IssueRequest{Spec: bad, OperationID: "operation-123", ApprovalID: "approval-123", TrustedSequence: 11, ExpectedArtifactSHA256: receipt.ArtifactSHA256}); err == nil {
		t.Fatal("accepted substituted artifact digest")
	}
}

func validSpec() profile.OfflineIssuanceSpec {
	return profile.OfflineIssuanceSpec{
		Profile: envelope.CanonicalProfileV1{ContentID: "content.0001", ProfileID: "profiles.one", LineageID: "lineage.0001", ProviderID: "provider.0001", ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation.0001", SnapshotMode: "full-snapshot", UpdateKind: "initial", Generation: 7, RequiredSafetyFloor: 2, ValidFrom: 100, ValidUntil: 1000, RootEpoch: 3, RevocationEpoch: 4, RelayIDs: []string{"relay.0001"}, StrategyIDs: []string{"strategy.0001"}, Policy: []byte{0xa1, 0x01, 0x01}},
		Class:   envelope.ArtifactSignedPublic, Audience: envelope.AudiencePublic, Suite: envelope.SuiteClassicalV1,
		IssuerRole: profile.RoleIssuer, IssuerScope: profile.AuthorityScope{ProviderID: "provider.0001", LineageID: "lineage.0001", ProfileNamespace: "profiles."},
		IssuerKey: profile.KeyReference{KeyID: "issuer-key-0001", SuiteID: 1}, MinimumGeneration: 7, Now: 500,
	}
}
