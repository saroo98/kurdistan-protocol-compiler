// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package kmsprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

const defaultTimeout = 10 * time.Second

var (
	ErrInvalidConfiguration = errors.New("kmsprovider: invalid configuration")
	ErrRejected             = errors.New("kmsprovider: operation rejected")
	ErrUnavailable          = errors.New("kmsprovider: service unavailable")

	keyIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	nameRE  = regexp.MustCompile(`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/locations/([a-z0-9-]{1,63})/keyRings/([A-Za-z0-9_-]{1,63})/cryptoKeys/([A-Za-z0-9_-]{1,63})/cryptoKeyVersions/([1-9][0-9]{0,18})$`)
)

type KeyRole string

const (
	RoleRoot        KeyRole = "root"
	RoleRecovery    KeyRole = "recovery"
	RoleIssuer      KeyRole = "issuer"
	RoleEmergency   KeyRole = "emergency"
	RolePublication KeyRole = "publication"
	RoleAudit       KeyRole = "audit"
)

type Binding struct {
	KeyID             string
	VersionResource   string
	ExpectedProjectID string
	Role              KeyRole
}

type Catalog struct{ bindings map[string]Binding }

func NewCatalog(bindings []Binding) (*Catalog, error) {
	if len(bindings) == 0 || len(bindings) > 64 {
		return nil, ErrInvalidConfiguration
	}
	catalog := &Catalog{bindings: make(map[string]Binding, len(bindings))}
	resources := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		match := nameRE.FindStringSubmatch(binding.VersionResource)
		if !keyIDRE.MatchString(binding.KeyID) || len(match) != 6 ||
			match[1] != binding.ExpectedProjectID || !validRole(binding.Role) {
			return nil, ErrInvalidConfiguration
		}
		if _, exists := catalog.bindings[binding.KeyID]; exists {
			return nil, ErrInvalidConfiguration
		}
		if _, exists := resources[binding.VersionResource]; exists {
			return nil, ErrInvalidConfiguration
		}
		catalog.bindings[binding.KeyID] = binding
		resources[binding.VersionResource] = struct{}{}
	}
	return catalog, nil
}

func validRole(role KeyRole) bool {
	switch role {
	case RoleRoot, RoleRecovery, RoleIssuer, RoleEmergency, RolePublication, RoleAudit:
		return true
	default:
		return false
	}
}

func (catalog *Catalog) resolve(reference profile.KeyReference) (Binding, error) {
	if catalog == nil || reference.SuiteID != uint16(envelope.SuiteClassicalV1) {
		return Binding{}, ErrRejected
	}
	binding, ok := catalog.bindings[reference.KeyID]
	if !ok {
		return Binding{}, ErrRejected
	}
	return binding, nil
}

type RPC interface {
	GetCryptoKey(context.Context, string) (*kmspb.CryptoKey, error)
	GetCryptoKeyVersion(context.Context, string) (*kmspb.CryptoKeyVersion, error)
	GetPublicKey(context.Context, string) (*kmspb.PublicKey, error)
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
}

type Provider struct {
	rpc     RPC
	catalog *Catalog
	timeout time.Duration
}

type SigningAuthorization struct {
	Role                  KeyRole
	OperationID           string
	ApprovalID            string
	ExpectedMessageSHA256 string
	TrustedSequence       uint64
}

type AuthorizedSigner struct {
	provider      *Provider
	authorization SigningAuthorization
	ctx           context.Context
}

func (provider *Provider) Bind(authorization SigningAuthorization) (*AuthorizedSigner, error) {
	if provider == nil || !validRole(authorization.Role) ||
		!keyIDRE.MatchString(authorization.OperationID) ||
		!keyIDRE.MatchString(authorization.ApprovalID) ||
		len(authorization.ExpectedMessageSHA256) != sha256.Size*2 ||
		authorization.TrustedSequence == 0 {
		return nil, ErrInvalidConfiguration
	}
	for _, char := range authorization.ExpectedMessageSHA256 {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return nil, ErrInvalidConfiguration
		}
	}
	return &AuthorizedSigner{provider: provider, authorization: authorization, ctx: context.Background()}, nil
}

func (provider *Provider) BindContext(ctx context.Context, authorization SigningAuthorization) (*AuthorizedSigner, error) {
	if ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	signer, err := provider.Bind(authorization)
	if err != nil {
		return nil, err
	}
	signer.ctx = ctx
	return signer, nil
}

// SignAuthorized performs one role- and subject-bound signing operation. It is
// the narrow integration surface used by workers that must not retain a
// reusable signer capability.
func (provider *Provider) SignAuthorized(ctx context.Context, reference profile.KeyReference, message []byte, authorization SigningAuthorization) ([]byte, error) {
	signer, err := provider.BindContext(ctx, authorization)
	if err != nil {
		return nil, err
	}
	return signer.Sign(reference, message)
}

func (signer *AuthorizedSigner) Sign(reference profile.KeyReference, message []byte) ([]byte, error) {
	if signer == nil || signer.provider == nil {
		return nil, ErrRejected
	}
	binding, err := signer.provider.catalog.resolve(reference)
	if err != nil || binding.Role != signer.authorization.Role {
		return nil, ErrRejected
	}
	digest := sha256.Sum256(message)
	if fmt.Sprintf("%x", digest[:]) != signer.authorization.ExpectedMessageSHA256 {
		return nil, ErrRejected
	}
	return signer.provider.SignContext(signer.ctx, reference, message)
}

func New(rpc RPC, catalog *Catalog, timeout time.Duration) (*Provider, error) {
	if rpc == nil || catalog == nil {
		return nil, ErrInvalidConfiguration
	}
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < time.Second || timeout > 30*time.Second {
		return nil, ErrInvalidConfiguration
	}
	return &Provider{rpc: rpc, catalog: catalog, timeout: timeout}, nil
}

func (provider *Provider) Sign(reference profile.KeyReference, message []byte) ([]byte, error) {
	return provider.SignContext(context.Background(), reference, message)
}

func (provider *Provider) SignContext(parent context.Context, reference profile.KeyReference, message []byte) ([]byte, error) {
	if len(message) == 0 || len(message) > envelope.MaxSignedObjectBytes {
		return nil, ErrRejected
	}
	binding, err := provider.catalog.resolve(reference)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, provider.timeout)
	defer cancel()
	publicKey, err := provider.validateKey(ctx, binding)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	request := &kmspb.AsymmetricSignRequest{
		Name:         binding.VersionResource,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}},
		DigestCrc32C: wrapperspb.Int64(int64(crc32.Checksum(digest[:], crc32.MakeTable(crc32.Castagnoli)))),
	}
	response, err := provider.rpc.AsymmetricSign(ctx, request)
	if err != nil {
		return nil, ErrUnavailable
	}
	if response == nil || response.GetName() != binding.VersionResource ||
		response.GetProtectionLevel() != kmspb.ProtectionLevel_HSM ||
		!response.GetVerifiedDigestCrc32C() ||
		!validCRC(response.GetSignature(), response.GetSignatureCrc32C()) {
		return nil, ErrRejected
	}
	r, s, err := decodeStrictDER(response.GetSignature())
	if err != nil {
		return nil, ErrRejected
	}
	raw, err := envelope.EncodeRawES256Signature(r, s)
	if err != nil {
		return nil, ErrRejected
	}
	r, s, err = envelope.DecodeRawES256Signature(raw)
	if err != nil || !ecdsa.Verify(publicKey, digest[:], r, s) {
		return nil, ErrRejected
	}
	return raw, nil
}

func (provider *Provider) Verify(reference profile.KeyReference, message, signature []byte) error {
	return provider.VerifyContext(context.Background(), reference, message, signature)
}

func (provider *Provider) VerifyContext(parent context.Context, reference profile.KeyReference, message, signature []byte) error {
	if len(message) == 0 || len(message) > envelope.MaxSignedObjectBytes {
		return ErrRejected
	}
	binding, err := provider.catalog.resolve(reference)
	if err != nil {
		return err
	}
	r, s, err := envelope.DecodeRawES256Signature(signature)
	if err != nil {
		return ErrRejected
	}
	ctx, cancel := context.WithTimeout(parent, provider.timeout)
	defer cancel()
	publicKey, err := provider.validateKey(ctx, binding)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return ErrRejected
	}
	return nil
}

func (provider *Provider) validateKey(ctx context.Context, binding Binding) (*ecdsa.PublicKey, error) {
	version, err := provider.rpc.GetCryptoKeyVersion(ctx, binding.VersionResource)
	if err != nil {
		return nil, ErrUnavailable
	}
	parent := binding.VersionResource[:strings.LastIndex(binding.VersionResource, "/cryptoKeyVersions/")]
	key, err := provider.rpc.GetCryptoKey(ctx, parent)
	if err != nil {
		return nil, ErrUnavailable
	}
	public, err := provider.rpc.GetPublicKey(ctx, binding.VersionResource)
	if err != nil {
		return nil, ErrUnavailable
	}
	if version == nil || key == nil || public == nil ||
		version.GetName() != binding.VersionResource || key.GetName() != parent ||
		version.GetState() != kmspb.CryptoKeyVersion_ENABLED ||
		version.GetProtectionLevel() != kmspb.ProtectionLevel_HSM ||
		version.GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 ||
		key.GetPurpose() != kmspb.CryptoKey_ASYMMETRIC_SIGN ||
		public.GetName() != binding.VersionResource ||
		public.GetProtectionLevel() != kmspb.ProtectionLevel_HSM ||
		public.GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 ||
		public.GetPem() == "" || !validCRC([]byte(public.GetPem()), public.GetPemCrc32C()) {
		return nil, ErrRejected
	}
	block, rest := pem.Decode([]byte(public.GetPem()))
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		return nil, ErrRejected
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrRejected
	}
	ecdsaKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ecdsaKey.Curve != elliptic.P256() || !ecdsaKey.Curve.IsOnCurve(ecdsaKey.X, ecdsaKey.Y) {
		return nil, ErrRejected
	}
	return ecdsaKey, nil
}

type derSignature struct{ R, S *big.Int }

func decodeStrictDER(encoded []byte) (*big.Int, *big.Int, error) {
	if len(encoded) < 8 || len(encoded) > 80 {
		return nil, nil, ErrRejected
	}
	var signature derSignature
	rest, err := asn1.Unmarshal(encoded, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil ||
		signature.R.Sign() <= 0 || signature.S.Sign() <= 0 ||
		signature.R.Cmp(elliptic.P256().Params().N) >= 0 || signature.S.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, nil, ErrRejected
	}
	reencoded, err := asn1.Marshal(signature)
	if err != nil || string(reencoded) != string(encoded) {
		return nil, nil, ErrRejected
	}
	return signature.R, signature.S, nil
}

func validCRC(data []byte, expected *wrapperspb.Int64Value) bool {
	if len(data) == 0 || expected == nil || expected.Value < 0 || expected.Value > int64(^uint32(0)) {
		return false
	}
	actual := crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
	return uint32(expected.Value) == actual
}

var _ profile.Signer = (*Provider)(nil)
var _ profile.Verifier = (*Provider)(nil)
var _ profile.Signer = (*AuthorizedSigner)(nil)
