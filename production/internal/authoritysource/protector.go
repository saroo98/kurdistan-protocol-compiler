// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package authoritysource protects exact verifier-admitted mutation sources
// before they enter durable production storage.
package authoritysource

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"io"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	Schema          = "phase16-protected-authority-source-v1"
	MaxSourceBytes  = 32 << 10
	maxWrappedBytes = 16 << 10
)

var (
	ErrInvalid     = errors.New("authoritysource: invalid input")
	ErrRejected    = errors.New("authoritysource: rejected")
	ErrUnavailable = errors.New("authoritysource: unavailable")

	idRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyRE    = regexp.MustCompile(`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/locations/([a-z0-9-]{1,63})/keyRings/([A-Za-z0-9_-]{1,63})/cryptoKeys/([A-Za-z0-9_-]{1,63})/cryptoKeyVersions/([1-9][0-9]{0,18})$`)
)

type Protected struct {
	Schema          string `json:"schema"`
	KeyVersion      string `json:"key_version"`
	OperationID     string `json:"operation_id"`
	SubjectDigest   string `json:"subject_digest"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	AADSHA256       string `json:"aad_sha256"`
	PlaintextBytes  int    `json:"plaintext_bytes"`
	Nonce           []byte `json:"nonce"`
	WrappedDEK      []byte `json:"wrapped_dek"`
	Ciphertext      []byte `json:"ciphertext"`
}

type RPC interface {
	Encrypt(context.Context, *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)
	Decrypt(context.Context, *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
}

type GoogleRPC struct{ client *kms.KeyManagementClient }

func NewGoogleRPC(client *kms.KeyManagementClient) (*GoogleRPC, error) {
	if client == nil {
		return nil, ErrInvalid
	}
	return &GoogleRPC{client: client}, nil
}

func (rpc *GoogleRPC) Encrypt(ctx context.Context, request *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	return rpc.client.Encrypt(ctx, request)
}

func (rpc *GoogleRPC) Decrypt(ctx context.Context, request *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	return rpc.client.Decrypt(ctx, request)
}

type Protector struct {
	rpc         RPC
	key         string
	keyVersion  string
	environment string
	timeout     time.Duration
	random      io.Reader
}

func New(rpc RPC, key, environment string, timeout time.Duration) (*Protector, error) {
	if rpc == nil || !keyRE.MatchString(key) || !idRE.MatchString(environment) ||
		timeout < time.Second || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	parent := key[:strings.LastIndex(key, "/cryptoKeyVersions/")]
	return &Protector{rpc: rpc, key: parent, keyVersion: key, environment: environment, timeout: timeout, random: rand.Reader}, nil
}

func (protector *Protector) Protect(parent context.Context, operationID, subjectDigest string, source []byte) (Protected, error) {
	if parent == nil || !idRE.MatchString(operationID) || !digestRE.MatchString(subjectDigest) ||
		len(source) == 0 || len(source) > MaxSourceBytes {
		return Protected{}, ErrInvalid
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(protector.random, dek); err != nil {
		return Protected{}, ErrUnavailable
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return Protected{}, ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Protected{}, ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(protector.random, nonce); err != nil {
		return Protected{}, ErrUnavailable
	}
	aad := protector.aad(operationID, subjectDigest, len(source))
	ciphertext := aead.Seal(nil, nonce, source, aad)
	ctx, cancel := context.WithTimeout(parent, protector.timeout)
	defer cancel()
	response, err := protector.rpc.Encrypt(ctx, &kmspb.EncryptRequest{
		Name: protector.keyVersion, Plaintext: dek, AdditionalAuthenticatedData: aad,
		PlaintextCrc32C: crc(dek), AdditionalAuthenticatedDataCrc32C: crc(aad),
	})
	if err != nil {
		return Protected{}, ErrUnavailable
	}
	if response == nil || response.GetName() != protector.keyVersion ||
		response.GetProtectionLevel() != kmspb.ProtectionLevel_HSM ||
		!response.GetVerifiedPlaintextCrc32C() || !response.GetVerifiedAdditionalAuthenticatedDataCrc32C() ||
		len(response.GetCiphertext()) == 0 || len(response.GetCiphertext()) > maxWrappedBytes ||
		!validCRC(response.GetCiphertext(), response.GetCiphertextCrc32C()) {
		return Protected{}, ErrRejected
	}
	plainDigest := sha256.Sum256(source)
	aadDigest := sha256.Sum256(aad)
	return Protected{
		Schema: Schema, KeyVersion: response.GetName(), OperationID: operationID,
		SubjectDigest: subjectDigest, PlaintextSHA256: hex.EncodeToString(plainDigest[:]),
		AADSHA256: hex.EncodeToString(aadDigest[:]), PlaintextBytes: len(source),
		Nonce: append([]byte(nil), nonce...), WrappedDEK: append([]byte(nil), response.GetCiphertext()...),
		Ciphertext: append([]byte(nil), ciphertext...),
	}, nil
}

func (protector *Protector) Open(parent context.Context, protected Protected) ([]byte, error) {
	if parent == nil || protected.Schema != Schema || !idRE.MatchString(protected.OperationID) ||
		!digestRE.MatchString(protected.SubjectDigest) || !digestRE.MatchString(protected.PlaintextSHA256) ||
		!digestRE.MatchString(protected.AADSHA256) || protected.PlaintextBytes < 1 || protected.PlaintextBytes > MaxSourceBytes ||
		protected.KeyVersion != protector.keyVersion ||
		len(protected.Nonce) != 12 || len(protected.WrappedDEK) == 0 || len(protected.WrappedDEK) > maxWrappedBytes ||
		len(protected.Ciphertext) != protected.PlaintextBytes+16 {
		return nil, ErrInvalid
	}
	aad := protector.aad(protected.OperationID, protected.SubjectDigest, protected.PlaintextBytes)
	aadDigest := sha256.Sum256(aad)
	if hex.EncodeToString(aadDigest[:]) != protected.AADSHA256 {
		return nil, ErrRejected
	}
	ctx, cancel := context.WithTimeout(parent, protector.timeout)
	defer cancel()
	response, err := protector.rpc.Decrypt(ctx, &kmspb.DecryptRequest{
		Name: protector.key, Ciphertext: protected.WrappedDEK, AdditionalAuthenticatedData: aad,
		CiphertextCrc32C: crc(protected.WrappedDEK), AdditionalAuthenticatedDataCrc32C: crc(aad),
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	if response == nil || response.GetProtectionLevel() != kmspb.ProtectionLevel_HSM ||
		len(response.GetPlaintext()) != 32 || !validCRC(response.GetPlaintext(), response.GetPlaintextCrc32C()) {
		return nil, ErrRejected
	}
	dek := append([]byte(nil), response.GetPlaintext()...)
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrRejected
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrRejected
	}
	plaintext, err := aead.Open(nil, protected.Nonce, protected.Ciphertext, aad)
	if err != nil || len(plaintext) != protected.PlaintextBytes {
		return nil, ErrRejected
	}
	digest := sha256.Sum256(plaintext)
	if hex.EncodeToString(digest[:]) != protected.PlaintextSHA256 {
		clear(plaintext)
		return nil, ErrRejected
	}
	return plaintext, nil
}

func (protector *Protector) aad(operationID, subjectDigest string, size int) []byte {
	return []byte(Schema + "\x00" + protector.environment + "\x00" + operationID + "\x00" + subjectDigest + "\x00" + itoa(size))
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

func crc(value []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli))))
}

func validCRC(value []byte, expected *wrapperspb.Int64Value) bool {
	if len(value) == 0 || expected == nil || expected.Value < 0 || expected.Value > int64(^uint32(0)) {
		return false
	}
	return uint32(expected.Value) == crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli))
}

var _ RPC = (*GoogleRPC)(nil)
