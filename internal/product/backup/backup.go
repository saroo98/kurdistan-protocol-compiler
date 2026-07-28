// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package backup implements the bounded, passphrase-encrypted kurd-backup-v1
// container. It performs no filesystem, UI, network, or persistence work.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
)

const (
	Version = "kurd-backup-v1"

	ArgonMemoryKiB  uint32 = 64 * 1024
	ArgonIterations uint32 = 3
	ArgonThreads    uint8  = 1

	MaxArgonMemoryKiB  uint32 = 256 * 1024
	MaxArgonIterations uint32 = 10
	MaxArgonThreads    uint8  = 4

	SaltBytes        = 16
	NonceBytes       = 12
	KeyBytes         = 32
	MinimumRunes     = 12
	MaximumPassBytes = 1024
	MaxRecords       = 128
	MaxPayloadBytes  = 8 * 1024 * 1024
)

const (
	headerMagic      = "KURDBK1\x00"
	headerVersion    = uint16(1)
	kdfArgon2id      = byte(1)
	cipherAES256GCM  = byte(1)
	fixedHeaderBytes = 28
)

var (
	ErrInvalidPassphrase = errors.New("backup: invalid passphrase")
	ErrInvalidHeader     = errors.New("backup: invalid header")
	ErrResourceLimit     = errors.New("backup: resource limit")
	ErrAuthentication    = errors.New("backup: authentication failed")
	ErrInvalidPayload    = errors.New("backup: invalid payload")
	ErrRestoreRejected   = errors.New("backup: restore rejected")
)

type RecordKind uint8

const (
	RecordNativeProfile RecordKind = iota + 1
	RecordVerifiedReceipt
	RecordLocalAlias
	RecordNonsecretSettings
	RecordRoutingPreferences
)

type Record struct {
	Kind       RecordKind `cbor:"1,keyasint"`
	LocalID    string     `cbor:"2,keyasint"`
	Generation uint64     `cbor:"3,keyasint,omitempty"`
	ExactBytes []byte     `cbor:"4,keyasint"`
}

type Payload struct {
	Version uint64   `cbor:"1,keyasint"`
	Records []Record `cbor:"2,keyasint"`
}

type Preview struct {
	Version     string
	RecordCount int
	KindCounts  map[RecordKind]int
}

type Opened struct {
	preview Preview
	payload Payload
}

type RestoreVerifier interface {
	VerifyBackupRecord(Record) error
}

type RandomSource interface {
	Read([]byte) (int, error)
}

func Create(passphrase string, payload Payload) ([]byte, error) {
	return CreateWithRandom(rand.Reader, passphrase, payload)
}

func CreateWithRandom(random io.Reader, passphrase string, payload Payload) ([]byte, error) {
	pass, err := validatePassphrase(passphrase)
	if err != nil || random == nil {
		return nil, ErrInvalidPassphrase
	}
	defer clear(pass)
	plaintext, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	salt := make([]byte, SaltBytes)
	nonce := make([]byte, NonceBytes)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, ErrResourceLimit
	}
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, ErrResourceLimit
	}
	ciphertextLength := len(plaintext) + 16
	header := encodeHeader(ArgonMemoryKiB, ArgonIterations, ArgonThreads, salt, nonce, ciphertextLength)
	key := argon2.IDKey(pass, salt, ArgonIterations, ArgonMemoryKiB, ArgonThreads, KeyBytes)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrResourceLimit
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrResourceLimit
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, header)
	out := make([]byte, 0, len(header)+len(ciphertext))
	out = append(out, header...)
	out = append(out, ciphertext...)
	return out, nil
}

func OpenPreview(passphrase string, encoded []byte) (Opened, Preview, error) {
	pass, err := validatePassphrase(passphrase)
	if err != nil {
		return Opened{}, Preview{}, err
	}
	defer clear(pass)
	header, salt, nonce, ciphertext, err := parseHeader(encoded)
	if err != nil {
		return Opened{}, Preview{}, err
	}
	memory := binary.BigEndian.Uint32(header[12:16])
	iterations := binary.BigEndian.Uint32(header[16:20])
	threads := header[20]
	key := argon2.IDKey(pass, salt, iterations, memory, threads, KeyBytes)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return Opened{}, Preview{}, ErrAuthentication
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Opened{}, Preview{}, ErrAuthentication
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return Opened{}, Preview{}, ErrAuthentication
	}
	defer clear(plaintext)
	payload, err := decodePayload(plaintext)
	if err != nil {
		return Opened{}, Preview{}, err
	}
	defer destroyPayload(&payload)
	preview := Preview{
		Version:     Version,
		RecordCount: len(payload.Records),
		KindCounts:  make(map[RecordKind]int),
	}
	for _, record := range payload.Records {
		preview.KindCounts[record.Kind]++
	}
	return Opened{preview: clonePreview(preview), payload: clonePayload(payload)}, clonePreview(preview), nil
}

// Destroy clears the decrypted payload retained between preview and restore.
// Callers must invoke it when the opened backup handle is released.
func (opened *Opened) Destroy() {
	if opened == nil {
		return
	}
	destroyPayload(&opened.payload)
	opened.preview = Preview{}
}

// Restore returns exact backup members only after the caller's current Go trust
// and monotonic lifecycle verifier accepts every member. It never persists.
func Restore(opened Opened, expected Preview, verifier RestoreVerifier) (Payload, error) {
	if verifier == nil || !previewEqual(opened.preview, expected) ||
		opened.preview.Version != Version ||
		opened.preview.RecordCount != len(opened.payload.Records) {
		return Payload{}, ErrRestoreRejected
	}
	for _, record := range opened.payload.Records {
		candidate := cloneRecord(record)
		err := verifier.VerifyBackupRecord(candidate)
		clear(candidate.ExactBytes)
		if err != nil {
			return Payload{}, ErrRestoreRejected
		}
	}
	return clonePayload(opened.payload), nil
}

func encodeHeader(memory, iterations uint32, threads uint8, salt, nonce []byte, ciphertextLength int) []byte {
	out := make([]byte, fixedHeaderBytes+len(salt)+len(nonce))
	copy(out[:8], headerMagic)
	binary.BigEndian.PutUint16(out[8:10], headerVersion)
	out[10], out[11] = kdfArgon2id, cipherAES256GCM
	binary.BigEndian.PutUint32(out[12:16], memory)
	binary.BigEndian.PutUint32(out[16:20], iterations)
	out[20] = threads
	out[21], out[22], out[23] = byte(len(salt)), byte(len(nonce)), 0
	binary.BigEndian.PutUint32(out[24:28], uint32(ciphertextLength))
	copy(out[28:28+len(salt)], salt)
	copy(out[28+len(salt):], nonce)
	return out
}

func parseHeader(encoded []byte) (header, salt, nonce, ciphertext []byte, err error) {
	if len(encoded) < fixedHeaderBytes+SaltBytes+NonceBytes+16 ||
		len(encoded) > fixedHeaderBytes+SaltBytes+NonceBytes+MaxPayloadBytes+16 {
		return nil, nil, nil, nil, ErrInvalidHeader
	}
	fixed := encoded[:fixedHeaderBytes]
	if string(fixed[:8]) != headerMagic ||
		binary.BigEndian.Uint16(fixed[8:10]) != headerVersion ||
		fixed[10] != kdfArgon2id || fixed[11] != cipherAES256GCM ||
		fixed[21] != SaltBytes || fixed[22] != NonceBytes || fixed[23] != 0 {
		return nil, nil, nil, nil, ErrInvalidHeader
	}
	memory := binary.BigEndian.Uint32(fixed[12:16])
	iterations := binary.BigEndian.Uint32(fixed[16:20])
	threads := fixed[20]
	if memory < ArgonMemoryKiB || memory > MaxArgonMemoryKiB ||
		iterations < ArgonIterations || iterations > MaxArgonIterations ||
		threads < ArgonThreads || threads > MaxArgonThreads {
		return nil, nil, nil, nil, ErrResourceLimit
	}
	headerLength := fixedHeaderBytes + SaltBytes + NonceBytes
	ciphertextLength := int(binary.BigEndian.Uint32(fixed[24:28]))
	if ciphertextLength < 16 || ciphertextLength > MaxPayloadBytes+16 ||
		len(encoded) != headerLength+ciphertextLength {
		return nil, nil, nil, nil, ErrInvalidHeader
	}
	header = bytes.Clone(encoded[:headerLength])
	salt = bytes.Clone(encoded[fixedHeaderBytes : fixedHeaderBytes+SaltBytes])
	nonce = bytes.Clone(encoded[fixedHeaderBytes+SaltBytes : headerLength])
	ciphertext = bytes.Clone(encoded[headerLength:])
	return header, salt, nonce, ciphertext, nil
}

func validatePassphrase(passphrase string) ([]byte, error) {
	raw := []byte(passphrase)
	if !utf8.ValidString(passphrase) || len(raw) > MaximumPassBytes ||
		utf8.RuneCountInString(passphrase) < MinimumRunes {
		return nil, ErrInvalidPassphrase
	}
	return raw, nil
}

func encodePayload(payload Payload) ([]byte, error) {
	if payload.Version != 1 || len(payload.Records) > MaxRecords {
		return nil, ErrInvalidPayload
	}
	seen := make(map[string]struct{}, len(payload.Records))
	for _, record := range payload.Records {
		if !validRecord(record) {
			return nil, ErrInvalidPayload
		}
		key := string(rune(record.Kind)) + "\x00" + record.LocalID
		if _, exists := seen[key]; exists {
			return nil, ErrInvalidPayload
		}
		seen[key] = struct{}{}
	}
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, ErrInvalidPayload
	}
	encoded, err := mode.Marshal(payload)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxPayloadBytes {
		return nil, ErrInvalidPayload
	}
	return encoded, nil
}

func decodePayload(encoded []byte) (Payload, error) {
	if len(encoded) == 0 || len(encoded) > MaxPayloadBytes {
		return Payload{}, ErrInvalidPayload
	}
	options := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		MaxArrayElements:  MaxRecords,
		MaxMapPairs:       MaxRecords * 4,
		MaxNestedLevels:   8,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	mode, err := options.DecMode()
	if err != nil {
		return Payload{}, ErrInvalidPayload
	}
	var payload Payload
	if err := mode.Unmarshal(encoded, &payload); err != nil {
		return Payload{}, ErrInvalidPayload
	}
	canonical, err := encodePayload(payload)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Payload{}, ErrInvalidPayload
	}
	return payload, nil
}

func validRecord(record Record) bool {
	if record.Kind < RecordNativeProfile || record.Kind > RecordRoutingPreferences ||
		len(record.LocalID) == 0 || len(record.LocalID) > 64 ||
		len(record.ExactBytes) == 0 || len(record.ExactBytes) > MaxPayloadBytes {
		return false
	}
	for _, value := range record.LocalID {
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' {
			return false
		}
	}
	if (record.Kind == RecordNativeProfile || record.Kind == RecordVerifiedReceipt) &&
		record.Generation == 0 {
		return false
	}
	if record.Kind != RecordNativeProfile && record.Kind != RecordVerifiedReceipt &&
		record.Generation != 0 {
		return false
	}
	return true
}

func clonePayload(payload Payload) Payload {
	out := Payload{Version: payload.Version, Records: make([]Record, len(payload.Records))}
	for index, record := range payload.Records {
		out.Records[index] = cloneRecord(record)
	}
	return out
}

func destroyPayload(payload *Payload) {
	if payload == nil {
		return
	}
	for index := range payload.Records {
		clear(payload.Records[index].ExactBytes)
		payload.Records[index] = Record{}
	}
	clear(payload.Records)
	payload.Records = nil
	payload.Version = 0
}

func cloneRecord(record Record) Record {
	record.ExactBytes = bytes.Clone(record.ExactBytes)
	return record
}

func clonePreview(preview Preview) Preview {
	out := Preview{
		Version:     preview.Version,
		RecordCount: preview.RecordCount,
		KindCounts:  make(map[RecordKind]int, len(preview.KindCounts)),
	}
	for kind, count := range preview.KindCounts {
		out.KindCounts[kind] = count
	}
	return out
}

func previewEqual(a, b Preview) bool {
	if a.Version != b.Version || a.RecordCount != b.RecordCount ||
		len(a.KindCounts) != len(b.KindCounts) {
		return false
	}
	for kind, count := range a.KindCounts {
		if b.KindCounts[kind] != count {
			return false
		}
	}
	return true
}
