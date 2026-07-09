// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
)

type SecureEnvelope struct {
	Sequence        uint64 `json:"sequence"`
	StreamID        uint64 `json:"stream_id"`
	Semantic        string `json:"semantic"`
	CarrierFamily   string `json:"carrier_family"`
	TranscriptHash  string `json:"transcript_hash"`
	CapabilityHash  string `json:"capability_hash"`
	Nonce           []byte `json:"-"`
	Ciphertext      []byte `json:"-"`
	CiphertextBytes int    `json:"ciphertext_bytes"`
	AuthTagBytes    int    `json:"auth_tag_bytes"`
	MetadataClass   string `json:"metadata_class"`
}

type EnvelopeMetadata struct {
	StreamID      uint64
	Semantic      string
	CarrierFamily string
	MetadataClass string
}

type EnvelopeCodec struct {
	ctx    SecurityContext
	aead   cipher.AEAD
	nonces *NonceManager
	replay *ReplayWindow
}

func NewEnvelopeCodec(ctx SecurityContext, keys KeySchedule, direction string) (*EnvelopeCodec, error) {
	var key []byte
	var base []byte
	if direction == "server" {
		key = keys.ServerWriteKey
		base = keys.ServerNonceBase
	} else {
		key = keys.ClientWriteKey
		base = keys.ClientNonceBase
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: invalid key length", ErrInvalidConfig)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &EnvelopeCodec{
		ctx:    ctx,
		aead:   aead,
		nonces: NewNonceManager(direction, base, "directional_counter"),
		replay: NewReplayWindow("windowed_replay", 64),
	}, nil
}

func (c *EnvelopeCodec) Seal(meta EnvelopeMetadata, plaintext []byte) (SecureEnvelope, error) {
	if meta.Semantic == "" || meta.CarrierFamily == "" {
		return SecureEnvelope{}, fmt.Errorf("%w: missing metadata", ErrEnvelopeRejected)
	}
	nonce, seq, err := c.nonces.Next()
	if err != nil {
		return SecureEnvelope{}, err
	}
	env := SecureEnvelope{
		Sequence:       seq,
		StreamID:       meta.StreamID,
		Semantic:       meta.Semantic,
		CarrierFamily:  meta.CarrierFamily,
		TranscriptHash: c.ctx.TranscriptHash,
		CapabilityHash: c.ctx.CapabilityHash,
		Nonce:          nonce,
		MetadataClass:  meta.MetadataClass,
		AuthTagBytes:   c.aead.Overhead(),
	}
	env.Ciphertext = c.aead.Seal(nil, nonce, plaintext, envelopeAAD(env))
	env.CiphertextBytes = len(env.Ciphertext)
	return env, nil
}

func (c *EnvelopeCodec) Open(env SecureEnvelope) ([]byte, error) {
	if env.TranscriptHash != c.ctx.TranscriptHash {
		return nil, ErrTranscriptMismatch
	}
	if env.CapabilityHash != c.ctx.CapabilityHash {
		return nil, ErrCapabilityMismatch
	}
	if len(env.Nonce) != c.aead.NonceSize() || len(env.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: malformed envelope", ErrEnvelopeRejected)
	}
	if err := c.replay.Accept(env.Sequence); err != nil {
		return nil, err
	}
	return c.aead.Open(nil, env.Nonce, env.Ciphertext, envelopeAAD(env))
}

func envelopeAAD(env SecureEnvelope) []byte {
	raw, _ := json.Marshal(struct {
		Sequence       uint64 `json:"sequence"`
		StreamID       uint64 `json:"stream_id"`
		Semantic       string `json:"semantic"`
		CarrierFamily  string `json:"carrier_family"`
		TranscriptHash string `json:"transcript_hash"`
		CapabilityHash string `json:"capability_hash"`
		MetadataClass  string `json:"metadata_class"`
	}{
		Sequence:       env.Sequence,
		StreamID:       env.StreamID,
		Semantic:       env.Semantic,
		CarrierFamily:  env.CarrierFamily,
		TranscriptHash: env.TranscriptHash,
		CapabilityHash: env.CapabilityHash,
		MetadataClass:  env.MetadataClass,
	})
	return raw
}
