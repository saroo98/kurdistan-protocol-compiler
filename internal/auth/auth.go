// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"kurdistan/internal/ir"
)

func RandomSeed() (int64, error) {
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(b[:]) & (1<<63 - 1)), nil
}

func Key(p *ir.Profile) ([]byte, error) {
	key, err := hex.DecodeString(p.Auth.TestKeyHex)
	if err != nil {
		return nil, err
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("test key is too short")
	}
	return key, nil
}

func Proof(p *ir.Profile, transcript [][]byte, nonce []byte) ([]byte, error) {
	key, err := Key(p)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(p.ID))
	mac.Write([]byte{0})
	mac.Write(nonce)
	for _, item := range transcript {
		mac.Write([]byte{0})
		mac.Write(item)
	}
	return mac.Sum(nil), nil
}

func Verify(p *ir.Profile, transcript [][]byte, nonce, proof []byte) bool {
	expected, err := Proof(p, transcript, nonce)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, proof)
}

type ReplayCache struct {
	seen map[string]bool
}

func NewReplayCache() *ReplayCache {
	return &ReplayCache{seen: map[string]bool{}}
}

func (c *ReplayCache) Accept(nonce []byte) bool {
	if c == nil {
		return true
	}
	key := hex.EncodeToString(nonce)
	if c.seen[key] {
		return false
	}
	c.seen[key] = true
	return true
}
