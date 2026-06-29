// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

type KeySchedule struct {
	Suite           Suite  `json:"suite"`
	ClientWriteKey  []byte `json:"-"`
	ServerWriteKey  []byte `json:"-"`
	ClientNonceBase []byte `json:"-"`
	ServerNonceBase []byte `json:"-"`
	ExporterSecret  []byte `json:"-"`
}

func DeriveKeySchedule(inputSecret []byte, transcriptHash string, suite Suite) (KeySchedule, error) {
	if len(inputSecret) == 0 {
		return KeySchedule{}, fmt.Errorf("%w: empty input secret", ErrInvalidConfig)
	}
	if transcriptHash == "" {
		return KeySchedule{}, fmt.Errorf("%w: missing transcript hash", ErrInvalidTranscript)
	}
	if !SuiteSupported(suite) {
		return KeySchedule{}, ErrInvalidSuite
	}
	prk := hkdfExtract([]byte("kurdistan-key-schedule-v1:"+transcriptHash), inputSecret)
	return KeySchedule{
		Suite:           suite,
		ClientWriteKey:  hkdfExpand(prk, []byte("client_write"), 32),
		ServerWriteKey:  hkdfExpand(prk, []byte("server_write"), 32),
		ClientNonceBase: hkdfExpand(prk, []byte("client_nonce_base"), 12),
		ServerNonceBase: hkdfExpand(prk, []byte("server_nonce_base"), 12),
		ExporterSecret:  hkdfExpand(prk, []byte("exporter_secret"), 32),
	}, nil
}

func KeyScheduleTrace(k KeySchedule) map[string]any {
	return map[string]any{
		"suite":             k.Suite,
		"client_write_key":  "<redacted>",
		"server_write_key":  "<redacted>",
		"client_nonce_base": "<redacted>",
		"server_nonce_base": "<redacted>",
		"exporter_secret":   "<redacted>",
		"key_bytes":         len(k.ClientWriteKey),
		"nonce_base_bytes":  len(k.ClientNonceBase),
	}
}

func hkdfExtract(salt, secret []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	var out []byte
	var previous []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(previous)
		mac.Write([]byte("kurdistan-hkdf-v1/"))
		mac.Write(info)
		mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		out = append(out, previous...)
		counter++
	}
	return out[:length]
}
