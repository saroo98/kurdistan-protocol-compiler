// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package labfault

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

var errInvalidV1 = errors.New("runtime_lab_fault_invalid")

const redactedV1 = "<runtime-lab-fault:redacted>"

type modeV1 uint8

const (
	modeReusedNonceV1 modeV1 = iota + 1
	modeAcceptsReplayV1
	modeRuntimeAcceptsReplayV1
	modeRuntimeNoStateValidationV1
	modeSecretTraceLeakV1
	modeRuntimeLeaksSecretTraceV1
	modeRuntimeLeaksPayloadTraceV1
	modeRuntimeIgnoresBackpressureV1
	modeRuntimePaddingOnlyDiversityV1
)

// Token is sealed, copyable lab authority with no exported state.
type Token struct {
	mode modeV1
	seal [32]byte
}

var sealKeyV1 = [32]byte{0x6d, 0x31, 0x97, 0x22, 0xaf, 0x41, 0x08, 0xdc, 0x55, 0xe2, 0x73, 0x19, 0x84, 0xbb, 0x0f, 0xc6, 0x2a, 0x90, 0x4e, 0xf1, 0x38, 0x67, 0xd5, 0x0b, 0x76, 0x13, 0xca, 0x9d, 0x44, 0xe8, 0x25, 0xb0}

func NewTokenV1(name string) (Token, error) {
	modes := map[string]modeV1{
		"reused_nonce":                   modeReusedNonceV1,
		"accepts_replay":                 modeAcceptsReplayV1,
		"runtime_accepts_replay":         modeRuntimeAcceptsReplayV1,
		"runtime_no_state_validation":    modeRuntimeNoStateValidationV1,
		"secret_trace_leak":              modeSecretTraceLeakV1,
		"runtime_leaks_secret_trace":     modeRuntimeLeaksSecretTraceV1,
		"runtime_leaks_payload_trace":    modeRuntimeLeaksPayloadTraceV1,
		"runtime_ignores_backpressure":   modeRuntimeIgnoresBackpressureV1,
		"runtime_padding_only_diversity": modeRuntimePaddingOnlyDiversityV1,
	}
	mode, ok := modes[name]
	if !ok {
		return Token{}, errInvalidV1
	}
	token := Token{mode: mode}
	token.seal = sealV1(mode)
	return token, nil
}

func sealV1(mode modeV1) [32]byte {
	mac := hmac.New(sha256.New, sealKeyV1[:])
	_, _ = mac.Write([]byte{0x72, byte(mode)})
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func (Token) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redactedV1) }
func (Token) MarshalJSON() ([]byte, error)   { return nil, errInvalidV1 }
func (*Token) UnmarshalJSON([]byte) error    { return errInvalidV1 }
func (Token) MarshalText() ([]byte, error)   { return nil, errInvalidV1 }
func (*Token) UnmarshalText([]byte) error    { return errInvalidV1 }
func (Token) MarshalBinary() ([]byte, error) { return nil, errInvalidV1 }
func (*Token) UnmarshalBinary([]byte) error  { return errInvalidV1 }
func (Token) GobEncode() ([]byte, error)     { return nil, errInvalidV1 }
func (*Token) GobDecode([]byte) error        { return errInvalidV1 }
