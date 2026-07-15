// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

var errAuthLabFaultInvalidV1 = errors.New("auth_lab_fault_invalid")

const authLabFaultRedactedV1 = "<auth-lab-fault:redacted>"

type authLabFaultModeV1 uint8

const (
	authLabFaultNoTranscriptV1 authLabFaultModeV1 = iota + 1
	authLabFaultAcceptsDowngradeV1
	authLabFaultCapabilityMismatchV1
	authLabFaultProfileMismatchV1
	authLabFaultRuntimeCapabilityV1
	authLabFaultRuntimeProfileV1
	authLabFaultUnsafeConfigV1
)

// AuthLabFaultToken is concrete, sealed, copyable lab authority. It has no
// exported state and deliberately cannot be serialized or reconstructed.
type AuthLabFaultToken struct {
	mode authLabFaultModeV1
	seal [32]byte
}

var authLabFaultSealKeyV1 = [32]byte{0x91, 0x37, 0x54, 0xa2, 0x06, 0x7d, 0xe3, 0x48, 0xbb, 0x19, 0xc5, 0x62, 0x73, 0x0d, 0xf1, 0x2a, 0x44, 0x86, 0x9b, 0xce, 0x35, 0x5f, 0x08, 0xd4, 0x6a, 0xe7, 0x21, 0x9c, 0x03, 0xb8, 0x65, 0xfa}

func NewAuthLabFaultTokenV1(name string) (AuthLabFaultToken, error) {
	modes := map[string]authLabFaultModeV1{
		"no_transcript_binding": authLabFaultNoTranscriptV1, "accepts_downgrade": authLabFaultAcceptsDowngradeV1,
		"capability_mismatch_accepted": authLabFaultCapabilityMismatchV1, "profile_mismatch_accepted": authLabFaultProfileMismatchV1,
		"runtime_accepts_capability_downgrade": authLabFaultRuntimeCapabilityV1, "runtime_accepts_profile_mismatch": authLabFaultRuntimeProfileV1,
		"unsafe_config_allowed": authLabFaultUnsafeConfigV1,
	}
	mode, ok := modes[name]
	if !ok {
		return AuthLabFaultToken{}, errAuthLabFaultInvalidV1
	}
	token := AuthLabFaultToken{mode: mode}
	token.seal = authLabFaultSealV1(mode)
	return token, nil
}

func authLabFaultSealV1(mode authLabFaultModeV1) [32]byte {
	mac := hmac.New(sha256.New, authLabFaultSealKeyV1[:])
	_, _ = mac.Write([]byte{"k"[0], byte(mode)})
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func validAuthLabFaultV1(token AuthLabFaultToken) bool {
	if token.mode < authLabFaultNoTranscriptV1 || token.mode > authLabFaultUnsafeConfigV1 {
		return false
	}
	want := authLabFaultSealV1(token.mode)
	return hmac.Equal(token.seal[:], want[:])
}

func (AuthLabFaultToken) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, authLabFaultRedactedV1)
}
func (AuthLabFaultToken) MarshalJSON() ([]byte, error)   { return nil, errAuthLabFaultInvalidV1 }
func (*AuthLabFaultToken) UnmarshalJSON([]byte) error    { return errAuthLabFaultInvalidV1 }
func (AuthLabFaultToken) MarshalText() ([]byte, error)   { return nil, errAuthLabFaultInvalidV1 }
func (*AuthLabFaultToken) UnmarshalText([]byte) error    { return errAuthLabFaultInvalidV1 }
func (AuthLabFaultToken) MarshalBinary() ([]byte, error) { return nil, errAuthLabFaultInvalidV1 }
func (*AuthLabFaultToken) UnmarshalBinary([]byte) error  { return errAuthLabFaultInvalidV1 }
func (AuthLabFaultToken) GobEncode() ([]byte, error)     { return nil, errAuthLabFaultInvalidV1 }
func (*AuthLabFaultToken) GobDecode([]byte) error        { return errAuthLabFaultInvalidV1 }

func applyAuthLabInputFaultV1(token AuthLabFaultToken, input FirstContactInput) (FirstContactInput, error) {
	if !validAuthLabFaultV1(token) {
		return FirstContactInput{}, errAuthLabFaultInvalidV1
	}
	switch token.mode {
	case authLabFaultAcceptsDowngradeV1:
		selected := input.SelectedPolicy.Clone()
		input.Client.OfferPolicy, input.Client.FloorPolicy = selected.Clone(), selected.Clone()
		input.Server.OfferPolicy, input.Server.FloorPolicy = selected.Clone(), selected.Clone()
	case authLabFaultCapabilityMismatchV1, authLabFaultRuntimeCapabilityV1:
		input.SelectedCapabilities = append([]string(nil), input.SelectedPolicy.SelectedCapabilities...)
	case authLabFaultProfileMismatchV1, authLabFaultRuntimeProfileV1:
		input.Server.ProfileID, input.Server.ProfileHash = input.Client.ProfileID, input.Client.ProfileHash
		input.Server.OfferPolicy.ProfileID, input.Server.OfferPolicy.ProfileHash = input.Client.ProfileID, input.Client.OfferPolicy.ProfileHash
		input.Server.FloorPolicy.ProfileID, input.Server.FloorPolicy.ProfileHash = input.Client.ProfileID, input.Client.FloorPolicy.ProfileHash
	}
	var err error
	input.Client.seal, err = sealPeerParameters(input.Client)
	if err != nil {
		return FirstContactInput{}, errAuthLabFaultInvalidV1
	}
	input.Server.seal, err = sealPeerParameters(input.Server)
	if err != nil {
		return FirstContactInput{}, errAuthLabFaultInvalidV1
	}
	return input, nil
}

func RuntimeAcceptsCapabilityDowngradeAuthLabFaultV1(token AuthLabFaultToken, input *FirstContactInput) bool {
	if input == nil || !validAuthLabFaultV1(token) || token.mode != authLabFaultRuntimeCapabilityV1 {
		return false
	}
	repaired, err := applyAuthLabInputFaultV1(token, *input)
	if err != nil {
		return false
	}
	*input = repaired
	return true
}

func RuntimeAcceptsProfileMismatchAuthLabFaultV1(token AuthLabFaultToken, input *FirstContactInput) bool {
	if input == nil || !validAuthLabFaultV1(token) || token.mode != authLabFaultRuntimeProfileV1 {
		return false
	}
	repaired, err := applyAuthLabInputFaultV1(token, *input)
	if err != nil {
		return false
	}
	*input = repaired
	return true
}

func UnsafeConfigAllowedAuthLabFaultV1(token AuthLabFaultToken) bool {
	return validAuthLabFaultV1(token) && token.mode == authLabFaultUnsafeConfigV1
}
