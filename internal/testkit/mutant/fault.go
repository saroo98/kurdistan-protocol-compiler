// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package mutant

import (
	"errors"
	"fmt"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/runtime/labfault"
)

var ErrInvalidLabFault = errors.New("invalid lab fault capability")

var authFaultModes = map[string]bool{
	ModeNoTranscriptBinding: true, ModeAcceptsDowngrade: true,
	ModeCapabilityMismatchAccepted: true, ModeProfileMismatchAccepted: true,
	ModeUnsafeConfigAllowed: true, ModeRuntimeAcceptsCapabilityDowngrade: true,
	ModeRuntimeAcceptsProfileMismatch: true,
}

var runtimeLabFaultModes = map[string]bool{
	ModeReusedNonce: true, ModeAcceptsReplay: true, ModeSecretTraceLeak: true,
	ModeRuntimeAcceptsReplay: true, ModeRuntimeIgnoresBackpressure: true,
	ModeRuntimeLeaksSecretTrace: true, ModeRuntimeLeaksPayloadTrace: true,
	ModeRuntimeNoStateValidation: true, ModeRuntimePaddingOnlyDiversity: true,
}

func AcquireAuthFaultV1(mode string) (auth.AuthLabFaultToken, error) {
	if !authFaultModes[mode] {
		return auth.AuthLabFaultToken{}, fmt.Errorf("%w: unsupported auth mode", ErrInvalidLabFault)
	}
	token, err := auth.NewAuthLabFaultTokenV1(mode)
	if err != nil {
		return auth.AuthLabFaultToken{}, fmt.Errorf("%w: auth mint failed", ErrInvalidLabFault)
	}
	return token, nil
}

func AcquireRuntimeLabFaultV1(mode string) (labfault.Token, error) {
	if !runtimeLabFaultModes[mode] {
		return labfault.Token{}, fmt.Errorf("%w: unsupported runtime mode", ErrInvalidLabFault)
	}
	token, err := labfault.NewTokenV1(mode)
	if err != nil {
		return labfault.Token{}, fmt.Errorf("%w: runtime mint failed", ErrInvalidLabFault)
	}
	return token, nil
}
