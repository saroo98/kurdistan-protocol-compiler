// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"errors"
	"io"
	"os"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
)

const maxRuntimeProfileBytesV1 = 1 << 20

var checkRuntimeProfileCompatibilityV1 = security.CheckProfileCompatibility

func LoadProfile(path, expectedID string) (*ir.Profile, error) {
	if path == "" {
		return nil, newProfileLoadFailureV1(nil)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, newProfileLoadFailureV1(nil)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxRuntimeProfileBytesV1+1))
	if err != nil {
		return nil, newProfileLoadFailureV1(nil)
	}
	if len(raw) > maxRuntimeProfileBytesV1 {
		return nil, newProfileLoadFailureV1(ir.ErrProfileMalformed)
	}
	p, err := ir.DecodeProfileV1(raw)
	if err != nil {
		return nil, newProfileLoadFailureV1(profileDecodeCauseV1(err))
	}
	if expectedID != "" && p.ID != expectedID {
		return nil, newProfileLoadFailureV1(ir.ErrProfileMismatch)
	}
	return p, nil
}

func ValidateLoadedProfile(p *ir.Profile) error {
	if err := ir.Validate(p); err != nil {
		return newProfileLoadFailureV1(ir.ErrProfileInvalid)
	}
	return checkProfileCompatibilityV1(p)
}

func checkProfileCompatibilityV1(p *ir.Profile) error {
	if err := checkRuntimeProfileCompatibilityV1(p, security.DefaultRuntimeCompatibility()); err != nil {
		return ErrCompatibility
	}
	return nil
}

func profileDecodeCauseV1(err error) error {
	for _, cause := range []error{ir.ErrProfileMalformed, ir.ErrMigrationRequired, ir.ErrProfileVersionMismatch, ir.ErrProfileVersionUnsupported, ir.ErrProfileInvalid} {
		if errors.Is(err, cause) {
			return cause
		}
	}
	return ir.ErrProfileInvalid
}
