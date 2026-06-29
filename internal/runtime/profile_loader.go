// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"encoding/json"
	"fmt"
	"os"

	"kurdistan/internal/ir"
	"kurdistan/internal/security"
)

func LoadProfile(path, expectedID string) (*ir.Profile, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: missing profile path", ErrProfileLoad)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProfileLoad, err)
	}
	var p ir.Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: malformed profile JSON", ErrProfileLoad)
	}
	if expectedID != "" && p.ID != expectedID {
		return nil, fmt.Errorf("%w: profile id mismatch", ErrProfileLoad)
	}
	if err := ValidateLoadedProfile(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func ValidateLoadedProfile(p *ir.Profile) error {
	if err := ir.Validate(p); err != nil {
		return fmt.Errorf("%w: %v", ErrProfileLoad, err)
	}
	if p.Security.SecurityVersion == "" {
		return fmt.Errorf("%w: missing security policy", ErrProfileLoad)
	}
	if err := security.CheckProfileCompatibility(p, security.DefaultRuntimeCompatibility()); err != nil {
		return fmt.Errorf("%w: %v", ErrCompatibility, err)
	}
	return nil
}
