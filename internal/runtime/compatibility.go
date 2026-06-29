// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"fmt"

	"kurdistan/internal/ir"
	"kurdistan/internal/security"
)

func CheckRuntimeCompatibility(p *ir.Profile, compat security.RuntimeCompatibility) error {
	if err := security.CheckProfileCompatibility(p, compat); err != nil {
		return fmt.Errorf("%w: %v", ErrCompatibility, err)
	}
	return nil
}

func CheckPeerProfileMatch(a, b *ir.Profile) error {
	if a == nil || b == nil {
		return fmt.Errorf("%w: nil profile", ErrCompatibility)
	}
	if a.ID != b.ID || a.GenerationHash != b.GenerationHash {
		return fmt.Errorf("%w: profile mismatch", ErrCompatibility)
	}
	return nil
}
