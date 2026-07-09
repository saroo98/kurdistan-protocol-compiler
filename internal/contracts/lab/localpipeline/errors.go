// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localpipeline

import "fmt"

func safeError(code string) error {
	return fmt.Errorf("localpipeline_%s", code)
}
