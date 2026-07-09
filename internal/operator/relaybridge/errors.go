// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

import "fmt"

func safeError(class string) error {
	return fmt.Errorf("relaybridge rejected %s", class)
}
