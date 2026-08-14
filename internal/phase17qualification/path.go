// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

// ValidateNoLinkedPath rejects any path whose existing component is a
// symbolic link or Windows reparse point. It deliberately avoids textual
// canonical-path comparison because Windows short-name aliases can resolve to
// a different spelling without crossing a link.
func ValidateNoLinkedPath(path string) error {
	return validateNoLinkedPath(path)
}
