// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

func SafeErrorClasses() []string {
	return []string{"target_error_bucket", "bridge_failure_bucket", "candidate_blocked_bucket"}
}
