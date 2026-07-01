// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

func SchedulerClasses() []string {
	return []string{"scheduler_policy_bucket", "interactive_first_bucket", "weighted_round_robin_bucket"}
}
