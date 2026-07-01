// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

func TimelineForScenario(s HealthScenario, active ActivePath) []HealthEvent {
	return timelineForScenario(s, active)
}
