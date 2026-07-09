// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

type HostDetectVersion string
type SyntheticHostID string
type HostClass string
type ObservationWindow string

const (
	Version          HostDetectVersion = "hostdetect-v1"
	FixedGeneratedAt                   = "2026-06-30T00:00:00Z"

	HostClassGeneratedRelay HostClass = "generated_relay"
	HostClassCorpusBaseline HostClass = "corpus_baseline"
	HostClassControlFixed   HostClass = "control_fixed"
	HostClassControlPadding HostClass = "control_padding_only"
	HostClassControlNoise   HostClass = "control_noise"

	WindowShort  ObservationWindow = "short"
	WindowMedium ObservationWindow = "medium"
	WindowLong   ObservationWindow = "long"
	WindowBurst  ObservationWindow = "burst"
	WindowSteady ObservationWindow = "steady"
	WindowMixed  ObservationWindow = "mixed"

	AssignSingleLongLived  = "single_long_lived_host"
	AssignManyHostsUniform = "many_hosts_uniform"
	AssignProfilePinned    = "profile_pinned_hosts"
	AssignFamilyPinned     = "family_pinned_hosts"
	AssignScenarioPinned   = "scenario_pinned_hosts"
	AssignRotatingProfile  = "rotating_profile_hosts"
	AssignMixedRotation    = "mixed_rotation_hosts"
	AssignControlCollapsed = "control_collapsed_hosts"
)

func DefaultAssignmentModes() []string {
	return []string{AssignManyHostsUniform, AssignProfilePinned, AssignMixedRotation}
}

func FullAssignmentModes() []string {
	return []string{
		AssignSingleLongLived,
		AssignManyHostsUniform,
		AssignProfilePinned,
		AssignFamilyPinned,
		AssignScenarioPinned,
		AssignRotatingProfile,
		AssignMixedRotation,
		AssignControlCollapsed,
	}
}

func DefaultTimelineWindows() []ObservationWindow {
	return []ObservationWindow{WindowShort, WindowMedium}
}

func FullTimelineWindows() []ObservationWindow {
	return []ObservationWindow{WindowShort, WindowMedium, WindowLong, WindowBurst, WindowSteady, WindowMixed}
}
