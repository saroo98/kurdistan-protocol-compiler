// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

func LogicalTime(index int, window ObservationWindow) int {
	switch window {
	case WindowShort:
		return index
	case WindowMedium:
		return index * 3
	case WindowLong:
		return index * 11
	case WindowBurst:
		return (index / 5) * 10
	case WindowSteady:
		return index * 5
	case WindowMixed:
		return index*2 + index%3
	default:
		return index
	}
}

func ValidateWindow(window ObservationWindow) error {
	for _, allowed := range FullTimelineWindows() {
		if window == allowed {
			return nil
		}
	}
	return ErrInvalidObservation
}
