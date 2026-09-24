//go:build phase9internal && phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import "testing"

func TestTask7MaintenanceActualCGoOutputEntry(t *testing.T) {
	for _, mode := range []uint8{0, 1, 2, 3, 4, 5} {
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			closeStatus := int32(0)
			if mode == 5 {
				closeStatus = 18
			}
			parent := testTask7MaintenanceParentV1(t, maintenanceFacadeOpeningFixtureV1(t), closeStatus)
			out, status, commit := testTask7MaintenanceCGoV1(parent, 3, 24, mode)
			if mode == 0 {
				if status != 0 || !commit || out[0] != 1 || out[1] != 3 || out[2] != 1 || out[3] != 0 || out[7] != 0 || out[18] != 1 || out[19] != 0 || out[20] != 0 || out[21] != 0 || out[22] != -1 || out[23] != -1 {
					t.Fatal("actual entry", status, commit, out)
				}
			} else {
				if status == 0 || commit {
					t.Fatal("failed fence published", mode, status)
				}
				for _, v := range out {
					if v != -1 {
						t.Fatal("failed fence changed caller output")
					}
				}
			}
		})
	}
}
func TestTask7MaintenanceActualCGoPreflightAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		caseID, length uint32
		cancel         bool
	}{{0, 24, false}, {4, 24, false}, {3, 23, false}, {3, 25, false}, {3, 24, true}} {
		t.Run("preflight", func(t *testing.T) {
			parent := testMaintenanceCanonicalParentV1(t, maintenanceFacadeOpeningFixtureV1(t))
			if tc.cancel && testMaintenanceCanonicalCancelCallV1(parent) != 0 {
				t.Fatal("real cancellation failed")
			}
			out, status, commit := testTask7MaintenanceCGoV1(parent, tc.caseID, tc.length, 0)
			if status == 0 || commit {
				t.Fatal("invalid call published")
			}
			for _, v := range out {
				if v != -1 {
					t.Fatal("invalid output")
				}
			}
		})
	}
}
