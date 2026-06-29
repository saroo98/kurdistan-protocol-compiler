// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

func controlPlan(seed int64, entry protocorpus.ProtocolShapeEntry) ControlPlan {
	preData := 0
	switch entry.ControlRichness {
	case "high":
		preData = 2
	case "moderate":
		preData = 1
	}
	return ControlPlan{
		Richness:        entry.ControlRichness,
		PreDataControls: preData,
		InterleaveClass: []string{"none", "sparse", "phase_bound", "dense"}[stableIndex(seed, "control-interleave:"+entry.Name, 4)],
		CloseClass:      []string{"explicit_close", "quiet_close", "control_close"}[stableIndex(seed, "control-close:"+entry.Name, 3)],
		ResetClass:      []string{"explicit_reset", "control_reset", "metadata_reset"}[stableIndex(seed, "control-reset:"+entry.Name, 3)],
	}
}
