// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package classifierdata

import "kurdistan/internal/wireeval"

func ControlRecords(records []wireeval.WireEvalRecord) []wireeval.WireEvalRecord {
	return wireeval.ControlRecords(records)
}
