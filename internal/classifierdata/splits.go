// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package classifierdata

import "kurdistan/internal/wireeval"

func SplitManifest(records []wireeval.WireEvalRecord, mode string) wireeval.SplitManifest {
	return wireeval.BuildSplitManifest(records, mode)
}
