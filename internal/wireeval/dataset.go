// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

func Records(dataset Dataset) []WireEvalRecord {
	out := make([]WireEvalRecord, len(dataset.Records))
	copy(out, dataset.Records)
	return out
}

func DatasetSplitCounts(dataset Dataset) map[string]int {
	out := map[string]int{}
	for _, record := range dataset.Records {
		out[string(record.Split)]++
	}
	return out
}
