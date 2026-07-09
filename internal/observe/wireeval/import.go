// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import "encoding/json"

func ParseDataset(raw []byte) (Dataset, error) {
	var dataset Dataset
	if err := json.Unmarshal(raw, &dataset); err != nil {
		return Dataset{}, err
	}
	return dataset, ValidateDataset(dataset)
}
