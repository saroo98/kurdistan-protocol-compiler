// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

func ThresholdName(model ConfidenceModel) string {
	if model.Name == "" {
		return DefaultConfidenceModel().Name
	}
	return model.Name
}
