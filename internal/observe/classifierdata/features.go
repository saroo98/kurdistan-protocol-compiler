// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package classifierdata

func DerivedColumns() []string {
	return []string{
		"packet_count_bucket",
		"direction_change_count_bucket",
		"unique_size_bucket_count",
		"fragment_count_bucket",
		"control_count_bucket",
		"metadata_visibility_bucket",
	}
}
