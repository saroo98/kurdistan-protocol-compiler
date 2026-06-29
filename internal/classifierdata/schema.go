// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package classifierdata

import "kurdistan/internal/wireeval"

const SchemaVersion = "classifierdata-v1"

func Columns() []string {
	return wireeval.RequiredColumns()
}

func ForbiddenColumns() []string {
	return wireeval.ForbiddenColumns()
}
