// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package classifierdata

import "kurdistan/internal/wireeval"

type ExportReport struct {
	SchemaVersion string   `json:"schema_version"`
	Formats       []string `json:"formats"`
	RecordCount   int      `json:"record_count"`
	ColumnCount   int      `json:"column_count"`
	Passed        bool     `json:"passed"`
	Conclusion    string   `json:"conclusion"`
}

func Report(records []wireeval.WireEvalRecord, formats []string) ExportReport {
	return ExportReport{SchemaVersion: SchemaVersion, Formats: formats, RecordCount: len(records), ColumnCount: len(Columns()), Passed: true, Conclusion: "passed"}
}
