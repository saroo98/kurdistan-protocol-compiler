// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

type ClassifierReadinessReport struct {
	DatasetVersion     string         `json:"dataset_version"`
	ExportFormats      []string       `json:"export_formats"`
	RecordCount        int            `json:"record_count"`
	FeatureColumnCount int            `json:"feature_column_count"`
	TrainCount         int            `json:"train_count"`
	TestCount          int            `json:"test_count"`
	OODCount           int            `json:"ood_count"`
	HoldoutCount       int            `json:"holdout_count"`
	LabelCounts        map[string]int `json:"label_counts"`
	MissingColumns     []string       `json:"missing_columns,omitempty"`
	ForbiddenColumns   []string       `json:"forbidden_columns,omitempty"`
	SplitViolations    []string       `json:"split_violations,omitempty"`
	LeakageFindings    []string       `json:"leakage_findings,omitempty"`
	PayloadLogged      bool           `json:"payload_logged"`
	SecretLogged       bool           `json:"secret_logged"`
	Conclusion         string         `json:"conclusion"`
}

func ClassifierReadiness(records []WireEvalRecord, columns []string, formats []string) ClassifierReadinessReport {
	report := ClassifierReadinessReport{
		DatasetVersion:     string(Version),
		ExportFormats:      append([]string(nil), formats...),
		RecordCount:        len(records),
		FeatureColumnCount: len(columns),
		LabelCounts:        map[string]int{},
		Conclusion:         "passed",
	}
	present := map[string]bool{}
	for _, column := range columns {
		present[column] = true
	}
	for _, required := range RequiredColumns() {
		if !present[required] {
			report.MissingColumns = append(report.MissingColumns, required)
		}
	}
	for _, forbidden := range ForbiddenColumns() {
		if present[forbidden] {
			report.ForbiddenColumns = append(report.ForbiddenColumns, forbidden)
		}
	}
	for _, record := range records {
		switch record.Split {
		case SplitTrain:
			report.TrainCount++
		case SplitTest:
			report.TestCount++
		case SplitOOD:
			report.OODCount++
		case SplitHoldout:
			report.HoldoutCount++
		default:
			report.SplitViolations = append(report.SplitViolations, record.RecordID)
		}
		report.LabelCounts[string(record.Label)]++
		report.PayloadLogged = report.PayloadLogged || record.PayloadLogged
		report.SecretLogged = report.SecretLogged || record.SecretLogged
		if err := ScanForLeak(record); err != nil {
			report.LeakageFindings = append(report.LeakageFindings, record.RecordID)
		}
	}
	if report.TrainCount == 0 || report.TestCount == 0 || report.OODCount == 0 {
		report.SplitViolations = append(report.SplitViolations, "missing required split")
	}
	if len(report.MissingColumns)+len(report.ForbiddenColumns)+len(report.SplitViolations)+len(report.LeakageFindings) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}
