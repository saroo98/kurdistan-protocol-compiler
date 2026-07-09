// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

type LeakageReport struct {
	Scanned    int      `json:"scanned"`
	Findings   []string `json:"findings,omitempty"`
	Passed     bool     `json:"passed"`
	Conclusion string   `json:"conclusion"`
}

func ScanDatasetForLeakage(dataset Dataset) LeakageReport {
	report := LeakageReport{Scanned: len(dataset.Records), Passed: true, Conclusion: "passed"}
	if err := ScanForLeak(dataset.Manifest); err != nil {
		report.Findings = append(report.Findings, "manifest:"+err.Error())
	}
	for _, record := range dataset.Records {
		if err := ScanForLeak(record); err != nil {
			report.Findings = append(report.Findings, record.RecordID+":"+err.Error())
		}
	}
	if len(report.Findings) > 0 {
		report.Passed = false
		report.Conclusion = "failed"
	}
	return report
}
