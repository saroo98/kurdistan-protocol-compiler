// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

type WireEvalComparisonReport struct {
	DatasetVersion     string   `json:"dataset_version"`
	OldRecordCount     int      `json:"old_record_count"`
	NewRecordCount     int      `json:"new_record_count"`
	AddedRecords       int      `json:"added_records"`
	RemovedRecords     int      `json:"removed_records"`
	ChangedRecords     int      `json:"changed_records"`
	SplitDrift         []string `json:"split_drift,omitempty"`
	LabelDrift         []string `json:"label_drift,omitempty"`
	FeatureDrift       []string `json:"feature_drift,omitempty"`
	HashDrift          []string `json:"hash_drift,omitempty"`
	AllowedDifferences []string `json:"allowed_differences,omitempty"`
	UnexpectedDrift    []string `json:"unexpected_drift,omitempty"`
	PayloadLogged      bool     `json:"payload_logged"`
	SecretLogged       bool     `json:"secret_logged"`
	Conclusion         string   `json:"conclusion"`
}

func CompareDatasets(oldDataset, newDataset Dataset) WireEvalComparisonReport {
	oldMap := recordMap(oldDataset.Records)
	newMap := recordMap(newDataset.Records)
	report := WireEvalComparisonReport{
		DatasetVersion: string(Version),
		OldRecordCount: len(oldDataset.Records),
		NewRecordCount: len(newDataset.Records),
		Conclusion:     "passed",
	}
	for key, oldRecord := range oldMap {
		newRecord, ok := newMap[key]
		if !ok {
			report.RemovedRecords++
			report.UnexpectedDrift = append(report.UnexpectedDrift, "removed:"+key)
			continue
		}
		if oldRecord.Split != newRecord.Split {
			report.SplitDrift = append(report.SplitDrift, key)
		}
		if oldRecord.Label != newRecord.Label {
			report.LabelDrift = append(report.LabelDrift, key)
		}
		if oldRecord.FeatureHash != newRecord.FeatureHash || oldRecord.FirstNShapeHash != newRecord.FirstNShapeHash {
			report.FeatureDrift = append(report.FeatureDrift, key)
		}
		if oldRecord.ByteShapeHash != newRecord.ByteShapeHash {
			report.HashDrift = append(report.HashDrift, key)
		}
	}
	for key := range newMap {
		if _, ok := oldMap[key]; !ok {
			report.AddedRecords++
			report.UnexpectedDrift = append(report.UnexpectedDrift, "added:"+key)
		}
	}
	report.ChangedRecords = len(report.SplitDrift) + len(report.LabelDrift) + len(report.FeatureDrift) + len(report.HashDrift)
	report.PayloadLogged = oldDataset.Manifest.PayloadLogged || newDataset.Manifest.PayloadLogged
	report.SecretLogged = oldDataset.Manifest.SecretLogged || newDataset.Manifest.SecretLogged
	if report.ChangedRecords+report.AddedRecords+report.RemovedRecords > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func recordMap(records []WireEvalRecord) map[string]WireEvalRecord {
	out := map[string]WireEvalRecord{}
	for _, record := range records {
		out[record.RecordID] = record
	}
	return out
}
