// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import (
	"fmt"
	"strings"
)

func ValidateRecord(record WireEvalRecord) error {
	if record.DatasetVersion != string(Version) {
		return fmt.Errorf("%w: dataset version %q", ErrInvalidRecord, record.DatasetVersion)
	}
	if record.RecordID == "" || record.ProfileID == "" || record.Scenario == "" || record.Backend == "" {
		return fmt.Errorf("%w: missing identity fields", ErrInvalidRecord)
	}
	if !validSplit(record.Split) {
		return fmt.Errorf("%w: split %q", ErrInvalidRecord, record.Split)
	}
	if !validLabel(record.Label) {
		return fmt.Errorf("%w: label %q", ErrInvalidRecord, record.Label)
	}
	if record.FeatureHash == "" || record.ByteShapeHash == "" || record.FirstNShapeHash == "" {
		return fmt.Errorf("%w: missing feature hash", ErrInvalidRecord)
	}
	if record.PayloadLogged || record.SecretLogged {
		return ErrTraceLeak
	}
	return ScanForLeak(record)
}

func ValidateDataset(dataset Dataset) error {
	if dataset.Manifest.DatasetVersion != string(Version) {
		return fmt.Errorf("%w: manifest version %q", ErrInvalidDataset, dataset.Manifest.DatasetVersion)
	}
	if dataset.Manifest.RecordCount != len(dataset.Records) {
		return fmt.Errorf("%w: record count mismatch", ErrInvalidDataset)
	}
	for _, record := range dataset.Records {
		if err := ValidateRecord(record); err != nil {
			return err
		}
	}
	if dataset.Manifest.PayloadLogged || dataset.Manifest.SecretLogged {
		return ErrTraceLeak
	}
	if dataset.Manifest.DatasetHash != DatasetHash(dataset.Records) {
		return fmt.Errorf("%w: dataset hash mismatch", ErrInvalidDataset)
	}
	return nil
}

func ScanForLeak(value any) error {
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range ForbiddenColumns() {
		if strings.Contains(lower, `"`+marker+`"`) || strings.Contains(lower, marker+":") {
			return fmt.Errorf("%w: forbidden marker %s", ErrTraceLeak, marker)
		}
	}
	return nil
}

func validSplit(split DatasetSplit) bool {
	switch split {
	case SplitTrain, SplitTest, SplitOOD, SplitHoldout:
		return true
	default:
		return false
	}
}

func validLabel(label WireEvalLabel) bool {
	switch label {
	case LabelGeneratedKurdistan, LabelCorpusBaseline, LabelControlCollapsed, LabelControlPaddingOnly, LabelControlFixedShape, LabelControlNoise:
		return true
	default:
		return false
	}
}
