// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package classifierdata

import (
	"bytes"
	"encoding/csv"
	"strconv"
	"strings"

	"kurdistan/internal/wireeval"
)

func ExportCSV(records []wireeval.WireEvalRecord) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(Columns()); err != nil {
		return nil, err
	}
	for _, record := range records {
		if err := wireeval.ValidateRecord(record); err != nil {
			return nil, err
		}
		if err := w.Write(recordRow(record)); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func recordRow(r wireeval.WireEvalRecord) []string {
	return []string{
		r.RecordID,
		r.ProfileID,
		strconv.Itoa(r.ProfileSeed),
		r.Scenario,
		r.Backend,
		string(r.Split),
		string(r.Label),
		r.SelectedFamily,
		r.SelectedCorpusEntry,
		r.PhaseShape,
		r.FieldLayoutClass,
		r.FirstNShapeHash,
		strings.Join(r.DirectionSequence, "|"),
		strings.Join(r.PacketSizeBuckets, "|"),
		strings.Join(r.FrameSizeBuckets, "|"),
		r.FragmentRhythm,
		r.ControlRichness,
		r.MetadataExposure,
		r.BackpressureClass,
		r.ResetCloseClass,
		r.ErrorMappingClass,
		r.FeatureHash,
		r.ByteShapeHash,
	}
}
