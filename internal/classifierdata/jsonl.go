// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package classifierdata

import (
	"bytes"
	"encoding/json"

	"kurdistan/internal/wireeval"
)

func ExportJSONL(records []wireeval.WireEvalRecord) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, record := range records {
		if err := wireeval.ValidateRecord(record); err != nil {
			return nil, err
		}
		if err := enc.Encode(recordMap(record)); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func recordMap(r wireeval.WireEvalRecord) map[string]any {
	row := recordRow(r)
	columns := Columns()
	out := make(map[string]any, len(columns))
	for i, column := range columns {
		out[column] = row[i]
	}
	return out
}
