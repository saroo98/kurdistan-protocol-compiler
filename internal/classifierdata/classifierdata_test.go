// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package classifierdata

import (
	"context"
	"testing"

	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wireeval"
)

func TestClassifierExportsAreDeterministicAndSafe(t *testing.T) {
	dataset, err := wireeval.BuildDataset(context.Background(), protocorpus.DefaultCorpus(), wireeval.BuildOptions{Controls: true})
	if err != nil {
		t.Fatal(err)
	}
	csvRaw, err := ExportCSV(dataset.Records)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCSV(csvRaw); err != nil {
		t.Fatal(err)
	}
	jsonlRaw, err := ExportJSONL(dataset.Records)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateJSONL(jsonlRaw); err != nil {
		t.Fatal(err)
	}
	if got := Report(dataset.Records, []string{"csv", "jsonl"}); !got.Passed || got.RecordCount != len(dataset.Records) {
		t.Fatalf("bad report: %+v", got)
	}
}

func TestForbiddenColumnRejected(t *testing.T) {
	if err := ValidateColumns(append(Columns(), "raw_bytes")); err == nil {
		t.Fatalf("forbidden column accepted")
	}
}
