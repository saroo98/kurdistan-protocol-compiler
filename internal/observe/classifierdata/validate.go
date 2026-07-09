// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package classifierdata

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func ValidateColumns(columns []string) error {
	seen := map[string]bool{}
	for _, column := range columns {
		lower := strings.ToLower(column)
		if seen[lower] {
			return fmt.Errorf("duplicate classifier column %s", column)
		}
		seen[lower] = true
		for _, forbidden := range ForbiddenColumns() {
			if lower == forbidden {
				return fmt.Errorf("forbidden classifier column %s", column)
			}
		}
	}
	for _, required := range Columns() {
		if !seen[required] {
			return fmt.Errorf("missing classifier column %s", required)
		}
	}
	return nil
}

func ValidateCSV(raw []byte) error {
	reader := csv.NewReader(strings.NewReader(string(raw)))
	rows, err := reader.ReadAll()
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("empty csv dataset")
	}
	return ValidateColumns(rows[0])
}

func ValidateJSONL(raw []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	count := 0
	for {
		var row map[string]string
		if err := dec.Decode(&row); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if err := ValidateColumns(mapKeys(row)); err != nil {
			return err
		}
		if _, err := strconv.Atoi(row["profile_seed"]); err != nil {
			return fmt.Errorf("invalid profile_seed")
		}
		count++
	}
	if count == 0 {
		return fmt.Errorf("empty jsonl dataset")
	}
	return nil
}

func mapKeys(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	return out
}
