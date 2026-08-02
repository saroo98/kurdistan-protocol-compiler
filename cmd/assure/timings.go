// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"

	"kurdistan/internal/assurance"
)

type gateTimingRecord struct {
	Schema         string `json:"schema"`
	StartedAt      string `json:"startedAt"`
	FinishedAt     string `json:"finishedAt"`
	DurationMillis int64  `json:"durationMillis"`
	Steps          []struct {
		Name           string `json:"name"`
		Status         string `json:"status"`
		DurationMillis int64  `json:"durationMillis"`
	} `json:"steps"`
}

type timingSummary struct {
	Schema string              `json:"schema"`
	Runs   int                 `json:"runs"`
	Total  timingPercentiles   `json:"total"`
	Steps  []stepTimingSummary `json:"steps"`
}

type timingPercentiles struct {
	P50Millis int64 `json:"p50Millis"`
	P95Millis int64 `json:"p95Millis"`
}

type stepTimingSummary struct {
	Name string `json:"name"`
	timingPercentiles
}

func runTimings(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("timings", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 0 {
		return errors.New("timings requires at least one timing file")
	}
	totals := make([]int64, 0, flags.NArg())
	byStep := map[string][]int64{}
	for _, path := range flags.Args() {
		raw, err := readRootFile(*root, path)
		if err != nil {
			return fmt.Errorf("read timing file %q: %w", path, err)
		}
		var record gateTimingRecord
		if err := assurance.DecodeStrict(bytes.NewReader(raw), &record); err != nil {
			return fmt.Errorf("decode timing file %q: %w", path, err)
		}
		if record.Schema != "kurdistan-gate-timings-v1" || record.DurationMillis < 0 || len(record.Steps) == 0 {
			return fmt.Errorf("timing file %q is invalid", path)
		}
		totals = append(totals, record.DurationMillis)
		seen := map[string]bool{}
		for _, step := range record.Steps {
			if step.Name == "" || seen[step.Name] || step.DurationMillis < 0 || (step.Status != "PASS" && step.Status != "FAIL") {
				return fmt.Errorf("timing file %q has invalid step", path)
			}
			seen[step.Name] = true
			byStep[step.Name] = append(byStep[step.Name], step.DurationMillis)
		}
	}
	summary := timingSummary{Schema: "kurdistan-timing-summary-v1", Runs: len(totals), Total: percentiles(totals)}
	names := make([]string, 0, len(byStep))
	for name := range byStep {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(byStep[name]) != len(totals) {
			return fmt.Errorf("step %q is absent from one or more runs", name)
		}
		summary.Steps = append(summary.Steps, stepTimingSummary{Name: name, timingPercentiles: percentiles(byStep[name])})
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func percentiles(values []int64) timingPercentiles {
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return timingPercentiles{P50Millis: nearestRank(sorted, 50), P95Millis: nearestRank(sorted, 95)}
}

func nearestRank(values []int64, percentile int) int64 {
	index := (percentile*len(values) + 99) / 100
	if index < 1 {
		index = 1
	}
	return values[index-1]
}
