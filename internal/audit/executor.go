// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

func CanonicalAuditReportsEqual(left, right AuditReport) error {
	leftRaw, err := canonicalAuditReportJSON(left)
	if err != nil {
		return err
	}
	rightRaw, err := canonicalAuditReportJSON(right)
	if err != nil {
		return err
	}
	if !bytes.Equal(leftRaw, rightRaw) {
		return fmt.Errorf("canonical audit reports differ")
	}
	return nil
}

func canonicalAuditReportJSON(report AuditReport) ([]byte, error) {
	report.GeneratedAt = ""
	report.BenchmarkSummary = nil
	return json.Marshal(report)
}

type ExecutorMode string

const (
	ExecutorSerial   ExecutorMode = "serial"
	ExecutorParallel ExecutorMode = "parallel"
)

type ExecutorOptions struct {
	Mode    ExecutorMode
	Workers int
}

func validateExecutorOptions(options ExecutorOptions) error {
	if options.Workers < 1 {
		return fmt.Errorf("audit executor workers must be positive")
	}
	if options.Mode != ExecutorSerial && options.Mode != ExecutorParallel {
		return fmt.Errorf("unknown audit executor %q", options.Mode)
	}
	return nil
}

type familyValues map[string]any

type auditFamily struct {
	ID           string
	Dependencies []string
	Run          func(context.Context, familyValues) (any, error)
}

type auditFamilyResult struct {
	ID    string
	Value any
	Err   error
}

func executeAuditFamilies(ctx context.Context, options ExecutorOptions, families []auditFamily) ([]auditFamilyResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateExecutorOptions(options); err != nil {
		return nil, err
	}
	if err := validateAuditFamilyRegistry(families); err != nil {
		return nil, err
	}
	pending := make(map[int]bool, len(families))
	for index := range families {
		pending[index] = true
	}
	values := familyValues{}
	rawResults := make([]auditFamilyResult, 0, len(families))
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ready := make([]auditFamily, 0, len(pending))
		readyIndexes := make([]int, 0, len(pending))
		for index, family := range families {
			if !pending[index] || !dependenciesReady(family.Dependencies, values) {
				continue
			}
			ready = append(ready, family)
			readyIndexes = append(readyIndexes, index)
		}
		if len(ready) == 0 {
			return nil, fmt.Errorf("audit family dependencies cannot be satisfied")
		}
		batch, err := executeFamilyBatch(ctx, options, ready, cloneFamilyValues(values))
		if err != nil {
			return nil, err
		}
		for index, result := range batch {
			delete(pending, readyIndexes[index])
			values[result.ID] = result.Value
			rawResults = append(rawResults, result)
		}
	}
	return orderAuditFamilyResults(families, rawResults)
}

func validateAuditFamilyRegistry(families []auditFamily) error {
	if len(families) == 0 {
		return fmt.Errorf("audit family registry is empty")
	}
	byID := make(map[string]auditFamily, len(families))
	for _, family := range families {
		if family.ID == "" || family.Run == nil {
			return fmt.Errorf("audit family has empty identity or runner")
		}
		if _, duplicate := byID[family.ID]; duplicate {
			return fmt.Errorf("duplicate audit family %q", family.ID)
		}
		byID[family.ID] = family
	}
	indegree := make(map[string]int, len(families))
	dependents := make(map[string][]string, len(families))
	for _, family := range families {
		seen := map[string]bool{}
		for _, dependency := range family.Dependencies {
			if dependency == family.ID || seen[dependency] {
				return fmt.Errorf("audit family %q has invalid dependency %q", family.ID, dependency)
			}
			if _, ok := byID[dependency]; !ok {
				return fmt.Errorf("audit family %q depends on missing family %q", family.ID, dependency)
			}
			seen[dependency] = true
			indegree[family.ID]++
			dependents[dependency] = append(dependents[dependency], family.ID)
		}
	}
	ready := make([]string, 0, len(families))
	for _, family := range families {
		if indegree[family.ID] == 0 {
			ready = append(ready, family.ID)
		}
	}
	visited := 0
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		visited++
		for _, dependent := range dependents[id] {
			indegree[dependent]--
			if indegree[dependent] == 0 {
				ready = append(ready, dependent)
			}
		}
	}
	if visited != len(families) {
		return fmt.Errorf("audit family registry contains a dependency cycle")
	}
	return nil
}

func dependenciesReady(dependencies []string, values familyValues) bool {
	for _, dependency := range dependencies {
		if _, ok := values[dependency]; !ok {
			return false
		}
	}
	return true
}

func cloneFamilyValues(values familyValues) familyValues {
	clone := make(familyValues, len(values))
	for id, value := range values {
		clone[id] = value
	}
	return clone
}

func executeFamilyBatch(ctx context.Context, options ExecutorOptions, families []auditFamily, values familyValues) ([]auditFamilyResult, error) {
	if options.Mode == ExecutorSerial {
		results := make([]auditFamilyResult, 0, len(families))
		for _, family := range families {
			result := runAuditFamily(ctx, family, values)
			if result.Err != nil {
				return nil, fmt.Errorf("audit family %s: %w", family.ID, result.Err)
			}
			results = append(results, result)
		}
		return results, nil
	}

	workerCount := options.Workers
	if workerCount > len(families) {
		workerCount = len(families)
	}
	jobs := make(chan auditFamily, len(families))
	completed := make(chan auditFamilyResult, len(families))
	for _, family := range families {
		jobs <- family
	}
	close(jobs)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for family := range jobs {
				completed <- runAuditFamily(ctx, family, values)
			}
		}()
	}
	workers.Wait()
	close(completed)

	rawResults := make([]auditFamilyResult, 0, len(families))
	for result := range completed {
		rawResults = append(rawResults, result)
	}
	ordered, err := orderAuditFamilyResults(families, rawResults)
	if err != nil {
		return nil, err
	}
	for _, result := range ordered {
		if result.Err != nil {
			return nil, fmt.Errorf("audit family %s: %w", result.ID, result.Err)
		}
	}
	return ordered, nil
}

func runAuditFamily(ctx context.Context, family auditFamily, values familyValues) (result auditFamilyResult) {
	result.ID = family.ID
	if err := ctx.Err(); err != nil {
		result.Err = err
		return result
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Value = nil
			result.Err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	result.Value, result.Err = family.Run(ctx, values)
	if ctxErr := ctx.Err(); ctxErr != nil {
		result.Value = nil
		if result.Err != nil {
			result.Err = fmt.Errorf("%w: %v", ctxErr, result.Err)
		} else {
			result.Err = ctxErr
		}
	}
	return result
}

func orderAuditFamilyResults(families []auditFamily, results []auditFamilyResult) ([]auditFamilyResult, error) {
	expected := make(map[string]bool, len(families))
	for _, family := range families {
		expected[family.ID] = true
	}
	byID := make(map[string]auditFamilyResult, len(results))
	for _, result := range results {
		if !expected[result.ID] {
			return nil, fmt.Errorf("unexpected audit family result %q", result.ID)
		}
		if _, duplicate := byID[result.ID]; duplicate {
			return nil, fmt.Errorf("duplicate audit family result %q", result.ID)
		}
		byID[result.ID] = result
	}
	ordered := make([]auditFamilyResult, 0, len(families))
	for _, family := range families {
		result, ok := byID[family.ID]
		if !ok {
			return nil, fmt.Errorf("missing audit family result %q", family.ID)
		}
		ordered = append(ordered, result)
	}
	return ordered, nil
}
