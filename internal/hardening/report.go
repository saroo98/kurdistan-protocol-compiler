// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"context"
	"sort"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

const Version = "0.17.0-lab"

const (
	CategoryInvariants          = "invariants"
	CategoryAPIContracts        = "api_contracts"
	CategoryResourceLimits      = "resource_limits"
	CategoryPanicSafety         = "panic_safety"
	CategoryTraceHygiene        = "trace_hygiene"
	CategorySecurityHygiene     = "security_hygiene"
	CategoryConcurrency         = "concurrency"
	CategoryGeneratedParity     = "generated_parity"
	CategoryCompatibility       = "compatibility"
	CategoryPreAdapterReadiness = "pre_adapter_readiness"
)

type CheckResult struct {
	Name     string            `json:"name"`
	Passed   bool              `json:"passed"`
	Severity string            `json:"severity"`
	Category string            `json:"category"`
	Details  string            `json:"details"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

type Checklist struct {
	Name        string        `json:"name"`
	Categories  []string      `json:"categories"`
	Results     []CheckResult `json:"results"`
	Passed      bool          `json:"passed"`
	FailedCount int           `json:"failed_count"`
}

type HardeningReport struct {
	Version               string        `json:"version"`
	Mode                  string        `json:"mode"`
	ProfileCount          int           `json:"profile_count"`
	PackagesChecked       []string      `json:"packages_checked"`
	InvariantsChecked     int           `json:"invariants_checked"`
	ContractsChecked      int           `json:"contracts_checked"`
	ResourceChecks        int           `json:"resource_checks"`
	PanicSafetyChecks     int           `json:"panic_safety_checks"`
	TraceHygieneChecks    int           `json:"trace_hygiene_checks"`
	APIMisuseChecks       int           `json:"api_misuse_checks"`
	ConcurrencyChecks     int           `json:"concurrency_checks"`
	CompatibilityChecks   int           `json:"compatibility_checks"`
	GeneratedParityChecks int           `json:"generated_parity_checks"`
	PreAdapterChecks      int           `json:"pre_adapter_checks"`
	Results               []CheckResult `json:"results"`
	FailedChecks          []CheckResult `json:"failed_checks"`
	Conclusion            string        `json:"conclusion"`
	RaceAdvice            string        `json:"race_advice,omitempty"`
}

type Options struct {
	Mode         string
	ProfileCount int
	StartSeed    int64
	Full         bool
}

func Run(ctx context.Context, profiles []*ir.Profile, opts Options) HardeningReport {
	if opts.Mode == "" {
		opts.Mode = "quick"
	}
	if opts.StartSeed == 0 {
		opts.StartSeed = 1
	}
	if opts.ProfileCount <= 0 {
		opts.ProfileCount = 3
	}
	if opts.Full || opts.Mode == "full" {
		opts.Mode = "full"
		if opts.ProfileCount < 20 {
			opts.ProfileCount = 20
		}
	}
	if len(profiles) == 0 {
		for i := 0; i < opts.ProfileCount; i++ {
			p, err := compiler.Generate(opts.StartSeed + int64(i))
			if err != nil {
				profiles = append(profiles, &ir.Profile{ID: "generation_failed"})
				continue
			}
			profiles = append(profiles, p)
		}
	}
	if len(profiles) > opts.ProfileCount {
		profiles = profiles[:opts.ProfileCount]
	}
	results := []CheckResult{}
	results = append(results, RunInvariantRegistry(profiles)...)
	results = append(results, RunAPIContractChecks(ctx, profiles)...)
	results = append(results, RunPanicSafetyChecks(profiles)...)
	results = append(results, RunResourceLimitChecks(ctx, profiles, opts)...)
	results = append(results, RunTraceHygieneChecks(ctx, profiles)...)
	results = append(results, RunConcurrencyChecks(profiles)...)
	results = append(results, RunCompatibilityChecks(profiles)...)
	results = append(results, RunGeneratedParityChecks(ctx, profiles)...)
	results = append(results, RunPreAdapterReadinessChecks()...)
	report := HardeningReport{
		Version:         Version,
		Mode:            opts.Mode,
		ProfileCount:    len(profiles),
		PackagesChecked: packagesChecked(),
		Results:         results,
		RaceAdvice:      `.tools\go\bin\go.exe test -race ./...`,
	}
	for _, result := range results {
		switch result.Category {
		case CategoryInvariants:
			report.InvariantsChecked++
		case CategoryAPIContracts:
			report.ContractsChecked++
			report.APIMisuseChecks++
		case CategoryResourceLimits:
			report.ResourceChecks++
		case CategoryPanicSafety:
			report.PanicSafetyChecks++
		case CategoryTraceHygiene, CategorySecurityHygiene:
			report.TraceHygieneChecks++
		case CategoryConcurrency:
			report.ConcurrencyChecks++
		case CategoryCompatibility:
			report.CompatibilityChecks++
		case CategoryGeneratedParity:
			report.GeneratedParityChecks++
		case CategoryPreAdapterReadiness:
			report.PreAdapterChecks++
		}
		if !result.Passed && result.Severity == "required" {
			report.FailedChecks = append(report.FailedChecks, result)
		}
	}
	report.Conclusion = "passed"
	if len(report.FailedChecks) > 0 {
		report.Conclusion = "failed"
	}
	sort.Strings(report.PackagesChecked)
	return report
}

func pass(name, category, details string, evidence map[string]string) CheckResult {
	return CheckResult{Name: name, Passed: true, Severity: "required", Category: category, Details: details, Evidence: evidence}
}

func fail(name, category, details string, evidence map[string]string) CheckResult {
	return CheckResult{Name: name, Passed: false, Severity: "required", Category: category, Details: details, Evidence: evidence}
}

func packagesChecked() []string {
	return []string{
		"internal/compiler",
		"internal/ir",
		"internal/framing",
		"internal/stream",
		"internal/proxysem",
		"internal/carrier",
		"internal/security",
		"internal/runtime",
		"internal/adapter",
		"internal/localadapter",
		"internal/bytetransport",
		"internal/codegen",
		"internal/trace",
	}
}

func firstProfile(profiles []*ir.Profile) *ir.Profile {
	for _, p := range profiles {
		if p != nil && p.ID != "" {
			return p
		}
	}
	p, _ := compiler.Generate(1)
	return p
}
