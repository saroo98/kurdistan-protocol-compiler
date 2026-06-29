// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"kurdistan/internal/adversary"
	"kurdistan/internal/audit"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "compare" {
		os.Exit(runCompare(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "adversary" {
		os.Exit(runAdversary(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "codegen" {
		os.Exit(runCodegen(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "streamadversary" {
		os.Exit(runStreamAdversary(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "proxysem" {
		os.Exit(runProxySemantics(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "carrier" {
		os.Exit(runCarrier(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "security" {
		os.Exit(runSecurity(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "runtime" {
		os.Exit(runRuntime(os.Args[2:]))
	}
	os.Exit(runAudit(os.Args[1:]))
}

func runAudit(args []string) int {
	flags := flag.NewFlagSet("kcheck", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local audit")
	full := flags.Bool("full", false, "run full local audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
	baseline := flags.String("baseline", "", "optional baseline audit JSON for longitudinal comparison")
	startSeed := flags.Int64("start-seed", 0, "optional start seed override")
	profiles := flags.Int("profiles", 0, "optional profile count override")
	traces := flags.Int("traces", 0, "optional trace count override")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	mode := "quick"
	if *full {
		mode = "full"
	}
	if *quick {
		mode = "quick"
	}
	cfg := audit.DefaultConfig(mode)
	if *startSeed != 0 {
		cfg.StartSeed = *startSeed
	}
	if *profiles != 0 {
		cfg.ProfileCount = *profiles
	}
	if *traces != 0 {
		cfg.TraceCount = *traces
	}
	cfg.OutputPath = *out
	cfg.StatusPath = *status
	cfg.BaselinePath = *baseline

	report, err := audit.Run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	comparisonPassed := true
	if cfg.BaselinePath != "" {
		oldReport, err := audit.LoadReport(cfg.BaselinePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		comparison := audit.CompareReports(oldReport, report, audit.DefaultComparisonThresholds())
		report.BaselineComparison = &comparison
		comparisonPassed = comparison.Passed
	}
	if err := audit.WriteJSON(cfg.OutputPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteStatus(cfg.StatusPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if report.BaselineComparison != nil {
		fmt.Print(report.BaselineComparison.HumanSummary())
	}
	if !report.Passed() || !comparisonPassed {
		return 1
	}
	return 0
}

func runCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old audit JSON path")
	newPath := flags.String("new", "", "new audit JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldReport, err := audit.LoadReport(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newReport, err := audit.LoadReport(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	comparison := audit.CompareReports(oldReport, newReport, audit.DefaultComparisonThresholds())
	fmt.Print(comparison.HumanSummary())
	if !comparison.Passed {
		return 1
	}
	return 0
}

func runAdversary(args []string) int {
	flags := flag.NewFlagSet("kcheck adversary", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local adversary analysis")
	full := flags.Bool("full", false, "run full local adversary analysis")
	out := flags.String("out", "", "optional adversary JSON output path")
	startSeed := flags.Int64("start-seed", 0, "optional start seed override")
	profiles := flags.Int("profiles", 0, "optional profile count override")
	traces := flags.Int("traces", 0, "optional trace count override")
	controls := flags.Int("controls", 0, "optional synthetic control count override")
	threshold := flags.Float64("threshold", 0, "optional clustering threshold override")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	mode := "quick"
	if *full {
		mode = "full"
	}
	if *quick {
		mode = "quick"
	}
	cfg := adversary.DefaultAnalysisConfig(mode)
	if *startSeed != 0 {
		cfg.StartSeed = *startSeed
	}
	if *profiles != 0 {
		cfg.ProfileCount = *profiles
	}
	if *traces != 0 {
		cfg.TraceCount = *traces
	}
	if *controls != 0 {
		cfg.ControlCount = *controls
	}
	if *threshold != 0 {
		cfg.ClusterThreshold = *threshold
	}
	report, err := adversary.RunLocalAnalysis(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := adversary.WriteJSON(*out, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runCodegen(args []string) int {
	flags := flag.NewFlagSet("kcheck codegen", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local generated-backend audit")
	full := flags.Bool("full", false, "run full local generated-backend audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
	startSeed := flags.Int64("start-seed", 0, "optional start seed override")
	profiles := flags.Int("profiles", 0, "optional generated profile count override")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	mode := "quick"
	if *full {
		mode = "full"
	}
	if *quick {
		mode = "quick"
	}
	cfg := audit.DefaultCodegenAuditConfig(mode)
	if *startSeed != 0 {
		cfg.StartSeed = *startSeed
	}
	if *profiles != 0 {
		cfg.ProfileCount = *profiles
	}
	cfg.OutputPath = *out
	report, err := audit.RunCodegenAudit(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteJSON(cfg.OutputPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteStatus(*status, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed() {
		return 1
	}
	return 0
}

func runStreamAdversary(args []string) int {
	flags := flag.NewFlagSet("kcheck streamadversary", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local multi-stream adversary audit")
	full := flags.Bool("full", false, "run full local multi-stream adversary audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
	startSeed := flags.Int64("start-seed", 0, "optional start seed override")
	profiles := flags.Int("profiles", 0, "optional profile count override")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	mode := "quick"
	if *full {
		mode = "full"
	}
	if *quick {
		mode = "quick"
	}
	cfg := audit.DefaultConfig(mode)
	if mode == "quick" {
		cfg.ProfileCount = 3
		cfg.TraceCount = 0
	} else {
		cfg.ProfileCount = 20
		cfg.TraceCount = 0
	}
	if *startSeed != 0 {
		cfg.StartSeed = *startSeed
	}
	if *profiles != 0 {
		cfg.ProfileCount = *profiles
	}
	cfg.OutputPath = *out
	cfg.StatusPath = *status
	report, err := audit.RunStreamAdversaryAudit(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteJSON(cfg.OutputPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteStatus(cfg.StatusPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed() {
		return 1
	}
	return 0
}

func runProxySemantics(args []string) int {
	flags := flag.NewFlagSet("kcheck proxysem", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local proxy-semantics audit")
	full := flags.Bool("full", false, "run full local proxy-semantics audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
	startSeed := flags.Int64("start-seed", 0, "optional start seed override")
	profiles := flags.Int("profiles", 0, "optional profile count override")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	mode := "quick"
	if *full {
		mode = "full"
	}
	if *quick {
		mode = "quick"
	}
	cfg := audit.DefaultConfig(mode)
	if mode == "quick" {
		cfg.ProfileCount = 3
		cfg.TraceCount = 0
	} else {
		cfg.ProfileCount = 20
		cfg.TraceCount = 0
	}
	if *startSeed != 0 {
		cfg.StartSeed = *startSeed
	}
	if *profiles != 0 {
		cfg.ProfileCount = *profiles
	}
	cfg.OutputPath = *out
	cfg.StatusPath = *status
	report, err := audit.RunProxySemanticsAudit(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteJSON(cfg.OutputPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteStatus(cfg.StatusPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed() {
		return 1
	}
	return 0
}

func runCarrier(args []string) int {
	flags := flag.NewFlagSet("kcheck carrier", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local carrier audit")
	full := flags.Bool("full", false, "run full local carrier audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
	startSeed := flags.Int64("start-seed", 0, "optional start seed override")
	profiles := flags.Int("profiles", 0, "optional profile count override")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	mode := "quick"
	if *full {
		mode = "full"
	}
	if *quick {
		mode = "quick"
	}
	cfg := audit.DefaultConfig(mode)
	if mode == "quick" {
		cfg.ProfileCount = 3
		cfg.TraceCount = 0
	} else {
		cfg.ProfileCount = 20
		cfg.TraceCount = 0
	}
	if *startSeed != 0 {
		cfg.StartSeed = *startSeed
	}
	if *profiles != 0 {
		cfg.ProfileCount = *profiles
	}
	cfg.OutputPath = *out
	cfg.StatusPath = *status
	report, err := audit.RunCarrierAudit(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteJSON(cfg.OutputPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteStatus(cfg.StatusPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed() {
		return 1
	}
	return 0
}

func runSecurity(args []string) int {
	flags := flag.NewFlagSet("kcheck security", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local security audit")
	full := flags.Bool("full", false, "run full local security audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
	startSeed := flags.Int64("start-seed", 0, "optional start seed override")
	profiles := flags.Int("profiles", 0, "optional profile count override")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	mode := "quick"
	if *full {
		mode = "full"
	}
	if *quick {
		mode = "quick"
	}
	cfg := audit.DefaultConfig(mode)
	if mode == "quick" {
		cfg.ProfileCount = 3
		cfg.TraceCount = 0
	} else {
		cfg.ProfileCount = 20
		cfg.TraceCount = 0
	}
	if *startSeed != 0 {
		cfg.StartSeed = *startSeed
	}
	if *profiles != 0 {
		cfg.ProfileCount = *profiles
	}
	cfg.OutputPath = *out
	cfg.StatusPath = *status
	report, err := audit.RunSecurityAudit(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteJSON(cfg.OutputPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteStatus(cfg.StatusPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed() {
		return 1
	}
	return 0
}

func runRuntime(args []string) int {
	flags := flag.NewFlagSet("kcheck runtime", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local runtime audit")
	full := flags.Bool("full", false, "run full local runtime audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
	startSeed := flags.Int64("start-seed", 0, "optional start seed override")
	profiles := flags.Int("profiles", 0, "optional profile count override")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	mode := "quick"
	if *full {
		mode = "full"
	}
	if *quick {
		mode = "quick"
	}
	cfg := audit.DefaultConfig(mode)
	if mode == "quick" {
		cfg.ProfileCount = 3
		cfg.TraceCount = 0
	} else {
		cfg.ProfileCount = 20
		cfg.TraceCount = 0
	}
	if *startSeed != 0 {
		cfg.StartSeed = *startSeed
	}
	if *profiles != 0 {
		cfg.ProfileCount = *profiles
	}
	cfg.OutputPath = *out
	cfg.StatusPath = *status
	report, err := audit.RunRuntimeAudit(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteJSON(cfg.OutputPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteStatus(cfg.StatusPath, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed() {
		return 1
	}
	return 0
}
