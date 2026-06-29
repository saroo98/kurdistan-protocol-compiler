// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"kurdistan/internal/adversary"
	"kurdistan/internal/audit"
	"kurdistan/internal/codegen"
	"kurdistan/internal/fixtures"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wirefeatures"
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
	if len(os.Args) > 1 && os.Args[1] == "hardening" {
		os.Exit(runHardening(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "adapter" {
		os.Exit(runAdapter(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "localadapter" {
		os.Exit(runLocalAdapter(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "bytetransport" {
		os.Exit(runByteTransport(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "fixtures" {
		os.Exit(runFixtures(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "bytepath" {
		os.Exit(runBytePath(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "protocorpus" {
		os.Exit(runProtocolCorpus(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "wirefeatures" {
		os.Exit(runWireFeatures(os.Args[2:]))
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

func runHardening(args []string) int {
	flags := flag.NewFlagSet("kcheck hardening", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local hardening audit")
	full := flags.Bool("full", false, "run full local hardening audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
	startSeed := flags.Int64("start-seed", 0, "optional start seed override")
	profiles := flags.Int("profiles", 0, "optional profile count override")
	raceAdvice := flags.Bool("race-advice", false, "print deterministic race-test advice")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *raceAdvice {
		fmt.Println("race-test command: .tools\\go\\bin\\go.exe test -race ./...")
		fmt.Println("deterministic concurrency checks: nonce manager, replay window, runtime double-close, single-threaded runtime component documentation")
		return 0
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
	report, err := audit.RunHardeningAudit(context.Background(), cfg)
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

func runAdapter(args []string) int {
	flags := flag.NewFlagSet("kcheck adapter", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local adapter audit")
	full := flags.Bool("full", false, "run full local adapter audit")
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
	report, err := audit.RunAdapterAudit(context.Background(), cfg)
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

func runLocalAdapter(args []string) int {
	flags := flag.NewFlagSet("kcheck localadapter", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local adapter prototype audit")
	full := flags.Bool("full", false, "run full local adapter prototype audit")
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
	report, err := audit.RunLocalAdapterAudit(context.Background(), cfg)
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

func runByteTransport(args []string) int {
	flags := flag.NewFlagSet("kcheck bytetransport", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick byte transport audit")
	full := flags.Bool("full", false, "run full byte transport audit")
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
	report, err := audit.RunByteTransportAudit(context.Background(), cfg)
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

func runBytePath(args []string) int {
	flags := flag.NewFlagSet("kcheck bytepath", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick bytepath fixture audit")
	full := flags.Bool("full", false, "run full bytepath fixture audit")
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
	report, err := audit.RunBytePathAudit(context.Background(), cfg)
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

func runProtocolCorpus(args []string) int {
	flags := flag.NewFlagSet("kcheck protocorpus", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick protocol corpus audit")
	full := flags.Bool("full", false, "run full protocol corpus audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
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
	cfg.OutputPath = *out
	cfg.StatusPath = *status
	report, err := audit.RunProtocolCorpusAudit(context.Background(), cfg)
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

func runWireFeatures(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runWireFeaturesGenerate(args[1:])
		case "verify":
			return runWireFeaturesVerify(args[1:])
		case "compare":
			return runWireFeaturesCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck wirefeatures", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick wire feature audit")
	full := flags.Bool("full", false, "run full wire feature audit")
	out := flags.String("out", "", "optional audit JSON output path")
	status := flags.String("status", "", "optional STATUS.md output path")
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
	cfg.OutputPath = *out
	cfg.StatusPath = *status
	report, err := audit.RunWireFeaturesAudit(context.Background(), cfg)
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

func runWireFeaturesGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck wirefeatures generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "wirefeatures", "wirefeatures-golden.json"), "wirefeature baseline output path")
	force := flags.Bool("force", false, "overwrite existing wirefeature output")
	fixturePath := flags.String("fixture", defaultFixturePath("bytepath-golden.json"), "bytepath fixture manifest path")
	corpusPath := flags.String("corpus", defaultProtocolCorpusPath("corpus-v1.json"), "protocol corpus path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	fixtureManifest, err := fixtures.LoadManifest(*fixturePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	corpus, err := protocorpus.LoadManifest(*corpusPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	baseline, err := wirefeatures.GenerateBaseline(context.Background(), fixtureManifest, corpus)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := wirefeatures.WriteBaseline(*out, baseline, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeWireFeatureCompanions(*out, baseline); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote wirefeature baseline: %s (%d vectors)\n", *out, baseline.FeatureCount)
	return 0
}

func runWireFeaturesVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck wirefeatures verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baselinePath := flags.String("baseline", filepath.Join("testdata", "wirefeatures", "wirefeatures-golden.json"), "wirefeature baseline path")
	fixturePath := flags.String("fixture", defaultFixturePath("bytepath-golden.json"), "bytepath fixture manifest path")
	corpusPath := flags.String("corpus", defaultProtocolCorpusPath("corpus-v1.json"), "protocol corpus path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report, err := wirefeatures.VerifyBaseline(context.Background(), *baselinePath, *fixturePath, *corpusPath)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runWireFeaturesCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck wirefeatures compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old wirefeature baseline path")
	newPath := flags.String("new", "", "new wirefeature baseline path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldBaseline, err := wirefeatures.LoadBaseline(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newBaseline, err := wirefeatures.LoadBaseline(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := wirefeatures.CompareBaselines(oldBaseline, newBaseline)
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil && filepath.Dir(*out) != "." {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := os.WriteFile(*out, append(raw, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	fmt.Println(string(raw))
	if !report.Passed {
		return 1
	}
	return 0
}

func writeWireFeatureCompanions(out string, baseline wirefeatures.BaselineManifest) error {
	dir := filepath.Dir(out)
	comparisonRaw, err := wirefeatures.StableJSON(baseline.Comparison)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "corpus-comparison-golden.json"), comparisonRaw, 0o600); err != nil {
		return err
	}
	collapseRaw, err := wirefeatures.StableJSON(baseline.Collapse)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "collapse-baseline.json"), collapseRaw, 0o600)
}

func runFixtures(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "fixtures subcommand required: generate, verify, compare")
		return 2
	}
	switch args[0] {
	case "generate":
		return runFixturesGenerate(args[1:])
	case "verify":
		return runFixturesVerify(args[1:])
	case "compare":
		return runFixturesCompare(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown fixtures subcommand %q\n", args[0])
		return 2
	}
}

func runFixturesGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck fixtures generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", "", "fixture output path")
	force := flags.Bool("force", false, "overwrite existing fixture output")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "--out is required")
		return 2
	}
	manifest, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{
		FixtureSet:     "bytepath-golden",
		Backend:        fixtures.BackendLab,
		BackendVersion: codegen.Version,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := fixtures.WriteManifest(*out, manifest, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote bytepath fixture manifest: %s (%d entries)\n", *out, len(manifest.Entries))
	return 0
}

func runFixturesVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck fixtures verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	fixturePath := flags.String("fixture", defaultFixturePath("bytepath-golden.json"), "fixture manifest path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report, err := fixtures.VerifyManifest(context.Background(), *fixturePath)
	if err != nil {
		fmt.Print(report.HumanSummary())
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	fmt.Printf("fixture verification passed: %s\n", *fixturePath)
	return 0
}

func runFixturesCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck fixtures compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old fixture manifest path")
	newPath := flags.String("new", "", "new fixture manifest path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldManifest, err := fixtures.LoadManifest(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newManifest, err := fixtures.LoadManifest(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := fixtures.CompareManifests(oldManifest, newManifest)
	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil && filepath.Dir(*out) != "." {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := os.WriteFile(*out, append(raw, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed {
		return 1
	}
	return 0
}

func defaultFixturePath(name string) string {
	return filepath.Join("testdata", "fixtures", name)
}

func defaultProtocolCorpusPath(name string) string {
	return filepath.Join("testdata", "protocorpus", name)
}
