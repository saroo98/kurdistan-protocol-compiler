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

	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/adversary"
	"kurdistan/internal/audit"
	"kurdistan/internal/classifierdata"
	"kurdistan/internal/codegen"
	"kurdistan/internal/fixtures"
	"kurdistan/internal/hostdetect"
	"kurdistan/internal/localproxyingress"
	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/proxyingress"
	"kurdistan/internal/proxyingressreview"
	"kurdistan/internal/relayfleet"
	"kurdistan/internal/wireeval"
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregencompare"
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
	if len(os.Args) > 1 && os.Args[1] == "wiregen" {
		os.Exit(runWireGen(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "wireeval" {
		os.Exit(runWireEval(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "hostdetect" {
		os.Exit(runHostDetect(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "relayfleet" {
		os.Exit(runRelayFleet(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "proxyingress" {
		os.Exit(runProxyIngress(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "localproxyingress" {
		os.Exit(runLocalProxyIngress(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "localproxyingressadv" {
		os.Exit(runLocalProxyIngressAdversarial(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "adaptivepath" {
		os.Exit(runAdaptivePath(os.Args[2:]))
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

func runWireGen(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runWireGenGenerate(args[1:])
		case "verify":
			return runWireGenVerify(args[1:])
		case "compare":
			return runWireGenCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck wiregen", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick wire-shape generation audit")
	full := flags.Bool("full", false, "run full wire-shape generation audit")
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
	report, err := audit.RunWireGenAudit(context.Background(), cfg)
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

func runWireGenGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck wiregen generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "wiregen", "wiregen-policy-golden.json"), "wiregen baseline output path")
	force := flags.Bool("force", false, "overwrite existing wiregen output")
	corpusPath := flags.String("corpus", defaultProtocolCorpusPath("corpus-v1.json"), "protocol corpus path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	corpus, err := protocorpus.LoadManifest(*corpusPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	baseline, err := wiregencompare.GenerateBaseline(context.Background(), corpus, wiregencompare.DefaultSeeds(), wiregencompare.DefaultScenarios())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := wiregencompare.WriteBaseline(*out, baseline, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeWireGenCompanions(*out, baseline); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote wiregen baseline: %s (%d policies, %d vectors)\n", *out, baseline.PolicyCount, baseline.FeatureCount)
	return 0
}

func runWireGenVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck wiregen verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baselinePath := flags.String("baseline", filepath.Join("testdata", "wiregen", "wiregen-policy-golden.json"), "wiregen baseline path")
	corpusPath := flags.String("corpus", defaultProtocolCorpusPath("corpus-v1.json"), "protocol corpus path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	corpus, err := protocorpus.LoadManifest(*corpusPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report, err := wiregencompare.VerifyBaseline(context.Background(), *baselinePath, corpus)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runWireGenCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck wiregen compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old wiregen baseline path")
	newPath := flags.String("new", "", "new wiregen baseline path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldBaseline, err := wiregencompare.LoadBaseline(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newBaseline, err := wiregencompare.LoadBaseline(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := wiregencompare.CompareBaselines(oldBaseline, newBaseline)
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

func writeWireGenCompanions(out string, baseline wiregencompare.BaselineManifest) error {
	dir := filepath.Dir(out)
	raw, err := wiregencompare.StableJSON(baseline.FeatureVectors)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "wiregen-bytepath-golden.json"), raw, 0o600); err != nil {
		return err
	}
	raw, err = wiregencompare.StableJSON(baseline.Comparison)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "wiregen-corpus-comparison.json"), raw, 0o600); err != nil {
		return err
	}
	raw, err = wiregencompare.StableJSON(baseline.Collapse)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "wiregen-collapse-baseline.json"), raw, 0o600)
}

func runWireEval(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runWireEvalGenerate(args[1:])
		case "verify":
			return runWireEvalVerify(args[1:])
		case "compare":
			return runWireEvalCompare(args[1:])
		case "export":
			return runWireEvalExport(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck wireeval", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick wire evaluation audit")
	full := flags.Bool("full", false, "run full wire evaluation audit")
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
	report, err := audit.RunWireEvalAudit(context.Background(), cfg)
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

func runWireEvalGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck wireeval generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "wireeval", "wireeval-dataset-golden.json"), "wireeval dataset output path")
	force := flags.Bool("force", false, "overwrite existing wireeval output")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	dataset, err := wireeval.GenerateGoldenDataset(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := wireeval.WriteDataset(*out, dataset, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeWireEvalCompanions(*out, dataset, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote wireeval dataset: %s (%d records)\n", *out, len(dataset.Records))
	return 0
}

func runWireEvalVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck wireeval verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "wireeval", "wireeval-dataset-golden.json"), "wireeval dataset baseline path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report, err := wireeval.VerifyDataset(context.Background(), *baseline)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runWireEvalCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck wireeval compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old wireeval dataset path")
	newPath := flags.String("new", "", "new wireeval dataset path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldDataset, err := wireeval.LoadDataset(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newDataset, err := wireeval.LoadDataset(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := wireeval.CompareDatasets(oldDataset, newDataset)
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
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runWireEvalExport(args []string) int {
	flags := flag.NewFlagSet("kcheck wireeval export", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	format := flags.String("format", "jsonl", "export format: jsonl or csv")
	out := flags.String("out", "", "export output path")
	force := flags.Bool("force", false, "overwrite existing export")
	baseline := flags.String("dataset", filepath.Join("testdata", "wireeval", "wireeval-dataset-golden.json"), "wireeval dataset path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "--out is required")
		return 2
	}
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintln(os.Stderr, "refusing to overwrite existing export; use --force")
			return 1
		}
	}
	dataset, err := wireeval.LoadDataset(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var raw []byte
	switch *format {
	case "jsonl":
		raw, err = classifierdata.ExportJSONL(dataset.Records)
	case "csv":
		raw, err = classifierdata.ExportCSV(dataset.Records)
	default:
		err = fmt.Errorf("unsupported wireeval export format %q", *format)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil && filepath.Dir(*out) != "." {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote wireeval %s export: %s (%d records)\n", *format, *out, len(dataset.Records))
	return 0
}

func writeWireEvalCompanions(out string, dataset wireeval.Dataset, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name string
		raw  []byte
	}{
		{"wireeval-manifest.json", mustJSON(dataset.Manifest)},
		{"wireeval-splits.json", mustJSON(wireeval.BuildSplitManifest(dataset.Records, wireeval.DefaultSplitMode()))},
		{"wireeval-controls.json", mustJSON(wireeval.ControlRecords(dataset.Records))},
		{"wireeval-baseline-report.json", mustJSON(wireeval.AnalyzeObservableDiversity(dataset.Records))},
	}
	csvRaw, err := classifierdata.ExportCSV(dataset.Records)
	if err != nil {
		return err
	}
	jsonlRaw, err := classifierdata.ExportJSONL(dataset.Records)
	if err != nil {
		return err
	}
	writes = append(writes, struct {
		name string
		raw  []byte
	}{"wireeval-dataset-golden.csv", csvRaw}, struct {
		name string
		raw  []byte
	}{"wireeval-dataset-golden.jsonl", jsonlRaw})
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				return wireeval.ErrRefuseOverwrite
			}
		}
		if err := os.WriteFile(path, write.raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func runHostDetect(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runHostDetectGenerate(args[1:])
		case "verify":
			return runHostDetectVerify(args[1:])
		case "compare":
			return runHostDetectCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck hostdetect", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick host detection audit")
	full := flags.Bool("full", false, "run full host detection audit")
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
	report, err := audit.RunHostDetectAudit(context.Background(), cfg)
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

func runHostDetectGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck hostdetect generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "hostdetect", "host-observations-golden.json"), "host observation output path")
	force := flags.Bool("force", false, "overwrite existing hostdetect output")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	summary, err := hostdetect.GenerateGoldenSummary(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := hostdetect.WriteObservationSet(*out, summary.ObservationSet, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeHostDetectCompanions(*out, summary, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote hostdetect observations: %s (%d observations)\n", *out, summary.ObservationSet.ObservationCount)
	return 0
}

func runHostDetectVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck hostdetect verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "hostdetect", "host-observations-golden.json"), "host observation baseline path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report, err := hostdetect.VerifyObservationSet(context.Background(), *baseline)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runHostDetectCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck hostdetect compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old host observation path")
	newPath := flags.String("new", "", "new host observation path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := hostdetect.LoadObservationSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := hostdetect.LoadObservationSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := hostdetect.CompareObservationSets(oldSet, newSet)
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
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeHostDetectCompanions(out string, summary hostdetect.HostDetectSummary, force bool) error {
	dir := filepath.Dir(out)
	writes := []struct {
		name string
		raw  []byte
	}{
		{"host-aggregates-golden.json", mustJSON(summary.Aggregates)},
		{"host-detection-report.json", mustJSON(summary.Detection)},
		{"host-resistance-report.json", mustJSON(summary.Resistance)},
		{"host-controls.json", mustJSON(summary.Collapse)},
		{"host-splits.json", mustJSON(map[string]any{"assignment_mode": summary.ObservationSet.AssignmentMode, "window": summary.ObservationSet.Window, "host_count": summary.ObservationSet.HostCount})},
	}
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				return hostdetect.ErrRefuseOverwrite
			}
		}
		if err := os.WriteFile(path, write.raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func runRelayFleet(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runRelayFleetGenerate(args[1:])
		case "verify":
			return runRelayFleetVerify(args[1:])
		case "compare":
			return runRelayFleetCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck relayfleet", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick relay fleet audit")
	full := flags.Bool("full", false, "run full relay fleet audit")
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
	report, err := audit.RunRelayFleetAudit(context.Background(), cfg)
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

func runRelayFleetGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck relayfleet generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "relayfleet", "relayfleet-golden.json"), "relayfleet output path")
	force := flags.Bool("force", false, "overwrite existing relayfleet output")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	summary, err := relayfleet.GenerateGoldenSummary(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := relayfleet.WriteFleet(*out, summary.Fleet, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeRelayFleetCompanions(*out, summary, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote relayfleet fixture: %s (%d relays)\n", *out, len(summary.Fleet.Relays))
	return 0
}

func runRelayFleetVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck relayfleet verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "relayfleet", "relayfleet-golden.json"), "relayfleet baseline path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report, err := relayfleet.VerifyFleet(context.Background(), *baseline)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runRelayFleetCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck relayfleet compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old relayfleet fixture path")
	newPath := flags.String("new", "", "new relayfleet fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldFleet, err := relayfleet.LoadFleet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newFleet, err := relayfleet.LoadFleet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := relayfleet.CompareFleetsOnly(oldFleet, newFleet)
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
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeRelayFleetCompanions(out string, summary relayfleet.RelayFleetSummary, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name string
		raw  []byte
	}{
		{"relay-lifecycle-golden.json", mustJSON(relayfleet.LifecycleGolden(summary.Fleet))},
		{"relay-churn-events.json", mustJSON(summary.ChurnEvents)},
		{"relay-migration-events.json", mustJSON(summary.MigrationEvents)},
		{"relay-burn-risk-report.json", mustJSON(summary.BurnRisk)},
		{"relay-collapse-report.json", mustJSON(summary.Collapse)},
		{"relay-controls.json", mustJSON(map[string]any{"assignment": summary.Assignment, "parity": summary.Parity})},
	}
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				return relayfleet.ErrRefuseOverwrite
			}
		}
		if err := os.WriteFile(path, write.raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func runProxyIngress(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runProxyIngressGenerate(args[1:])
		case "verify":
			return runProxyIngressVerify(args[1:])
		case "compare":
			return runProxyIngressCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck proxyingress", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick proxy ingress audit")
	full := flags.Bool("full", false, "run full proxy ingress audit")
	out := flags.String("out", "", "optional audit JSON output path")
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
	report, err := audit.RunProxyIngressAudit(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteJSON(*out, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed() {
		return 1
	}
	return 0
}

func runProxyIngressGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck proxyingress generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "proxyingress", "proxyingress-contract-golden.json"), "proxy ingress contract fixture path")
	force := flags.Bool("force", false, "overwrite existing fixtures")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := proxyingress.GoldenFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := proxyingress.WriteContract(*out, set.Contract, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeProxyIngressCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote proxyingress fixtures: %s (%d requests)\n", *out, len(set.Requests))
	return 0
}

func runProxyIngressVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck proxyingress verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "proxyingress", "proxyingress-contract-golden.json"), "proxy ingress contract fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report, err := proxyingress.VerifyContract(context.Background(), *baseline)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runProxyIngressCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck proxyingress compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old proxyingress contract path")
	newPath := flags.String("new", "", "new proxyingress contract path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldContract, err := proxyingress.LoadContract(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newContract, err := proxyingress.LoadContract(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := proxyingress.CompareContractsOnly(oldContract, newContract)
	raw, _ := json.MarshalIndent(report, "", "  ")
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
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeProxyIngressCompanions(out string, set proxyingress.ProxyIngressFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	review, misuse, parity, err := proxyingressreview.GenerateGoldenReview()
	if err != nil {
		return err
	}
	writes := []struct {
		name string
		raw  []byte
	}{
		{"proxyingress-requests-golden.json", mustJSON(set.Requests)},
		{"proxyingress-targets-golden.json", mustJSON(set.Targets)},
		{"proxyingress-mapping-golden.json", mustJSON(set.Mappings)},
		{"proxyingress-lifecycle-golden.json", mustJSON(set.Lifecycle)},
		{"proxyingress-design-review.json", mustJSON(review)},
		{"failure-mode-matrix.json", mustJSON(review.FailureModes)},
		{"proxyingress-controls.json", mustJSON(map[string]any{"misuse": misuse, "parity": parity})},
	}
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				return proxyingress.ErrRefuseOverwrite
			}
		}
		if err := os.WriteFile(path, write.raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func runLocalProxyIngress(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runLocalProxyIngressGenerate(args[1:])
		case "verify":
			return runLocalProxyIngressVerify(args[1:])
		case "compare":
			return runLocalProxyIngressCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck localproxyingress", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local proxy ingress audit")
	full := flags.Bool("full", false, "run full local proxy ingress audit")
	out := flags.String("out", "", "optional audit JSON output path")
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
	report, err := audit.RunLocalProxyIngressAudit(context.Background(), audit.DefaultConfig(mode))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteJSON(*out, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed() {
		return 1
	}
	return 0
}

func runLocalProxyIngressGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyingress generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "localproxyingress", "localproxyingress-summary-golden.json"), "local proxy ingress fixture path")
	force := flags.Bool("force", false, "overwrite fixtures")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := localproxyingress.GenerateFixtureSet(context.Background(), localproxyingress.FullScenarios())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := localproxyingress.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeLocalProxyIngressCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote localproxyingress fixtures: %s (%d scenarios)\n", *out, len(set.Summaries))
	return 0
}

func runLocalProxyIngressVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyingress verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "localproxyingress", "localproxyingress-summary-golden.json"), "local proxy ingress fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := localproxyingress.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localproxyingress.GenerateFixtureSet(context.Background(), oldSet.Scenarios)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localproxyingress.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runLocalProxyIngressCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyingress compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old local proxy ingress fixture path")
	newPath := flags.String("new", "", "new local proxy ingress fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := localproxyingress.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localproxyingress.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localproxyingress.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
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
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeLocalProxyIngressCompanions(out string, set localproxyingress.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	adversaryRuns := []localproxyingressadversary.ScenarioRun{}
	for _, scenario := range localproxyingressadversary.FullScenarios() {
		adversaryRuns = append(adversaryRuns, localproxyingressadversary.RunScenario(context.Background(), scenario))
	}
	writes := []struct {
		name string
		raw  []byte
	}{
		{"localproxyingress-scenarios-golden.json", mustJSON(set.Scenarios)},
		{"localproxyingress-backpressure.json", mustJSON(set.Backpressure)},
		{"localproxyingress-error-reset.json", mustJSON(set.ErrorReset)},
		{"localproxyingress-collapse-report.json", mustJSON(localproxyingressadversary.RunAll(adversaryRuns))},
		{"localproxyingress-controls.json", mustJSON(adversaryRuns)},
	}
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				return localproxyingress.ErrRefuseOverwrite
			}
		}
		if err := os.WriteFile(path, write.raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func runLocalProxyIngressAdversarial(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runLocalProxyIngressAdversarialGenerate(args[1:])
		case "verify":
			return runLocalProxyIngressAdversarialVerify(args[1:])
		case "compare":
			return runLocalProxyIngressAdversarialCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck localproxyingressadv", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local proxy ingress adversarial audit")
	full := flags.Bool("full", false, "run full local proxy ingress adversarial audit")
	out := flags.String("out", "", "optional audit JSON output path")
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
	report, err := audit.RunLocalProxyIngressAdversarialAudit(context.Background(), audit.DefaultConfig(mode))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := audit.WriteJSON(*out, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(report.HumanSummary())
	if !report.Passed() {
		return 1
	}
	return 0
}

func runLocalProxyIngressAdversarialGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyingressadv generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "localproxyingressadversary", "adversarial-corpus-golden.json"), "local proxy ingress adversarial fixture path")
	force := flags.Bool("force", false, "overwrite fixtures")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := localproxyingressadversary.GenerateAdversarialFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := localproxyingressadversary.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeLocalProxyIngressAdversarialCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote localproxyingressadv fixtures: %s (%d scenarios)\n", *out, set.Corpus.ScenarioCount)
	return 0
}

func runLocalProxyIngressAdversarialVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyingressadv verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "localproxyingressadversary", "adversarial-corpus-golden.json"), "local proxy ingress adversarial fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := localproxyingressadversary.LoadAdversarialFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localproxyingressadversary.GenerateAdversarialFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localproxyingressadversary.CompareAdversarialFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runLocalProxyIngressAdversarialCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyingressadv compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old local proxy ingress adversarial fixture path")
	newPath := flags.String("new", "", "new local proxy ingress adversarial fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := localproxyingressadversary.LoadAdversarialFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localproxyingressadversary.LoadAdversarialFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localproxyingressadversary.CompareAdversarialFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
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
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeLocalProxyIngressAdversarialCompanions(out string, set localproxyingressadversary.AdversarialFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name string
		raw  []byte
	}{
		{"descriptor-abuse-golden.json", mustJSON(set.DescriptorAbuse)},
		{"lifecycle-hardening-report.json", mustJSON(set.Lifecycle)},
		{"pressure-hardening-report.json", mustJSON(set.Pressure)},
		{"reset-error-isolation-report.json", mustJSON(set.ResetError)},
		{"mapping-collapse-report.json", mustJSON(set.MappingCollapse)},
		{"parity-hardening-report.json", mustJSON(set.Parity)},
		{"m27-readiness-report.json", mustJSON(set.Readiness)},
	}
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				return localproxyingressadversary.ErrRefuseOverwrite
			}
		}
		if err := os.WriteFile(path, write.raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func runAdaptivePath(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runAdaptivePathGenerate(args[1:])
		case "verify":
			return runAdaptivePathVerify(args[1:])
		case "compare":
			return runAdaptivePathCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck adaptivepath", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick adaptive path audit")
	full := flags.Bool("full", false, "run full adaptive path audit")
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
	cfg.TraceCount = 0
	cfg.OutputPath = *out
	cfg.StatusPath = *status
	report, err := audit.RunAdaptivePathAudit(context.Background(), cfg)
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

func runAdaptivePathGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck adaptivepath generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "adaptivepath", "path-candidates-golden.json"), "adaptive path fixture path")
	force := flags.Bool("force", false, "overwrite fixtures")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := adaptivepath.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := adaptivepath.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeAdaptivePathCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote adaptivepath fixtures: %s (%d candidates, %d conditions)\n", *out, len(set.Candidates), len(set.Conditions))
	return 0
}

func runAdaptivePathVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck adaptivepath verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "adaptivepath", "path-candidates-golden.json"), "adaptive path fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := adaptivepath.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := adaptivepath.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := adaptivepath.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runAdaptivePathCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck adaptivepath compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old adaptive path fixture path")
	newPath := flags.String("new", "", "new adaptive path fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := adaptivepath.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := adaptivepath.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := adaptivepath.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
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
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeAdaptivePathCompanions(out string, set adaptivepath.AdaptivePathFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"candidate-families.json", set.Families},
		{"path-conditions-golden.json", set.Conditions},
		{"path-observations-golden.json", set.Observations},
		{"viability-reports-golden.json", set.ViabilityReports},
		{"decision-inputs-golden.json", set.DecisionInputs},
		{"adaptivepath-collapse-report.json", set.CollapsedControl},
		{"adaptivepath-controls.json", map[string]any{"misuse": set.MisuseReport, "parity": set.Parity, "freshness": set.Freshness}},
	}
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if err := adaptivepath.WriteJSON(path, write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func mustJSON(value any) []byte {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(raw, '\n')
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
