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
	"kurdistan/internal/androidreview"
	"kurdistan/internal/androidruntime"
	"kurdistan/internal/audit"
	"kurdistan/internal/carriercollapse"
	"kurdistan/internal/carrierreadiness"
	"kurdistan/internal/carrierreview"
	"kurdistan/internal/classifierdata"
	"kurdistan/internal/codegen"
	"kurdistan/internal/concretelocaladapter"
	"kurdistan/internal/constrainedcarrier"
	"kurdistan/internal/constrainedcarrierreview"
	"kurdistan/internal/fixtures"
	"kurdistan/internal/hostdetect"
	"kurdistan/internal/httpscarrieradversary"
	"kurdistan/internal/httpscarrierreview"
	"kurdistan/internal/httpslikecarrier"
	"kurdistan/internal/keyexchangeplan"
	"kurdistan/internal/labegress"
	"kurdistan/internal/localpipeline"
	"kurdistan/internal/localprotocoladapter"
	"kurdistan/internal/localproxyadapter"
	"kurdistan/internal/localproxyadapterreview"
	"kurdistan/internal/localproxyingress"
	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/localvpnadapter"
	"kurdistan/internal/loopbackrelay"
	"kurdistan/internal/measurementreview"
	"kurdistan/internal/multicarrierselect"
	"kurdistan/internal/operationalhardening"
	"kurdistan/internal/pathhealth"
	"kurdistan/internal/pathrace"
	"kurdistan/internal/productionreadiness"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/proxyegress"
	"kurdistan/internal/proxyingress"
	"kurdistan/internal/proxyingressreview"
	"kurdistan/internal/relayauthplan"
	"kurdistan/internal/relaybridge"
	"kurdistan/internal/relayfleet"
	"kurdistan/internal/relayprocess"
	"kurdistan/internal/transportbundle"
	"kurdistan/internal/vpnsemantics"
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
	if len(os.Args) > 1 && os.Args[1] == "transportbundle" {
		os.Exit(runTransportBundle(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "pathrace" {
		os.Exit(runPathRace(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "pathhealth" {
		os.Exit(runPathHealth(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "carrierreview" {
		os.Exit(runCarrierReview(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "measurementreview" {
		os.Exit(runMeasurementReview(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "proxyegress" {
		os.Exit(runProxyEgress(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "relaybridge" {
		os.Exit(runRelayBridge(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "localpipeline" {
		os.Exit(runLocalPipeline(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "productionreadiness" {
		os.Exit(runProductionReadiness(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "concretelocaladapter" {
		os.Exit(runConcreteLocalAdapter(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "localprotocoladapter" {
		os.Exit(runLocalProtocolAdapter(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "loopbackrelay" {
		os.Exit(runLoopbackRelay(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "labegress" {
		os.Exit(runLabEgress(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "carrierreadiness" {
		os.Exit(runCarrierReadiness(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "httpscarrierreview" {
		os.Exit(runHTTPSCarrierReview(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "httpslikecarrier" {
		os.Exit(runHTTPSLikeCarrier(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "httpscarrieradversary" {
		os.Exit(runHTTPSCarrierAdversary(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "constrainedcarrierreview" {
		os.Exit(runConstrainedCarrierReview(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "constrainedcarrier" {
		os.Exit(runConstrainedCarrier(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "multicarrierselect" {
		os.Exit(runMultiCarrierSelect(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "carriercollapse" {
		os.Exit(runCarrierCollapse(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "localproxyadapterreview" {
		os.Exit(runLocalProxyAdapterReview(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "localproxyadapter" {
		os.Exit(runLocalProxyAdapter(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "vpnsemantics" {
		os.Exit(runVPNSemantics(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "localvpnadapter" {
		os.Exit(runLocalVPNAdapter(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "relayprocess" {
		os.Exit(runRelayProcess(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "keyexchangeplan" {
		os.Exit(runKeyExchangePlan(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "relayauthplan" {
		os.Exit(runRelayAuthPlan(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "operationalhardening" {
		os.Exit(runOperationalHardening(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "androidruntime" {
		os.Exit(runAndroidRuntime(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "androidreview" {
		os.Exit(runAndroidReview(os.Args[2:]))
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

func runTransportBundle(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runTransportBundleGenerate(args[1:])
		case "verify":
			return runTransportBundleVerify(args[1:])
		case "compare":
			return runTransportBundleCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck transportbundle", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick transport bundle audit")
	full := flags.Bool("full", false, "run full transport bundle audit")
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
	report, err := audit.RunTransportBundleAudit(context.Background(), cfg)
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

func runTransportBundleGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck transportbundle generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "transportbundle", "bundle-manifest-golden.json"), "transport bundle fixture path")
	force := flags.Bool("force", false, "overwrite fixtures")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := transportbundle.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := transportbundle.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeTransportBundleCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote transportbundle fixtures: %s (%d candidates, %d modes)\n", *out, len(set.Candidates), len(set.ModeManifests))
	return 0
}

func runTransportBundleVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck transportbundle verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "transportbundle", "bundle-manifest-golden.json"), "transport bundle fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := transportbundle.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := transportbundle.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := transportbundle.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runTransportBundleCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck transportbundle compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old transport bundle fixture path")
	newPath := flags.String("new", "", "new transport bundle fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := transportbundle.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := transportbundle.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := transportbundle.CompareFixtureSets(oldSet, newSet)
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

func writeTransportBundleCompanions(out string, set transportbundle.TransportBundleFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"bundle-policy-golden.json", set.Policies},
		{"bundle-seedplan-golden.json", set.SeedPlan},
		{"bundle-candidates-golden.json", set.Candidates},
		{"bundle-adaptivepath-mapping.json", set.AdaptivePathCandidates},
		{"bundle-relay-binding-report.json", set.RelayBinding},
		{"bundle-fallback-hints.json", set.FallbackHints},
		{"bundle-collapse-report.json", set.CollapseReport},
		{"bundle-controls.json", map[string]any{"control_collapse": set.ControlCollapseReport, "parity": set.Parity}},
	}
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if err := transportbundle.WriteJSON(path, write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runPathRace(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runPathRaceGenerate(args[1:])
		case "verify":
			return runPathRaceVerify(args[1:])
		case "compare":
			return runPathRaceCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck pathrace", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick pathrace audit")
	full := flags.Bool("full", false, "run full pathrace audit")
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
	report, err := audit.RunPathRaceAudit(context.Background(), cfg)
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

func runPathRaceGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck pathrace generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "pathrace", "pathrace-report-golden.json"), "pathrace fixture path")
	force := flags.Bool("force", false, "overwrite fixtures")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := pathrace.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := pathrace.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writePathRaceCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote pathrace fixtures: %s (%d scenarios, %d outcomes)\n", *out, len(set.Scenarios), len(set.Outcomes))
	return 0
}

func runPathRaceVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck pathrace verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "pathrace", "pathrace-report-golden.json"), "pathrace fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := pathrace.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := pathrace.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := pathrace.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runPathRaceCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck pathrace compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old pathrace fixture path")
	newPath := flags.String("new", "", "new pathrace fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := pathrace.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := pathrace.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := pathrace.CompareFixtureSets(oldSet, newSet)
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

func writePathRaceCompanions(out string, set pathrace.PathRaceFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"race-scenarios-golden.json", set.Scenarios},
		{"race-events-golden.json", set.Events},
		{"race-outcomes-golden.json", set.Outcomes},
		{"scoring-policy-golden.json", set.ScoringPolicy},
		{"candidate-scores-golden.json", set.Scores},
		{"ranking-report-golden.json", set.RankingReport},
		{"pathrace-misuse-report.json", set.MisuseReport},
		{"pathrace-controls.json", set.Controls},
	}
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if err := pathrace.WriteJSON(path, write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runPathHealth(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runPathHealthGenerate(args[1:])
		case "verify":
			return runPathHealthVerify(args[1:])
		case "compare":
			return runPathHealthCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck pathhealth", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick pathhealth audit")
	full := flags.Bool("full", false, "run full pathhealth audit")
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
	report, err := audit.RunPathHealthAudit(context.Background(), cfg)
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

func runPathHealthGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck pathhealth generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "pathhealth", "pathhealth-report-golden.json"), "pathhealth fixture path")
	force := flags.Bool("force", false, "overwrite fixtures")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := pathhealth.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := pathhealth.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writePathHealthCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote pathhealth fixtures: %s (%d scenarios, %d events)\n", *out, len(set.Scenarios), len(set.Events))
	return 0
}

func runPathHealthVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck pathhealth verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "pathhealth", "pathhealth-report-golden.json"), "pathhealth fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := pathhealth.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := pathhealth.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := pathhealth.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runPathHealthCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck pathhealth compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old pathhealth fixture path")
	newPath := flags.String("new", "", "new pathhealth fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := pathhealth.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := pathhealth.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := pathhealth.CompareFixtureSets(oldSet, newSet)
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

func writePathHealthCompanions(out string, set pathhealth.PathHealthFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"pathhealth-scenarios-golden.json", set.Scenarios},
		{"pathhealth-events-golden.json", set.Events},
		{"pathhealth-transitions-golden.json", set.Transitions},
		{"pathhealth-degradation-golden.json", set.Degradation},
		{"pathhealth-decisions-golden.json", set.Decisions},
		{"pathhealth-controls.json", set.Controls},
		{"pathhealth-parity.json", set.Parity},
	}
	for _, write := range writes {
		path := filepath.Join(dir, write.name)
		if err := pathhealth.WriteJSON(path, write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runCarrierReview(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runCarrierReviewGenerate(args[1:])
		case "verify":
			return runCarrierReviewVerify(args[1:])
		case "compare":
			return runCarrierReviewCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck carrierreview", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick carrier review audit")
	full := flags.Bool("full", false, "run full carrier review audit")
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
	report, err := audit.RunCarrierReviewAudit(context.Background(), cfg)
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

func runCarrierReviewGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck carrierreview generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "carrierreview", "carrierreview-golden.json"), "carrier review fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	review, err := carrierreview.GenerateReview()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := carrierreview.WriteJSON(*out, review, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeCarrierReviewCompanions(*out, review, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote carrierreview fixtures: %s (%d families)\n", *out, len(review.Descriptors))
	return 0
}

func runCarrierReviewVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck carrierreview verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "carrierreview", "carrierreview-golden.json"), "carrier review fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldReview, err := carrierreview.LoadReview(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newReview, err := carrierreview.GenerateReview()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := carrierreview.CompareReviews(oldReview, newReview)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runCarrierReviewCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck carrierreview compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old carrier review fixture path")
	newPath := flags.String("new", "", "new carrier review fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldReview, err := carrierreview.LoadReview(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newReview, err := carrierreview.LoadReview(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := carrierreview.CompareReviews(oldReview, newReview)
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

func writeCarrierReviewCompanions(out string, review carrierreview.CarrierFamilyReview, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"carrier-families.json", review.Descriptors},
		{"carrier-readiness.json", review.Readiness},
		{"carrier-review-matrix.json", review.Matrix},
		{"carrierreview-controls.json", review.Misuse},
		{"carrierreview-parity.json", review.Parity},
	}
	for _, write := range writes {
		if err := carrierreview.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runMeasurementReview(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runMeasurementReviewGenerate(args[1:])
		case "verify":
			return runMeasurementReviewVerify(args[1:])
		case "compare":
			return runMeasurementReviewCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck measurementreview", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick measurement review audit")
	full := flags.Bool("full", false, "run full measurement review audit")
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
	report, err := audit.RunMeasurementReviewAudit(context.Background(), cfg)
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

func runMeasurementReviewGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck measurementreview generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "measurementreview", "measurementreview-golden.json"), "measurement review fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	review, err := measurementreview.GenerateReview()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := measurementreview.WriteJSON(*out, review, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeMeasurementReviewCompanions(*out, review, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote measurementreview fixtures: %s (%d fields)\n", *out, len(review.Fields))
	return 0
}

func runMeasurementReviewVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck measurementreview verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "measurementreview", "measurementreview-golden.json"), "measurement review fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldReview, err := measurementreview.LoadReview(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newReview, err := measurementreview.GenerateReview()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := measurementreview.CompareReviews(oldReview, newReview)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runMeasurementReviewCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck measurementreview compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old measurement review fixture path")
	newPath := flags.String("new", "", "new measurement review fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldReview, err := measurementreview.LoadReview(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newReview, err := measurementreview.LoadReview(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := measurementreview.CompareReviews(oldReview, newReview)
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

func writeMeasurementReviewCompanions(out string, review measurementreview.MeasurementReview, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"measurement-observation-schema.json", review.Fields},
		{"measurement-redaction-policy.json", review.Policy},
		{"measurement-local-diagnostics.json", review.Diagnostics},
		{"measurement-readiness.json", review.Readiness},
		{"measurementreview-controls.json", review.Misuse},
		{"measurementreview-parity.json", review.Parity},
	}
	for _, write := range writes {
		if err := measurementreview.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runProxyEgress(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runProxyEgressGenerate(args[1:])
		case "verify":
			return runProxyEgressVerify(args[1:])
		case "compare":
			return runProxyEgressCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck proxyegress", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick proxy egress audit")
	full := flags.Bool("full", false, "run full proxy egress audit")
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
	report, err := audit.RunProxyEgressAudit(context.Background(), cfg)
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

func runProxyEgressGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck proxyegress generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "proxyegress", "egress-lifecycle-golden.json"), "proxy egress fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := proxyegress.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := proxyegress.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeProxyEgressCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote proxyegress fixtures: %s (%d scenarios)\n", *out, len(set.Scenarios))
	return 0
}

func runProxyEgressVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck proxyegress verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "proxyegress", "egress-lifecycle-golden.json"), "proxy egress fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := proxyegress.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := proxyegress.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := proxyegress.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runProxyEgressCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck proxyegress compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old proxy egress fixture path")
	newPath := flags.String("new", "", "new proxy egress fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := proxyegress.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := proxyegress.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := proxyegress.CompareFixtureSets(oldSet, newSet)
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

func writeProxyEgressCompanions(out string, set proxyegress.EgressFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"egress-requests-golden.json", set.Requests},
		{"egress-targets-golden.json", set.Targets},
		{"egress-mapping-golden.json", set.Mappings},
		{"egress-backpressure-golden.json", set.Backpressure},
		{"egress-reset-error-golden.json", set.ResetError},
		{"egress-adaptive-binding.json", set.Adaptive},
		{"ingress-egress-mapping.json", set.IngressMapping},
		{"proxyegress-misuse-report.json", set.Misuse},
		{"proxyegress-parity.json", set.Parity},
	}
	for _, write := range writes {
		if err := proxyegress.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runRelayBridge(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runRelayBridgeGenerate(args[1:])
		case "verify":
			return runRelayBridgeVerify(args[1:])
		case "compare":
			return runRelayBridgeCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck relaybridge", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick relay bridge audit")
	full := flags.Bool("full", false, "run full relay bridge audit")
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
	report, err := audit.RunRelayBridgeAudit(context.Background(), cfg)
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

func runRelayBridgeGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck relaybridge generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "relaybridge", "relaybridge-report-golden.json"), "relay bridge fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := relaybridge.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := relaybridge.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeRelayBridgeCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote relaybridge fixtures: %s (%d scenarios)\n", *out, len(set.Scenarios))
	return 0
}

func runRelayBridgeVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck relaybridge verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "relaybridge", "relaybridge-report-golden.json"), "relay bridge fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := relaybridge.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := relaybridge.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := relaybridge.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runRelayBridgeCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck relaybridge compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old relay bridge fixture path")
	newPath := flags.String("new", "", "new relay bridge fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := relaybridge.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := relaybridge.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := relaybridge.CompareFixtureSets(oldSet, newSet)
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

func writeRelayBridgeCompanions(out string, set relaybridge.RelayBridgeFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"relaybridge-scenarios-golden.json", set.Scenarios},
		{"relaybridge-sessions-golden.json", set.Sessions},
		{"relaybridge-streams-golden.json", set.Streams},
		{"relaybridge-reports-golden.json", set.Reports},
		{"relaybridge-adaptive-binding.json", set.Adaptive},
		{"relaybridge-misuse-report.json", set.Misuse},
		{"relaybridge-parity.json", set.Parity},
	}
	for _, write := range writes {
		if err := relaybridge.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runLocalPipeline(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runLocalPipelineGenerate(args[1:])
		case "verify":
			return runLocalPipelineVerify(args[1:])
		case "compare":
			return runLocalPipelineCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck localpipeline", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local pipeline audit")
	full := flags.Bool("full", false, "run full local pipeline audit")
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
	report, err := audit.RunLocalPipelineAudit(context.Background(), cfg)
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

func runLocalPipelineGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck localpipeline generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "localpipeline", "localpipeline-golden.json"), "local pipeline fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := localpipeline.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := localpipeline.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeLocalPipelineCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote localpipeline fixtures: %s (%d scenarios)\n", *out, len(set.Scenarios))
	return 0
}

func runLocalPipelineVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck localpipeline verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "localpipeline", "localpipeline-golden.json"), "local pipeline fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := localpipeline.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localpipeline.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localpipeline.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runLocalPipelineCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck localpipeline compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old local pipeline fixture path")
	newPath := flags.String("new", "", "new local pipeline fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := localpipeline.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localpipeline.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localpipeline.CompareFixtureSets(oldSet, newSet)
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

func writeLocalPipelineCompanions(out string, set localpipeline.PipelineFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"localpipeline-scenarios-golden.json", set.Scenarios},
		{"localpipeline-runs-golden.json", set.Runs},
		{"localpipeline-boundary.json", set.Boundary},
		{"localpipeline-collapse.json", set.Collapse},
		{"localpipeline-misuse-report.json", set.Misuse},
		{"localpipeline-parity.json", set.Parity},
	}
	for _, write := range writes {
		if err := localpipeline.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
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

func runProductionReadiness(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runProductionReadinessGenerate(args[1:])
		case "verify":
			return runProductionReadinessVerify(args[1:])
		case "compare":
			return runProductionReadinessCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck productionreadiness", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick production readiness audit")
	full := flags.Bool("full", false, "run full production readiness audit")
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
	report, err := audit.RunProductionReadinessAudit(context.Background(), cfg)
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

func runProductionReadinessGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck productionreadiness generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "productionreadiness", "productionreadiness-golden.json"), "production readiness fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	review, err := productionreadiness.GenerateReview()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := productionreadiness.WriteJSON(*out, review, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeProductionReadinessCompanions(*out, review, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote productionreadiness fixtures: %s (%d items)\n", *out, len(review.Items))
	return 0
}

func runProductionReadinessVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck productionreadiness verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "productionreadiness", "productionreadiness-golden.json"), "production readiness fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldReview, err := productionreadiness.LoadReview(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newReview, err := productionreadiness.GenerateReview()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := productionreadiness.CompareReviews(oldReview, newReview)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runProductionReadinessCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck productionreadiness compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old production readiness fixture path")
	newPath := flags.String("new", "", "new production readiness fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldReview, err := productionreadiness.LoadReview(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newReview, err := productionreadiness.LoadReview(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := productionreadiness.CompareReviews(oldReview, newReview)
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

func writeProductionReadinessCompanions(out string, review productionreadiness.ProductionReadinessReview, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"productionreadiness-inventory.json", review.Items},
		{"productionreadiness-dependencies.json", review.Dependencies},
		{"productionreadiness-boundaries.json", review.Boundaries},
		{"productionreadiness-contracts.json", review.Contracts},
		{"productionreadiness-blockers.json", review.Blockers},
		{"productionreadiness-controls.json", review.Misuse},
		{"productionreadiness-parity.json", review.Parity},
	}
	for _, write := range writes {
		if err := productionreadiness.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runConcreteLocalAdapter(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runConcreteLocalAdapterGenerate(args[1:])
		case "verify":
			return runConcreteLocalAdapterVerify(args[1:])
		case "compare":
			return runConcreteLocalAdapterCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck concretelocaladapter", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick concrete local adapter audit")
	full := flags.Bool("full", false, "run full concrete local adapter audit")
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
	report, err := audit.RunConcreteLocalAdapterAudit(context.Background(), cfg)
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

func runConcreteLocalAdapterGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck concretelocaladapter generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "concretelocaladapter", "concretelocaladapter-golden.json"), "concrete local adapter fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := concretelocaladapter.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := concretelocaladapter.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeConcreteLocalAdapterCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote concretelocaladapter fixtures: %s (%d scenarios)\n", *out, len(set.Scenarios))
	return 0
}

func runConcreteLocalAdapterVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck concretelocaladapter verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "concretelocaladapter", "concretelocaladapter-golden.json"), "concrete local adapter fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := concretelocaladapter.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := concretelocaladapter.GenerateFixtureSet(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := concretelocaladapter.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runConcreteLocalAdapterCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck concretelocaladapter compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old concrete local adapter fixture path")
	newPath := flags.String("new", "", "new concrete local adapter fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := concretelocaladapter.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := concretelocaladapter.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := concretelocaladapter.CompareFixtureSets(oldSet, newSet)
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

func writeConcreteLocalAdapterCompanions(out string, set concretelocaladapter.SocketFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"concretelocaladapter-scenarios.json", set.Scenarios},
		{"concretelocaladapter-summaries.json", set.Summaries},
		{"concretelocaladapter-misuse.json", set.Misuse},
		{"concretelocaladapter-parity.json", set.Parity},
		{"concretelocaladapter-collapse.json", set.Collapse},
	}
	for _, write := range writes {
		if err := concretelocaladapter.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runLocalProtocolAdapter(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runLocalProtocolAdapterGenerate(args[1:])
		case "verify":
			return runLocalProtocolAdapterVerify(args[1:])
		case "compare":
			return runLocalProtocolAdapterCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck localprotocoladapter", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local protocol adapter audit")
	full := flags.Bool("full", false, "run full local protocol adapter audit")
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
	report, err := audit.RunLocalProtocolAdapterAudit(context.Background(), cfg)
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

func runLocalProtocolAdapterGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck localprotocoladapter generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "localprotocoladapter", "localprotocoladapter-report-golden.json"), "local protocol adapter fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := localprotocoladapter.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := localprotocoladapter.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeLocalProtocolAdapterCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote localprotocoladapter fixtures: %s (%d requests)\n", *out, len(set.Requests))
	return 0
}

func runLocalProtocolAdapterVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck localprotocoladapter verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "localprotocoladapter", "localprotocoladapter-report-golden.json"), "local protocol adapter fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := localprotocoladapter.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localprotocoladapter.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localprotocoladapter.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runLocalProtocolAdapterCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck localprotocoladapter compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old local protocol adapter fixture path")
	newPath := flags.String("new", "", "new local protocol adapter fixture path")
	out := flags.String("out", "", "optional compare JSON output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := localprotocoladapter.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localprotocoladapter.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localprotocoladapter.CompareFixtureSets(oldSet, newSet)
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

func writeLocalProtocolAdapterCompanions(out string, set localprotocoladapter.LocalProtocolFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"localprotocoladapter-requests.json", set.Requests},
		{"localprotocoladapter-config-report.json", set.ConfigReport},
		{"localprotocoladapter-connect-report.json", set.ConnectReport},
		{"localprotocoladapter-socks5-report.json", set.Socks5Report},
		{"localprotocoladapter-redaction-report.json", set.RedactionReport},
		{"localprotocoladapter-state-report.json", set.StateReport},
		{"localprotocoladapter-misuse-report.json", set.Misuse},
		{"localprotocoladapter-parity.json", set.Parity},
	}
	for _, write := range writes {
		if err := localprotocoladapter.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runLoopbackRelay(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runLoopbackRelayGenerate(args[1:])
		case "verify":
			return runLoopbackRelayVerify(args[1:])
		case "compare":
			return runLoopbackRelayCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck loopbackrelay", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick loopback relay audit")
	full := flags.Bool("full", false, "run full loopback relay audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunLoopbackRelayAudit(context.Background(), cfg)
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

func runLoopbackRelayGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck loopbackrelay generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "loopbackrelay", "loopbackrelay-report-golden.json"), "loopback relay fixture path")
	force := flags.Bool("force", false, "overwrite existing fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := loopbackrelay.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := loopbackrelay.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeLoopbackRelayCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote loopbackrelay fixtures: %s (%d sessions)\n", *out, len(set.Report.Sessions))
	return 0
}

func runLoopbackRelayVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck loopbackrelay verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "loopbackrelay", "loopbackrelay-report-golden.json"), "loopback relay fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := loopbackrelay.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := loopbackrelay.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := loopbackrelay.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runLoopbackRelayCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck loopbackrelay compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old loopback relay fixture")
	newPath := flags.String("new", "", "new loopback relay fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := loopbackrelay.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := loopbackrelay.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := loopbackrelay.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := loopbackrelay.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeLoopbackRelayCompanions(out string, set loopbackrelay.LoopbackRelayFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"loopbackrelay-sessions.json", set.Report.Sessions},
		{"loopbackrelay-bind-policy.json", set.BindPolicy},
		{"loopbackrelay-misuse-report.json", set.Misuse},
		{"loopbackrelay-parity.json", set.Parity},
	}
	for _, write := range writes {
		if err := loopbackrelay.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runLabEgress(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runLabEgressGenerate(args[1:])
		case "verify":
			return runLabEgressVerify(args[1:])
		case "compare":
			return runLabEgressCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck labegress", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick lab egress audit")
	full := flags.Bool("full", false, "run full lab egress audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunLabEgressAudit(context.Background(), cfg)
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

func runLabEgressGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck labegress generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "labegress", "labegress-report-golden.json"), "lab egress fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := labegress.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := labegress.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeLabEgressCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote labegress fixtures: %s (%d exchanges)\n", *out, len(set.Report.Exchanges))
	return 0
}

func runLabEgressVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck labegress verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "labegress", "labegress-report-golden.json"), "lab egress fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := labegress.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := labegress.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := labegress.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runLabEgressCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck labegress compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old lab egress fixture")
	newPath := flags.String("new", "", "new lab egress fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := labegress.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := labegress.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := labegress.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := labegress.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeLabEgressCompanions(out string, set labegress.LabEgressFixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"labegress-exchanges.json", set.Report.Exchanges},
		{"labegress-allowlist.json", set.Allowlist},
		{"labegress-misuse-report.json", set.Misuse},
		{"labegress-parity.json", set.Parity},
	}
	for _, write := range writes {
		if err := labegress.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runCarrierReadiness(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runCarrierReadinessGenerate(args[1:])
		case "verify":
			return runCarrierReadinessVerify(args[1:])
		case "compare":
			return runCarrierReadinessCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck carrierreadiness", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick carrier readiness audit")
	full := flags.Bool("full", false, "run full carrier readiness audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunCarrierReadinessAudit(context.Background(), cfg)
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

func runCarrierReadinessGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck carrierreadiness generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "carrierreadiness", "carrierreadiness-golden.json"), "carrier readiness fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := carrierreadiness.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := carrierreadiness.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeCarrierReadinessCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote carrierreadiness fixtures: %s (%d inventory items)\n", *out, len(set.Review.Inventory))
	return 0
}

func runCarrierReadinessVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck carrierreadiness verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "carrierreadiness", "carrierreadiness-golden.json"), "carrier readiness fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := carrierreadiness.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := carrierreadiness.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := carrierreadiness.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runCarrierReadinessCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck carrierreadiness compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old carrier readiness fixture")
	newPath := flags.String("new", "", "new carrier readiness fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := carrierreadiness.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := carrierreadiness.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := carrierreadiness.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := carrierreadiness.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeCarrierReadinessCompanions(out string, set carrierreadiness.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"carrierreadiness-inventory.json", set.Review.Inventory},
		{"carrierreadiness-dependencies.json", set.Review.Dependencies},
		{"carrierreadiness-boundaries.json", set.Review.Boundaries},
		{"carrierreadiness-future-contracts.json", set.Review.FutureContracts},
		{"carrierreadiness-blockers.json", set.Review.Blockers},
		{"carrierreadiness-risks.json", set.Review.Risks},
		{"carrierreadiness-misuse-report.json", set.Misuse},
		{"carrierreadiness-parity.json", set.Parity},
	}
	for _, write := range writes {
		if err := carrierreadiness.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runHTTPSCarrierReview(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runHTTPSCarrierReviewGenerate(args[1:])
		case "verify":
			return runHTTPSCarrierReviewVerify(args[1:])
		case "compare":
			return runHTTPSCarrierReviewCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck httpscarrierreview", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick HTTPS carrier design-lock audit")
	full := flags.Bool("full", false, "run full HTTPS carrier design-lock audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunHTTPSCarrierReviewAudit(context.Background(), cfg)
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

func runHTTPSCarrierReviewGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck httpscarrierreview generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "httpscarrierreview", "httpscarrierreview-report-golden.json"), "HTTPS carrier design-lock fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := httpscarrierreview.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := httpscarrierreview.WriteJSON(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeHTTPSCarrierReviewCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote httpscarrierreview fixtures: %s (%d request shapes, %d response shapes)\n", *out, len(set.RequestShapes), len(set.ResponseShapes))
	return 0
}

func runHTTPSCarrierReviewVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck httpscarrierreview verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "httpscarrierreview", "httpscarrierreview-report-golden.json"), "HTTPS carrier design-lock fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := httpscarrierreview.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := httpscarrierreview.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := httpscarrierreview.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runHTTPSCarrierReviewCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck httpscarrierreview compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old HTTPS carrier design-lock fixture")
	newPath := flags.String("new", "", "new HTTPS carrier design-lock fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := httpscarrierreview.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := httpscarrierreview.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := httpscarrierreview.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := httpscarrierreview.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeHTTPSCarrierReviewCompanions(out string, set httpscarrierreview.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"https-carrier-lab-contract.json", set.Contract},
		{"scope-report.json", set.Scope},
		{"shape-taxonomy-report.json", set.ShapeTaxonomy},
		{"request-shapes-golden.json", set.RequestShapes},
		{"response-shapes-golden.json", set.ResponseShapes},
		{"stream-mapping-report.json", set.StreamMapping},
		{"backpressure-contract-report.json", set.Backpressure},
		{"reset-error-contract-report.json", set.ResetError},
		{"integration-contract-report.json", set.Integration},
		{"m42-implementation-contract.json", set.M42Contract},
		{"blocker-matrix.json", set.Blockers},
		{"risk-report.json", set.Risks},
		{"readiness-checklist.json", set.Checklist},
		{"httpscarrierreview-misuse-report.json", set.Misuse},
		{"httpscarrierreview-controls.json", set.Controls},
	}
	for _, write := range writes {
		if err := httpscarrierreview.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runHTTPSLikeCarrier(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runHTTPSLikeCarrierGenerate(args[1:])
		case "verify":
			return runHTTPSLikeCarrierVerify(args[1:])
		case "compare":
			return runHTTPSLikeCarrierCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck httpslikecarrier", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick HTTPS-like carrier prototype audit")
	full := flags.Bool("full", false, "run full HTTPS-like carrier prototype audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunHTTPSLikeCarrierAudit(context.Background(), cfg)
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

func runHTTPSLikeCarrierGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck httpslikecarrier generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "httpslikecarrier", "httpslikecarrier-report-golden.json"), "HTTPS-like carrier prototype fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := httpslikecarrier.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := httpslikecarrier.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeHTTPSLikeCarrierCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote httpslikecarrier fixtures: %s (%d scenarios, %d shape events)\n", *out, len(set.Scenarios), len(set.Report.ShapeEvents))
	return 0
}

func runHTTPSLikeCarrierVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck httpslikecarrier verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "httpslikecarrier", "httpslikecarrier-report-golden.json"), "HTTPS-like carrier prototype fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := httpslikecarrier.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := httpslikecarrier.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := httpslikecarrier.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runHTTPSLikeCarrierCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck httpslikecarrier compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old HTTPS-like carrier prototype fixture")
	newPath := flags.String("new", "", "new HTTPS-like carrier prototype fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := httpslikecarrier.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := httpslikecarrier.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := httpslikecarrier.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := httpslikecarrier.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeHTTPSLikeCarrierCompanions(out string, set httpslikecarrier.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"scope-report.json", set.Report.ScopesBlocked},
		{"request-shapes-golden.json", set.Report.RequestShapes},
		{"response-shapes-golden.json", set.Report.ResponseShapes},
		{"control-shapes.json", set.Report.ControlShapes},
		{"shape-events-golden.json", set.Report.ShapeEvents},
		{"session-lifecycle-report.json", set.Report.Sessions},
		{"stream-lifecycle-report.json", set.Report.Streams},
		{"fixture-exchange-report.json", set.Report.FixtureExchange},
		{"integration-report.json", set.Report.Integrations},
		{"runtime-security-report.json", set.Report.RuntimeSecurity},
		{"resource-limits-report.json", set.Report.ResourceLimits},
		{"httpslikecarrier-misuse-report.json", set.Misuse},
		{"httpslikecarrier-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := httpslikecarrier.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runHTTPSCarrierAdversary(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runHTTPSCarrierAdversaryGenerate(args[1:])
		case "verify":
			return runHTTPSCarrierAdversaryVerify(args[1:])
		case "compare":
			return runHTTPSCarrierAdversaryCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck httpscarrieradversary", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick HTTPS carrier adversary audit")
	full := flags.Bool("full", false, "run full HTTPS carrier adversary audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunHTTPSCarrierAdversaryAudit(context.Background(), cfg)
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

func runHTTPSCarrierAdversaryGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck httpscarrieradversary generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "httpscarrieradversary", "httpscarrieradversary-report-golden.json"), "HTTPS carrier adversary fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := httpscarrieradversary.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := httpscarrieradversary.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeHTTPSCarrierAdversaryCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote httpscarrieradversary fixtures: %s (%d scenarios, %d controls)\n", *out, len(set.Scenarios), set.Misuse.DetectedCount)
	return 0
}

func runHTTPSCarrierAdversaryVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck httpscarrieradversary verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "httpscarrieradversary", "httpscarrieradversary-report-golden.json"), "HTTPS carrier adversary fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := httpscarrieradversary.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := httpscarrieradversary.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := httpscarrieradversary.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runHTTPSCarrierAdversaryCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck httpscarrieradversary compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old HTTPS carrier adversary fixture")
	newPath := flags.String("new", "", "new HTTPS carrier adversary fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := httpscarrieradversary.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := httpscarrieradversary.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := httpscarrieradversary.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := httpscarrieradversary.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeHTTPSCarrierAdversaryCompanions(out string, set httpscarrieradversary.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"collapse-report.json", set.Report.Collapse},
		{"profile-sensitivity-report.json", set.Report.ProfileSensitivity},
		{"padding-variation-report.json", set.Report.PaddingVariation},
		{"unsafe-fallback-report.json", set.Report.UnsafeFallback},
		{"trace-hygiene-report.json", set.Report.TraceHygiene},
		{"replay-control-report.json", set.Report.ReplayControls},
		{"stream-isolation-report.json", set.Report.StreamIsolation},
		{"backpressure-report.json", set.Report.Backpressure},
		{"reset-error-report.json", set.Report.ResetError},
		{"integration-bypass-report.json", set.Report.IntegrationBypass},
		{"public-claim-safety-report.json", set.Report.PublicClaims},
		{"httpscarrieradversary-misuse-report.json", set.Misuse},
		{"httpscarrieradversary-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := httpscarrieradversary.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runConstrainedCarrierReview(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runConstrainedCarrierReviewGenerate(args[1:])
		case "verify":
			return runConstrainedCarrierReviewVerify(args[1:])
		case "compare":
			return runConstrainedCarrierReviewCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck constrainedcarrierreview", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick constrained carrier review audit")
	full := flags.Bool("full", false, "run full constrained carrier review audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunConstrainedCarrierReviewAudit(context.Background(), cfg)
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

func runConstrainedCarrierReviewGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck constrainedcarrierreview generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "constrainedcarrierreview", "constrainedcarrierreview-report-golden.json"), "constrained carrier review fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := constrainedcarrierreview.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := constrainedcarrierreview.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeConstrainedCarrierReviewCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote constrainedcarrierreview fixtures: %s (%d fixtures, %d controls)\n", *out, len(set.Fixtures), set.Report.Misuse.DetectedCount)
	return 0
}

func runConstrainedCarrierReviewVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck constrainedcarrierreview verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "constrainedcarrierreview", "constrainedcarrierreview-report-golden.json"), "constrained carrier review fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := constrainedcarrierreview.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := constrainedcarrierreview.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := constrainedcarrierreview.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runConstrainedCarrierReviewCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck constrainedcarrierreview compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old constrained carrier review fixture")
	newPath := flags.String("new", "", "new constrained carrier review fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := constrainedcarrierreview.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := constrainedcarrierreview.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := constrainedcarrierreview.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := constrainedcarrierreview.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeConstrainedCarrierReviewCompanions(out string, set constrainedcarrierreview.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"scope-report.json", set.Report.Scope},
		{"resolver-harness-contract.json", set.Report.ResolverHarness},
		{"query-shape-taxonomy.json", set.Report.QueryShapes},
		{"response-shape-taxonomy.json", set.Report.ResponseShapes},
		{"size-truncation-report.json", set.Report.SizeTruncation},
		{"retry-failure-report.json", set.Report.RetryFailure},
		{"stream-mapping-report.json", set.Report.StreamMapping},
		{"privacy-measurement-report.json", set.Report.PrivacyMeasurement},
		{"m45-implementation-contract.json", set.Report.M45Contract},
		{"blocker-matrix.json", set.Report.Blockers},
		{"risk-report.json", set.Report.Risks},
		{"readiness-checklist.json", set.Report.Checklist},
		{"constrainedcarrierreview-misuse-report.json", set.Report.Misuse},
		{"constrainedcarrierreview-controls.json", set.Report.M45Contract.RequiredControls},
		{"constrainedcarrierreview-parity-report.json", set.Report.Parity},
	}
	for _, write := range writes {
		if err := constrainedcarrierreview.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runConstrainedCarrier(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runConstrainedCarrierGenerate(args[1:])
		case "verify":
			return runConstrainedCarrierVerify(args[1:])
		case "compare":
			return runConstrainedCarrierCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck constrainedcarrier", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick constrained carrier audit")
	full := flags.Bool("full", false, "run full constrained carrier audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunConstrainedCarrierAudit(context.Background(), cfg)
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

func runConstrainedCarrierGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck constrainedcarrier generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "constrainedcarrier", "constrainedcarrier-report-golden.json"), "constrained carrier fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := constrainedcarrier.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := constrainedcarrier.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeConstrainedCarrierCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote constrainedcarrier fixtures: %s (%d scenarios, %d controls)\n", *out, len(set.Scenarios), set.Report.Misuse.DetectedCount)
	return 0
}

func runConstrainedCarrierVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck constrainedcarrier verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "constrainedcarrier", "constrainedcarrier-report-golden.json"), "constrained carrier fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := constrainedcarrier.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := constrainedcarrier.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := constrainedcarrier.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runConstrainedCarrierCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck constrainedcarrier compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old constrained carrier fixture")
	newPath := flags.String("new", "", "new constrained carrier fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := constrainedcarrier.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := constrainedcarrier.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := constrainedcarrier.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := constrainedcarrier.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeConstrainedCarrierCompanions(out string, set constrainedcarrier.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"harness-report.json", set.Report.Harness},
		{"query-shape-report.json", set.Report.QueryShapes},
		{"response-shape-report.json", set.Report.ResponseShapes},
		{"capacity-truncation-report.json", set.Report.CapacityTruncation},
		{"retry-failure-report.json", set.Report.RetryFailure},
		{"profile-sensitivity-report.json", set.Report.ProfileSensitivity},
		{"stream-mapping-report.json", set.Report.Streams},
		{"backpressure-report.json", set.Report.Backpressure},
		{"reset-error-report.json", set.Report.ResetError},
		{"integration-report.json", set.Report.Integrations},
		{"diagnostics-report.json", set.Report.Diagnostics},
		{"resource-limits-report.json", set.Report.ResourceLimits},
		{"constrainedcarrier-misuse-report.json", set.Report.Misuse},
		{"constrainedcarrier-parity-report.json", set.Report.Parity},
	}
	for _, write := range writes {
		if err := constrainedcarrier.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runMultiCarrierSelect(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runMultiCarrierSelectGenerate(args[1:])
		case "verify":
			return runMultiCarrierSelectVerify(args[1:])
		case "compare":
			return runMultiCarrierSelectCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck multicarrierselect", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick multi-carrier selection audit")
	full := flags.Bool("full", false, "run full multi-carrier selection audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunMultiCarrierSelectAudit(context.Background(), cfg)
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

func runMultiCarrierSelectGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck multicarrierselect generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "multicarrierselect", "multicarrierselect-report-golden.json"), "multi-carrier selection fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := multicarrierselect.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := multicarrierselect.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeMultiCarrierSelectCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote multicarrierselect fixtures: %s (%d candidates, %d controls)\n", *out, len(set.Report.Candidates), set.Report.Misuse.DetectedCount)
	return 0
}

func runMultiCarrierSelectVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck multicarrierselect verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "multicarrierselect", "multicarrierselect-report-golden.json"), "multi-carrier selection fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := multicarrierselect.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := multicarrierselect.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := multicarrierselect.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runMultiCarrierSelectCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck multicarrierselect compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old multi-carrier selection fixture")
	newPath := flags.String("new", "", "new multi-carrier selection fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := multicarrierselect.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := multicarrierselect.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := multicarrierselect.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := multicarrierselect.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeMultiCarrierSelectCompanions(out string, set multicarrierselect.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"carrier-inventory-report.json", set.Report.Inventory},
		{"candidate-bundle-report.json", set.Report.Candidates},
		{"selection-policy-report.json", set.Report.SelectionPolicy},
		{"profile-sensitivity-report.json", set.Report.ProfileSensitivity},
		{"pathrace-report.json", set.Report.Race},
		{"pathhealth-report.json", set.Report.Health},
		{"failover-fallback-report.json", set.Report.Failover},
		{"composition-report.json", set.Report.Compositions},
		{"multicarrierselect-misuse-report.json", set.Report.Misuse},
		{"multicarrierselect-parity-report.json", set.Report.Parity},
		{"public-claim-safety-report.json", set.Report.PublicClaimSafety},
	}
	for _, write := range writes {
		if err := multicarrierselect.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runCarrierCollapse(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runCarrierCollapseGenerate(args[1:])
		case "verify":
			return runCarrierCollapseVerify(args[1:])
		case "compare":
			return runCarrierCollapseCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck carriercollapse", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick carrier collapse audit")
	full := flags.Bool("full", false, "run full carrier collapse audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunCarrierCollapseAudit(context.Background(), cfg)
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

func runCarrierCollapseGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck carriercollapse generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "carriercollapse", "carriercollapse-report-golden.json"), "carrier collapse fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := carriercollapse.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := carriercollapse.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeCarrierCollapseCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote carriercollapse fixtures: %s (%d fixtures, %d controls)\n", *out, len(set.Fixtures), set.Report.Mutations.DetectedCount)
	return 0
}

func runCarrierCollapseVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck carriercollapse verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "carriercollapse", "carriercollapse-report-golden.json"), "carrier collapse fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := carriercollapse.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := carriercollapse.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := carriercollapse.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runCarrierCollapseCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck carriercollapse compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old carrier collapse fixture")
	newPath := flags.String("new", "", "new carrier collapse fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := carriercollapse.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := carriercollapse.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := carriercollapse.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := carriercollapse.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeCarrierCollapseCompanions(out string, set carriercollapse.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"carrier-diversity-report.json", set.Report.Diversity},
		{"shape-diversity-report.json", set.Report.Diversity.ShapeClasses},
		{"profile-sensitivity-report.json", set.Report.SelectionCollapse},
		{"bundle-sensitivity-report.json", set.Report.SelectionCollapse.BundleSensitive},
		{"selection-collapse-report.json", set.Report.SelectionCollapse},
		{"fallback-safety-report.json", set.Report.FallbackSafety},
		{"pathhealth-pathrace-enforcement-report.json", []carriercollapse.EnforcementReport{set.Report.PathHealth, set.Report.PathRace}},
		{"review-enforcement-report.json", []carriercollapse.EnforcementReport{set.Report.MeasurementReview, set.Report.CarrierReview, set.Report.LabEgress}},
		{"stream-backpressure-reset-report.json", set.Report.RuntimeSafety},
		{"carriercollapse-parity-report.json", set.Report.Parity},
		{"trace-hygiene-report.json", set.Report.TraceHygiene},
		{"mutation-coverage-report.json", set.Report.Mutations},
		{"public-claim-safety-report.json", set.Report.PublicClaims},
	}
	for _, write := range writes {
		if err := carriercollapse.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runLocalProxyAdapterReview(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runLocalProxyAdapterReviewGenerate(args[1:])
		case "verify":
			return runLocalProxyAdapterReviewVerify(args[1:])
		case "compare":
			return runLocalProxyAdapterReviewCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck localproxyadapterreview", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local proxy adapter review audit")
	full := flags.Bool("full", false, "run full local proxy adapter review audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunLocalProxyAdapterReviewAudit(context.Background(), cfg)
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

func runLocalProxyAdapterReviewGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyadapterreview generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "localproxyadapterreview", "localproxyadapterreview-report-golden.json"), "local proxy adapter review fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := localproxyadapterreview.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := localproxyadapterreview.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeLocalProxyAdapterReviewCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote localproxyadapterreview fixtures: %s (%d fixtures, %d controls)\n", *out, len(set.Fixtures), set.Misuse.DetectedCount)
	return 0
}

func runLocalProxyAdapterReviewVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyadapterreview verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "localproxyadapterreview", "localproxyadapterreview-report-golden.json"), "local proxy adapter review fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := localproxyadapterreview.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localproxyadapterreview.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localproxyadapterreview.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runLocalProxyAdapterReviewCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyadapterreview compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old local proxy adapter review fixture")
	newPath := flags.String("new", "", "new local proxy adapter review fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := localproxyadapterreview.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localproxyadapterreview.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localproxyadapterreview.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := localproxyadapterreview.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeLocalProxyAdapterReviewCompanions(out string, set localproxyadapterreview.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"adapter-scope-report.json", set.Scope},
		{"protocol-acceptance-report.json", set.Protocols},
		{"payload-handling-contract.json", set.Payload},
		{"stream-mapping-contract.json", set.StreamMapping},
		{"backpressure-reset-contract.json", set.BackpressureReset},
		{"target-redaction-report.json", set.TargetRedaction},
		{"carrier-selector-integration-report.json", set.Integration},
		{"resource-limit-contract.json", set.ResourceLimits},
		{"misuse-report.json", set.Misuse},
		{"public-claim-safety-report.json", set.PublicClaims},
		{"m49-implementation-contract.json", set.M49Contract},
		{"localproxyadapterreview-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := localproxyadapterreview.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runLocalProxyAdapter(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runLocalProxyAdapterGenerate(args[1:])
		case "verify":
			return runLocalProxyAdapterVerify(args[1:])
		case "compare":
			return runLocalProxyAdapterCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck localproxyadapter", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local proxy adapter audit")
	full := flags.Bool("full", false, "run full local proxy adapter audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunLocalProxyAdapterAudit(context.Background(), cfg)
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

func runLocalProxyAdapterGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyadapter generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "localproxyadapter", "localproxyadapter-report-golden.json"), "local proxy adapter fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := localproxyadapter.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := localproxyadapter.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeLocalProxyAdapterCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote localproxyadapter fixtures: %s (%d runs, %d controls)\n", *out, len(set.Runs), set.Misuse.DetectedCount)
	return 0
}

func runLocalProxyAdapterVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyadapter verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "localproxyadapter", "localproxyadapter-report-golden.json"), "local proxy adapter fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := localproxyadapter.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localproxyadapter.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localproxyadapter.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runLocalProxyAdapterCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck localproxyadapter compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old local proxy adapter fixture")
	newPath := flags.String("new", "", "new local proxy adapter fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := localproxyadapter.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localproxyadapter.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localproxyadapter.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := localproxyadapter.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeLocalProxyAdapterCompanions(out string, set localproxyadapter.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"config.json", set.Config},
		{"accepted-requests.json", set.Requests},
		{"stream-runs.json", set.Runs},
		{"prototype-summary.json", set.Summary},
		{"integration-report.json", set.Integration},
		{"resource-limit-report.json", set.ResourceLimits},
		{"misuse-report.json", set.Misuse},
		{"localproxyadapter-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := localproxyadapter.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runVPNSemantics(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runVPNSemanticsGenerate(args[1:])
		case "verify":
			return runVPNSemanticsVerify(args[1:])
		case "compare":
			return runVPNSemanticsCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck vpnsemantics", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick VPN semantics audit")
	full := flags.Bool("full", false, "run full VPN semantics audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunVPNSemanticsAudit(context.Background(), cfg)
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

func runVPNSemanticsGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck vpnsemantics generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "vpnsemantics", "vpnsemantics-report-golden.json"), "VPN semantics fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := vpnsemantics.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := vpnsemantics.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeVPNSemanticsCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote vpnsemantics fixtures: %s (%d fixtures, %d controls)\n", *out, len(set.Fixtures), set.Misuse.DetectedCount)
	return 0
}

func runVPNSemanticsVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck vpnsemantics verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "vpnsemantics", "vpnsemantics-report-golden.json"), "VPN semantics fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := vpnsemantics.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := vpnsemantics.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := vpnsemantics.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runVPNSemanticsCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck vpnsemantics compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old VPN semantics fixture")
	newPath := flags.String("new", "", "new VPN semantics fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := vpnsemantics.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := vpnsemantics.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := vpnsemantics.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := vpnsemantics.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeVPNSemanticsCompanions(out string, set vpnsemantics.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"packet-flow-taxonomy.json", set.Taxonomy},
		{"flow-stream-mapping.json", set.Mapping},
		{"mtu-fragmentation-semantics.json", set.MTU},
		{"boundary-policy-report.json", set.Boundaries},
		{"m51-implementation-contract.json", set.M51Contract},
		{"misuse-report.json", set.Misuse},
		{"vpnsemantics-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := vpnsemantics.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runLocalVPNAdapter(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runLocalVPNAdapterGenerate(args[1:])
		case "verify":
			return runLocalVPNAdapterVerify(args[1:])
		case "compare":
			return runLocalVPNAdapterCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck localvpnadapter", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick local packet adapter audit")
	full := flags.Bool("full", false, "run full local packet adapter audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunLocalVPNAdapterAudit(context.Background(), cfg)
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

func runLocalVPNAdapterGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck localvpnadapter generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "localvpnadapter", "localvpnadapter-report-golden.json"), "local packet adapter fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := localvpnadapter.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := localvpnadapter.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeLocalVPNAdapterCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote localvpnadapter fixtures: %s (%d flows, %d controls)\n", *out, len(set.Runs), set.Misuse.DetectedCount)
	return 0
}

func runLocalVPNAdapterVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck localvpnadapter verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "localvpnadapter", "localvpnadapter-report-golden.json"), "local packet adapter fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := localvpnadapter.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localvpnadapter.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localvpnadapter.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runLocalVPNAdapterCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck localvpnadapter compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old local packet adapter fixture")
	newPath := flags.String("new", "", "new local packet adapter fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := localvpnadapter.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := localvpnadapter.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := localvpnadapter.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := localvpnadapter.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeLocalVPNAdapterCompanions(out string, set localvpnadapter.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"flow-descriptors.json", set.Descriptors},
		{"flow-runs.json", set.Runs},
		{"integration-report.json", set.Integration},
		{"resource-report.json", set.Resource},
		{"panic-safety-report.json", set.PanicSafety},
		{"trace-hygiene-report.json", set.TraceHygiene},
		{"misuse-report.json", set.Misuse},
		{"localvpnadapter-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := localvpnadapter.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runRelayProcess(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runRelayProcessGenerate(args[1:])
		case "verify":
			return runRelayProcessVerify(args[1:])
		case "compare":
			return runRelayProcessCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck relayprocess", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick relay process architecture audit")
	full := flags.Bool("full", false, "run full relay process architecture audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunRelayProcessAudit(context.Background(), cfg)
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

func runRelayProcessGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck relayprocess generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "relayprocess", "relayprocess-report-golden.json"), "relay process fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := relayprocess.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := relayprocess.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeRelayProcessCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote relayprocess fixtures: %s (%d roles, %d controls)\n", *out, len(set.Roles), set.Misuse.DetectedCount)
	return 0
}

func runRelayProcessVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck relayprocess verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "relayprocess", "relayprocess-report-golden.json"), "relay process fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := relayprocess.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := relayprocess.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := relayprocess.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runRelayProcessCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck relayprocess compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old relay process fixture")
	newPath := flags.String("new", "", "new relay process fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := relayprocess.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := relayprocess.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := relayprocess.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := relayprocess.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeRelayProcessCompanions(out string, set relayprocess.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"process-role-inventory.json", set.Roles},
		{"config-contract.json", set.Config},
		{"lifecycle-contract.json", set.Lifecycle},
		{"logging-observability-contract.json", set.Logging},
		{"shutdown-crash-recovery-contract.json", set.Shutdown},
		{"compatibility-contract.json", set.Compatibility},
		{"resource-contract.json", set.Resource},
		{"abuse-control-placeholder-contract.json", set.Resource.AbuseControlPolicy},
		{"m53-preconditions.json", set.M53Preconditions},
		{"misuse-report.json", set.Misuse},
		{"trace-hygiene-report.json", set.TraceHygiene},
		{"public-claim-safety-report.json", set.PublicClaims},
		{"relayprocess-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := relayprocess.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runKeyExchangePlan(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runKeyExchangePlanGenerate(args[1:])
		case "verify":
			return runKeyExchangePlanVerify(args[1:])
		case "compare":
			return runKeyExchangePlanCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck keyexchangeplan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick production key exchange design audit")
	full := flags.Bool("full", false, "run full production key exchange design audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunKeyExchangePlanAudit(context.Background(), cfg)
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

func runKeyExchangePlanGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck keyexchangeplan generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "keyexchangeplan", "keyexchangeplan-report-golden.json"), "key exchange plan fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := keyexchangeplan.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := keyexchangeplan.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeKeyExchangePlanCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote keyexchangeplan fixtures: %s (%d design items, %d controls)\n", *out, len(set.DesignInventory), set.Misuse.DetectedCount)
	return 0
}

func runKeyExchangePlanVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck keyexchangeplan verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "keyexchangeplan", "keyexchangeplan-report-golden.json"), "key exchange plan fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := keyexchangeplan.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := keyexchangeplan.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := keyexchangeplan.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runKeyExchangePlanCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck keyexchangeplan compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old key exchange plan fixture")
	newPath := flags.String("new", "", "new key exchange plan fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := keyexchangeplan.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := keyexchangeplan.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := keyexchangeplan.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := keyexchangeplan.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeKeyExchangePlanCompanions(out string, set keyexchangeplan.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"design-inventory.json", set.DesignInventory},
		{"transcript-binding-report.json", set.TranscriptBinding},
		{"identity-binding-report.json", set.IdentityBinding},
		{"nonce-replay-report.json", set.NonceReplay},
		{"downgrade-resistance-report.json", set.DowngradeResistance},
		{"key-separation-report.json", set.KeySeparation},
		{"rotation-readiness-report.json", set.RotationReadiness},
		{"generated-transport-compatibility-report.json", set.TransportCompatibility},
		{"external-crypto-review-readiness-report.json", set.ExternalReviewReadiness},
		{"misuse-report.json", set.Misuse},
		{"trace-hygiene-report.json", set.TraceHygiene},
		{"public-claim-safety-report.json", set.PublicClaims},
		{"keyexchangeplan-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := keyexchangeplan.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runRelayAuthPlan(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runRelayAuthPlanGenerate(args[1:])
		case "verify":
			return runRelayAuthPlanVerify(args[1:])
		case "compare":
			return runRelayAuthPlanCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck relayauthplan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick relay auth plan audit")
	full := flags.Bool("full", false, "run full relay auth plan audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunRelayAuthPlanAudit(context.Background(), cfg)
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

func runRelayAuthPlanGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck relayauthplan generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "relayauthplan", "relayauthplan-report-golden.json"), "relay auth plan fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := relayauthplan.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := relayauthplan.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeRelayAuthPlanCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote relayauthplan fixtures: %s (%d auth items, %d controls)\n", *out, len(set.AuthInventory), set.Misuse.DetectedCount)
	return 0
}

func runRelayAuthPlanVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck relayauthplan verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "relayauthplan", "relayauthplan-report-golden.json"), "relay auth plan fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := relayauthplan.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := relayauthplan.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := relayauthplan.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runRelayAuthPlanCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck relayauthplan compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old relay auth plan fixture")
	newPath := flags.String("new", "", "new relay auth plan fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := relayauthplan.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := relayauthplan.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := relayauthplan.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := relayauthplan.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeRelayAuthPlanCompanions(out string, set relayauthplan.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"relay-auth-inventory.json", set.AuthInventory},
		{"identity-binding-policy.json", set.IdentityBinding},
		{"compatibility-matrix.json", set.CompatibilityMatrix},
		{"rotation-policy.json", set.RotationPolicy},
		{"expiry-revocation-policy.json", set.ExpiryRevocation},
		{"safe-failure-policy.json", set.SafeFailure},
		{"downgrade-rejection-report.json", set.DowngradeRejection},
		{"unknown-stale-profile-report.json", set.UnknownStaleProfile},
		{"m55-operational-hardening-prerequisites.json", set.OperationalPrereqs},
		{"misuse-report.json", set.Misuse},
		{"trace-hygiene-report.json", set.TraceHygiene},
		{"public-claim-safety-report.json", set.PublicClaims},
		{"relayauthplan-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := relayauthplan.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runOperationalHardening(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runOperationalHardeningGenerate(args[1:])
		case "verify":
			return runOperationalHardeningVerify(args[1:])
		case "compare":
			return runOperationalHardeningCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck operationalhardening", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick operational hardening audit")
	full := flags.Bool("full", false, "run full operational hardening audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunOperationalHardeningAudit(context.Background(), cfg)
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

func runOperationalHardeningGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck operationalhardening generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "operationalhardening", "operationalhardening-report-golden.json"), "operational hardening fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := operationalhardening.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := operationalhardening.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeOperationalHardeningCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote operationalhardening fixtures: %s (%d bounds, %d controls)\n", *out, len(set.ResourceLimits.Bounds), set.Misuse.DetectedCount)
	return 0
}

func runOperationalHardeningVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck operationalhardening verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "operationalhardening", "operationalhardening-report-golden.json"), "operational hardening fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := operationalhardening.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := operationalhardening.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := operationalhardening.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runOperationalHardeningCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck operationalhardening compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old operational hardening fixture")
	newPath := flags.String("new", "", "new operational hardening fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := operationalhardening.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := operationalhardening.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := operationalhardening.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := operationalhardening.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeOperationalHardeningCompanions(out string, set operationalhardening.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"resource-limits.json", set.ResourceLimits},
		{"config-validation.json", set.ConfigValidation},
		{"lifecycle-shutdown-restart.json", set.Lifecycle},
		{"safe-logging-diagnostics.json", set.Logging},
		{"rollback-update-boundaries.json", set.Rollback},
		{"health-summary.json", set.Health},
		{"compatibility-integration.json", set.Compatibility},
		{"checklist-report.json", set.Checklist},
		{"misuse-report.json", set.Misuse},
		{"trace-hygiene-report.json", set.TraceHygiene},
		{"public-claim-safety-report.json", set.PublicClaims},
		{"operationalhardening-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := operationalhardening.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runAndroidReview(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runAndroidReviewGenerate(args[1:])
		case "verify":
			return runAndroidReviewVerify(args[1:])
		case "compare":
			return runAndroidReviewCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck androidreview", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick Android architecture review audit")
	full := flags.Bool("full", false, "run full Android architecture review audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunAndroidReviewAudit(context.Background(), cfg)
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

func runAndroidReviewGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck androidreview generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "androidreview", "androidreview-report-golden.json"), "Android review fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := androidreview.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := androidreview.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeAndroidReviewCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote androidreview fixtures: %s (%d flows, %d controls)\n", *out, len(set.UserFlows.Flows), set.Misuse.DetectedCount)
	return 0
}

func runAndroidReviewVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck androidreview verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "androidreview", "androidreview-report-golden.json"), "Android review fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := androidreview.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := androidreview.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := androidreview.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runAndroidReviewCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck androidreview compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old Android review fixture")
	newPath := flags.String("new", "", "new Android review fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := androidreview.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := androidreview.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := androidreview.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := androidreview.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeAndroidReviewCompanions(out string, set androidreview.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"user-flows.json", set.UserFlows},
		{"permission-model.json", set.Permissions},
		{"ui-states.json", set.UIStates},
		{"diagnostics-privacy.json", set.Diagnostics},
		{"privacy-boundaries.json", set.Privacy},
		{"kill-switch.json", set.KillSwitch},
		{"runtime-composition.json", set.Integration},
		{"m57-m58-contracts.json", set.Contracts},
		{"checklist-report.json", set.Checklist},
		{"misuse-report.json", set.Misuse},
		{"trace-hygiene-report.json", set.TraceHygiene},
		{"public-claim-safety-report.json", set.PublicClaims},
		{"androidreview-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := androidreview.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}

func runAndroidRuntime(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "generate":
			return runAndroidRuntimeGenerate(args[1:])
		case "verify":
			return runAndroidRuntimeVerify(args[1:])
		case "compare":
			return runAndroidRuntimeCompare(args[1:])
		}
	}
	flags := flag.NewFlagSet("kcheck androidruntime", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	quick := flags.Bool("quick", false, "run quick Android local runtime audit")
	full := flags.Bool("full", false, "run full Android local runtime audit")
	out := flags.String("out", "", "optional JSON report path")
	status := flags.String("status", "", "optional status markdown path")
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
	report, err := audit.RunAndroidRuntimeAudit(context.Background(), cfg)
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

func runAndroidRuntimeGenerate(args []string) int {
	flags := flag.NewFlagSet("kcheck androidruntime generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", filepath.Join("testdata", "androidruntime", "androidruntime-report-golden.json"), "Android runtime fixture path")
	force := flags.Bool("force", false, "overwrite fixture")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	set, err := androidruntime.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := androidruntime.WriteFixtureSet(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeAndroidRuntimeCompanions(*out, set, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote androidruntime fixtures: %s (%d lifecycle events, %d controls)\n", *out, len(set.Lifecycle.Events), set.Misuse.DetectedCount)
	return 0
}

func runAndroidRuntimeVerify(args []string) int {
	flags := flag.NewFlagSet("kcheck androidruntime verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseline := flags.String("baseline", filepath.Join("testdata", "androidruntime", "androidruntime-report-golden.json"), "Android runtime fixture path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	oldSet, err := androidruntime.LoadFixtureSet(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := androidruntime.GenerateFixtureSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := androidruntime.CompareFixtureSets(oldSet, newSet)
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func runAndroidRuntimeCompare(args []string) int {
	flags := flag.NewFlagSet("kcheck androidruntime compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldPath := flags.String("old", "", "old Android runtime fixture")
	newPath := flags.String("new", "", "new Android runtime fixture")
	out := flags.String("out", "", "optional comparison JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "--old and --new are required")
		return 2
	}
	oldSet, err := androidruntime.LoadFixtureSet(*oldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newSet, err := androidruntime.LoadFixtureSet(*newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := androidruntime.CompareFixtureSets(oldSet, newSet)
	if *out != "" {
		if err := androidruntime.WriteJSON(*out, report, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(raw))
	if report.Conclusion != "passed" {
		return 1
	}
	return 0
}

func writeAndroidRuntimeCompanions(out string, set androidruntime.FixtureSet, force bool) error {
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	writes := []struct {
		name  string
		value any
	}{
		{"initialization.json", set.Initialization},
		{"lifecycle.json", set.Lifecycle},
		{"storage-boundaries.json", set.Storage},
		{"diagnostics.json", set.Diagnostics},
		{"concurrency.json", set.Concurrency},
		{"compatibility.json", set.Compatibility},
		{"shutdown.json", set.Shutdown},
		{"checklist-report.json", set.Checklist},
		{"misuse-report.json", set.Misuse},
		{"trace-hygiene-report.json", set.TraceHygiene},
		{"public-claim-safety-report.json", set.PublicClaims},
		{"androidruntime-parity-report.json", set.Parity},
	}
	for _, write := range writes {
		if err := androidruntime.WriteJSON(filepath.Join(dir, write.name), write.value, force); err != nil {
			return err
		}
	}
	return nil
}
