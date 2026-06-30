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

	"kurdistan/internal/auth"
	"kurdistan/internal/compiler"
	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
	"kurdistan/internal/transportbundle"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = generate(os.Args[2:])
	case "validate":
		err = validate(os.Args[2:])
	case "corpus":
		err = corpus(os.Args[2:])
	case "bundle":
		err = bundle(os.Args[2:])
	case "validate-bundle":
		err = validateBundle(os.Args[2:])
	case "summarize-bundle":
		err = summarizeBundle(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func bundle(args []string) error {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	seed := fs.Int("seed", 12345, "deterministic bundle seed")
	mode := fs.String("mode", string(transportbundle.BundleModeBalancedAdaptive), "transport bundle mode")
	out := fs.String("out", "profiles/examples/bundle-12345.json", "output bundle manifest path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	policy := transportbundle.DefaultPolicy(*seed, transportbundle.BundleMode(*mode))
	compiled, err := transportbundle.Compile(context.Background(), policy)
	if err != nil {
		return err
	}
	if err := transportbundle.ScanForLeak(compiled.Manifest); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil && filepath.Dir(*out) != "." {
		return err
	}
	raw, err := json.MarshalIndent(compiled.Manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	printBundleSummary(compiled.Manifest)
	return nil
}

func validateBundle(args []string) error {
	fs := flag.NewFlagSet("validate-bundle", flag.ContinueOnError)
	bundlePath := fs.String("bundle", "", "bundle manifest path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		return fmt.Errorf("--bundle is required")
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	var manifest transportbundle.TransportBundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if err := transportbundle.ValidateManifest(manifest); err != nil {
		return err
	}
	printBundleSummary(manifest)
	return nil
}

func summarizeBundle(args []string) error {
	fs := flag.NewFlagSet("summarize-bundle", flag.ContinueOnError)
	bundlePath := fs.String("bundle", "", "bundle manifest path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		return fmt.Errorf("--bundle is required")
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	var manifest transportbundle.TransportBundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if err := transportbundle.ValidateManifest(manifest); err != nil {
		return err
	}
	printBundleSummary(manifest)
	return nil
}

func generate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	seed := fs.Int64("seed", 0, "deterministic seed")
	out := fs.String("out", "profile.json", "output profile path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	seedProvided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "seed" {
			seedProvided = true
		}
	})
	if !seedProvided {
		randomSeed, err := auth.RandomSeed()
		if err != nil {
			return err
		}
		*seed = randomSeed
	}
	p, err := compiler.Generate(*seed)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil && filepath.Dir(*out) != "." {
		return err
	}
	if err := ir.SaveProfile(*out, p); err != nil {
		return err
	}
	printSummary(p)
	return nil
}

func validate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	profilePath := fs.String("profile", "", "profile path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *profilePath == "" {
		return fmt.Errorf("--profile is required")
	}
	p, err := ir.LoadProfile(*profilePath)
	if err != nil {
		return err
	}
	if err := ir.Validate(p); err != nil {
		return err
	}
	if err := compiler.ValidateDeterministic(p); err != nil {
		return err
	}
	printSummary(p)
	return nil
}

func corpus(args []string) error {
	fs := flag.NewFlagSet("corpus", flag.ContinueOnError)
	startSeed := fs.Int64("start-seed", 1, "first deterministic seed")
	count := fs.Int("count", 1000, "number of profiles to generate")
	out := fs.String("out", "testdata/corpus/summary.json", "summary JSON path")
	writeProfiles := fs.Bool("write-profiles", false, "write full profile JSON files next to the summary")
	profilesDir := fs.String("profiles-dir", "", "optional directory for --write-profiles")
	if err := fs.Parse(args); err != nil {
		return err
	}
	profiles, err := diversity.GenerateProfiles(*startSeed, *count)
	if err != nil {
		return err
	}
	summary := diversity.SummarizeCorpus(*startSeed, profiles)
	if err := diversity.WriteCorpusSummary(*out, summary); err != nil {
		return err
	}
	if *writeProfiles {
		dir := *profilesDir
		if dir == "" {
			dir = filepath.Join(filepath.Dir(*out), "profiles")
		}
		if err := diversity.WriteProfiles(dir, profiles); err != nil {
			return err
		}
	}
	fmt.Printf("profiles: %d\n", summary.ProfileCount)
	fmt.Printf("unique_first_contact_patterns: %d\n", summary.UniqueFirstContactPatterns)
	fmt.Printf("unique_frame_grammar_combinations: %d\n", summary.UniqueFrameGrammarCombinations)
	fmt.Printf("unique_scheduler_combinations: %d\n", summary.UniqueSchedulerCombinations)
	fmt.Printf("unique_padding_combinations: %d\n", summary.UniquePaddingCombinations)
	fmt.Printf("unique_invalid_input_policy_combinations: %d\n", summary.UniqueInvalidInputPolicyCombinations)
	fmt.Printf("structurally_different_pairs: %d\n", summary.StructurallyDifferentPairs)
	return nil
}

func printSummary(p *ir.Profile) {
	fmt.Printf("profile_id: %s\n", p.ID)
	fmt.Printf("states: %d\n", len(p.States))
	fmt.Printf("transitions: %d\n", len(p.Transitions))
	fmt.Printf("first_contact_pattern: %s\n", p.FirstContact.PatternID)
	fmt.Printf("frame_grammar_family: %s/%s/%s\n", p.FrameGrammar.LengthMode, p.FrameGrammar.TypeMode, p.FrameGrammar.FragmentationMode)
	fmt.Printf("scheduler_mode: %s\n", p.Scheduler.Mode)
	fmt.Printf("padding_policy: %s min=%d max=%d probability=%.2f\n", p.Padding.Mode, p.Padding.MinPaddingBytes, p.Padding.MaxPaddingBytes, p.Padding.Probability)
}

func printBundleSummary(manifest transportbundle.TransportBundleManifest) {
	fmt.Printf("bundle_id: %s\n", manifest.BundleID)
	fmt.Printf("mode: %s\n", manifest.Mode)
	fmt.Printf("candidates: %d\n", len(manifest.Candidates))
	fmt.Printf("fallback_hints: %d\n", len(manifest.FallbackPlan.OrderedCandidateIDs))
	fmt.Printf("family_counts: %v\n", manifest.FamilyCounts)
	fmt.Printf("role_counts: %v\n", manifest.RoleCounts)
	fmt.Printf("bundle_hash: %s\n", manifest.BundleHash)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: kdc generate --seed 12345 --out profile.json | kdc validate --profile profile.json | kdc corpus --start-seed 1 --count 1000 --out testdata/corpus/summary.json | kdc bundle --seed 12345 --mode balanced_adaptive --out profiles/examples/bundle-12345.json | kdc validate-bundle --bundle profiles/examples/bundle-12345.json")
}
