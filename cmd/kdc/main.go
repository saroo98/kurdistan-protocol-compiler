// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"kurdistan/internal/auth"
	"kurdistan/internal/compiler"
	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
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
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: kdc generate --seed 12345 --out profile.json | kdc validate --profile profile.json | kdc corpus --start-seed 1 --count 1000 --out testdata/corpus/summary.json")
}
