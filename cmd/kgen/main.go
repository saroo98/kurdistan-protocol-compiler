package main

import (
	"flag"
	"fmt"
	"os"

	"kurdistan/internal/codegen"
	"kurdistan/internal/ir"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("kgen", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	profilePath := flags.String("profile", "", "profile JSON path")
	out := flags.String("out", "", "generated output directory")
	force := flags.Bool("force", false, "overwrite generated files in output directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *profilePath == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "--profile and --out are required")
		return 2
	}
	p, err := ir.LoadProfile(*profilePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	result, err := codegen.Generate(p, *out, codegen.Options{Force: *force})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("generated %s\n", result.OutputDir)
	fmt.Printf("profile_id %s\n", result.Manifest.ProfileID)
	fmt.Printf("files %d\n", len(result.Files))
	return 0
}
