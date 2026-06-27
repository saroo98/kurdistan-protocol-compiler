package main

import (
	"flag"
	"fmt"
	"os"

	ktrace "kurdistan/internal/trace"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "compare" {
		fmt.Fprintln(os.Stderr, "usage: ktrace compare --a trace-a.jsonl --b trace-b.jsonl")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	a := fs.String("a", "", "first trace")
	b := fs.String("b", "", "second trace")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if *a == "" || *b == "" {
		fmt.Fprintln(os.Stderr, "--a and --b are required")
		os.Exit(2)
	}
	report, err := ktrace.CompareFiles(*a, *b)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(report.String())
	if !report.Valid || !report.MeaningfullyDifferent {
		os.Exit(1)
	}
}
