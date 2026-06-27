package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"kurdistan/internal/labtrace"
	ktrace "kurdistan/internal/trace"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "compare":
		err = compare(os.Args[2:])
	case "scan":
		err = scan(os.Args[2:])
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

func compare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	a := fs.String("a", "", "first trace")
	b := fs.String("b", "", "second trace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *a == "" || *b == "" {
		return fmt.Errorf("--a and --b are required")
	}
	report, err := ktrace.CompareFiles(*a, *b)
	if err != nil {
		return err
	}
	fmt.Print(report.String())
	if !report.Valid || !report.MeaningfullyDifferent {
		return fmt.Errorf("traces are not meaningfully different")
	}
	return nil
}

func scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	dir := fs.String("dir", "testdata/traces", "directory containing trace JSONL files")
	threshold := fs.Float64("threshold", ktrace.DefaultStabilityThreshold, "stability threshold from 0 to 1")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report, err := ktrace.ScanDirectory(*dir, *threshold)
	if err != nil {
		return err
	}
	fmt.Print(report.String())
	return nil
}

func corpus(args []string) error {
	fs := flag.NewFlagSet("corpus", flag.ContinueOnError)
	startSeed := fs.Int64("start-seed", 1, "first deterministic seed")
	count := fs.Int("count", 20, "number of profiles/traces")
	out := fs.String("out", "testdata/traces/corpus-summary.json", "summary JSON path")
	message := fs.String("message", "hello kurdistan", "local echo message")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report, err := labtrace.GenerateCorpus(context.Background(), labtrace.CorpusOptions{StartSeed: *startSeed, Count: *count, Message: *message})
	if err != nil {
		return err
	}
	if err := labtrace.WriteCorpusTraceReport(*out, report); err != nil {
		return err
	}
	fmt.Print(report.TraceScanReport.String())
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ktrace compare --a trace-a.jsonl --b trace-b.jsonl | ktrace scan --dir testdata/traces | ktrace corpus --start-seed 1 --count 20 --out testdata/traces/corpus-summary.json")
}
