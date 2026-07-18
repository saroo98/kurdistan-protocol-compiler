package main

import (
	"flag"
	"fmt"
	"kurdistan/internal/testkit/phase8issuancefixture"
	"os"
)

func main() {
	out := flag.String("out", "", "new output directory")
	root := flag.String("repo-root", "", "repository root")
	flag.Parse()
	if err := phase8issuancefixture.Generate(*out, *root); err != nil {
		fmt.Fprintln(os.Stderr, "fixture generation failed")
		os.Exit(1)
	}
}
