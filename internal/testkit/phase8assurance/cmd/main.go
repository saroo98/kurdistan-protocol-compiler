// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"flag"
	"fmt"
	"os"

	"kurdistan/internal/testkit/phase8assurance"
)

func main() {
	root := flag.String("repo-root", ".", "repository root")
	out := flag.String("out", "", "new output file")
	kind := flag.String("kind", "corpus", "corpus or fuzz")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "output path required")
		os.Exit(2)
	}
	var raw []byte
	var err error
	if *kind == "fuzz" {
		raw, err = phase8assurance.GenerateFuzzCommandManifest(*root)
	} else {
		raw, err = phase8assurance.Generate(*root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		_, err = file.Write(raw)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
