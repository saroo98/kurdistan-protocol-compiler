// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"kurdistan/internal/codegen"
	"kurdistan/internal/protocol/ir"
)

var (
	errProfileInput                   = errors.New("kgen profile input rejected")
	errAuthorizationCatalog           = errors.New("kgen authorization catalog rejected")
	errStrictGeneration               = errors.New("kgen strict generation failed")
	commandStderr           io.Writer = os.Stderr
	commandStdout           io.Writer = os.Stdout
	lstatLocal                        = os.Lstat
	openLocal                         = os.Open
	sameLocalFile                     = os.SameFile
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("kgen", flag.ContinueOnError)
	flags.SetOutput(commandStderr)
	profilePath := flags.String("profile", "", "profile JSON path")
	authorizationPath := flags.String("authorization-catalog", "", "authorization catalog JSON path")
	out := flags.String("out", "", "generated output directory")
	force := flags.Bool("force", false, "overwrite generated files in output directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *profilePath == "" || *authorizationPath == "" || *out == "" {
		fmt.Fprintln(commandStderr, "--profile, --authorization-catalog, and --out are required")
		return 2
	}
	profileRaw, err := readLocalRegularFile(*profilePath)
	if err != nil {
		fmt.Fprintln(commandStderr, errProfileInput)
		return 1
	}
	p, err := ir.DecodeProfileV1(profileRaw)
	if err != nil {
		fmt.Fprintln(commandStderr, errProfileInput)
		return 1
	}
	catalogRaw, err := readLocalRegularFile(*authorizationPath)
	if err != nil {
		fmt.Fprintln(commandStderr, errAuthorizationCatalog)
		return 1
	}
	catalog, err := codegen.ParseAuthorizationCatalogV1(catalogRaw)
	if err != nil || catalog.ValidateExactSeedRangeV1(codegen.AuthorizationCatalogScopeExplicitV1, p.Seed, 1) != nil {
		fmt.Fprintln(commandStderr, errAuthorizationCatalog)
		return 1
	}
	result, err := codegen.GenerateStrict(p, *out, codegen.Options{Force: *force}, catalog)
	if err != nil {
		if errors.Is(err, codegen.ErrAuthorizationCatalogInvalid) || errors.Is(err, codegen.ErrAuthorizationMismatch) || errors.Is(err, codegen.ErrStrictSeedRange) || errors.Is(err, codegen.ErrStrictModulePath) {
			fmt.Fprintln(commandStderr, fmt.Errorf("%w: %w", errStrictGeneration, err))
		} else {
			fmt.Fprintln(commandStderr, errStrictGeneration)
		}
		return 1
	}
	fmt.Fprintf(commandStdout, "generated %s\n", result.OutputDir)
	fmt.Fprintf(commandStdout, "profile_id %s\n", result.Manifest.ProfileID)
	fmt.Fprintf(commandStdout, "files %d\n", len(result.Files))
	return 0
}

// readLocalRegularFile is a portable best-effort local check. It does not make
// a concurrently hostile filesystem atomic; stronger no-follow handles are a
// separate platform-specific boundary.
func readLocalRegularFile(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errProfileInput
	}
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)
	current := volume + string(os.PathSeparator)
	rootInfo, err := lstatLocal(current)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, errProfileInput
	}
	for _, component := range strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == '\\' }) {
		current = filepath.Join(current, component)
		info, err := lstatLocal(current)
		if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeCharDevice) != 0 {
			return nil, errProfileInput
		}
	}
	final, err := lstatLocal(clean)
	if err != nil || !final.Mode().IsRegular() {
		return nil, errProfileInput
	}
	f, err := openLocal(clean)
	if err != nil {
		return nil, errProfileInput
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !sameLocalFile(final, opened) {
		return nil, errProfileInput
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errProfileInput
	}
	return raw, nil
}
