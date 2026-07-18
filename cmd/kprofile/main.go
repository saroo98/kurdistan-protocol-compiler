// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command kprofile provides provider-independent offline profile compilation
// and redacted structural inspection. Signing, sealing, and verification are
// host-integrated through internal/product/profile's opaque provider APIs.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

var commandStdout, commandStderr io.Writer = os.Stdout, os.Stderr

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(commandStderr, "usage: kprofile <compile|inspect>")
		return 2
	}
	switch args[0] {
	case "compile":
		return runCompile(args[1:])
	case "inspect":
		return runInspect(args[1:])
	default:
		fmt.Fprintln(commandStderr, "unknown command")
		return 2
	}
}

func runCompile(args []string) int {
	fs := flag.NewFlagSet("kprofile compile", flag.ContinueOnError)
	fs.SetOutput(commandStderr)
	specPath := fs.String("spec", "", "absolute path to an offline issuance specification containing provider handles only")
	outPath := fs.String("out", "", "new absolute output path; existing files are never overwritten")
	if fs.Parse(args) != nil || *specPath == "" || *outPath == "" {
		fmt.Fprintln(commandStderr, "compile requires --spec and --out")
		return 2
	}
	raw, err := readBoundedLocal(*specPath)
	if err != nil {
		fmt.Fprintln(commandStderr, "spec rejected")
		return 1
	}
	var spec profile.OfflineIssuanceSpec
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&spec) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		fmt.Fprintln(commandStderr, "spec rejected")
		return 1
	}
	canonical, err := json.Marshal(spec)
	if err != nil || !bytes.Equal(raw, canonical) {
		fmt.Fprintln(commandStderr, "spec rejected")
		return 1
	}
	compiled, err := profile.CompileOffline(spec)
	if err != nil {
		fmt.Fprintln(commandStderr, "spec rejected")
		return 1
	}
	if err := writeNewLocal(*outPath, compiled); err != nil {
		fmt.Fprintln(commandStderr, "output rejected")
		return 1
	}
	digest := sha256.Sum256(compiled)
	fmt.Fprintf(commandStdout, "compiled sha256=%s bytes=%d\n", hex.EncodeToString(digest[:]), len(compiled))
	return 0
}

func runInspect(args []string) int {
	fs := flag.NewFlagSet("kprofile inspect", flag.ContinueOnError)
	fs.SetOutput(commandStderr)
	inPath := fs.String("in", "", "absolute path to canonical compiled profile bytes")
	if fs.Parse(args) != nil || *inPath == "" {
		fmt.Fprintln(commandStderr, "inspect requires --in")
		return 2
	}
	raw, err := readBoundedLocal(*inPath)
	if err != nil {
		fmt.Fprintln(commandStderr, "input rejected")
		return 1
	}
	p, err := envelope.DecodeCanonicalProfileV1(raw)
	if err != nil {
		fmt.Fprintln(commandStderr, "input rejected")
		return 1
	}
	digest := sha256.Sum256(raw)
	fmt.Fprintf(commandStdout, "structural-only verified=false generation=%d valid_until=%d sha256=%s\n", p.Generation, p.ValidUntil, hex.EncodeToString(digest[:]))
	return 0
}

func readBoundedLocal(path string) ([]byte, error) {
	return readBoundedLocalWithHook(path, nil)
}

// readBoundedLocalWithHook exists to let the package tests replace pathnames
// after the parent directory handle is acquired. Production callers pass nil.
func readBoundedLocalWithHook(path string, beforeLeafOpen func()) ([]byte, error) {
	parent, leaf, err := openLocalParent(path)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if beforeLeafOpen != nil {
		beforeLeafOpen()
	}
	f, err := parent.OpenFile(leaf, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("regular file required")
	}
	raw, err := io.ReadAll(io.LimitReader(f, envelope.MaxTotalInputBytes+1))
	if err != nil || len(raw) > envelope.MaxTotalInputBytes {
		return nil, errors.New("input size rejected")
	}
	return raw, nil
}

func writeNewLocal(path string, content []byte) error {
	return writeNewLocalWithHook(path, content, nil)
}

// writeNewLocalWithHook exists to let the package tests replace pathnames
// after the parent directory handle is acquired. Production callers pass nil.
func writeNewLocalWithHook(path string, content []byte, beforeLeafOpen func()) error {
	parent, leaf, err := openLocalParent(path)
	if err != nil {
		return err
	}
	defer parent.Close()
	if beforeLeafOpen != nil {
		beforeLeafOpen()
	}
	f, err := parent.OpenFile(leaf, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return errors.New("regular file required")
	}
	return writeNewLocalFile(content, f)
}

func writeNewLocalFile(content []byte, f io.WriteCloser) (err error) {
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	n, err := f.Write(content)
	if err != nil {
		return err
	}
	if n != len(content) {
		return io.ErrShortWrite
	}
	return nil
}
