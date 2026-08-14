// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunEmitsCategoricalReceiptWithoutInputContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stream.jsonl")
	line := func(source, payload string) string {
		return `{"source":"` + source + `","data":"` + base64.StdEncoding.EncodeToString([]byte(payload)) + `"}` + "\n"
	}
	raw := []byte(line("ANDROID_LOGCAT", "safe category") + line("REMOTE_JOURNAL", "safe category"))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := run([]string{"-input", path}, &stdout); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"result":"PASS"`)) || bytes.Contains(stdout.Bytes(), []byte("safe category")) ||
		!strings.HasSuffix(stdout.String(), "\n") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestRunWithInputAcceptsOnlyExactBoundedStdin(t *testing.T) {
	line := func(source, payload string) string {
		return `{"source":"` + source + `","data":"` + base64.StdEncoding.EncodeToString([]byte(payload)) + `"}` + "\n"
	}
	raw := []byte(line("ANDROID_LOGCAT", "safe category") + line("REMOTE_JOURNAL", "safe category"))
	var stdout bytes.Buffer
	arguments := []string{"-input", "-", "-expected-bytes", fmt.Sprint(len(raw))}
	if err := runWithInput(arguments, bytes.NewReader(raw), &stdout); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"result":"PASS"`)) {
		t.Fatalf("stdout=%q", stdout.String())
	}
	stdout.Reset()
	arguments[len(arguments)-1] = fmt.Sprint(len(raw) - 1)
	if err := runWithInput(arguments, bytes.NewReader(raw), &stdout); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"result":"FAIL"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"truncated":true`)) {
		t.Fatalf("mismatched stdin receipt=%q", stdout.String())
	}
}
