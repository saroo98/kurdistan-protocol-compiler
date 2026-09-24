// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"fmt"
	"go/constant"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoConstantChecksValuesInsteadOfFormattingOrComments(t *testing.T) {
	want := map[string]constant.Value{"MaxControlBytes": constant.MakeInt64(65536)}
	for _, source := range []string{
		"package p; const MaxControlBytes = 64 << 10",
		"package p; const (MaxControlBytes = 65536)",
	} {
		if err := requireGoConstants("fixture", source, want); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []string{
		"package p; const MaxControlBytes = 7 // MaxControlBytes = 65536",
		"package p; var MaxControlBytes = 65536",
		"package p; const MaxControlBytes uint8 = 65536",
		"package p; const MaxControlBytes = missing",
	} {
		if err := requireGoConstants("fixture", source, want); err == nil {
			t.Fatalf("invalid candidate accepted: %q", source)
		}
	}
}

func TestGoConstantsPreserveGroupsDependenciesAndExcludeFunctions(t *testing.T) {
	for _, source := range []string{
		"package p; const (FlagCritical uint8 = 1 << 0; knownFlags = FlagCritical)",
		"package p; const FlagCritical uint8 = 1; const knownFlags = FlagCritical",
		"package p; const (unused = iota; FlagCritical; knownFlags = FlagCritical)",
		"package p; const (base = 0; FlagCritical, knownFlags = iota, iota)",
		"package p; const knownFlags = FlagCritical; const FlagCritical = 1; func never() { panic(unresolved()) }",
		"package p; const (unused = iota; FlagCritical; ignored; knownFlags = FlagCritical)",
	} {
		if err := requireGoConstants("fixture", source, map[string]constant.Value{"FlagCritical": constant.MakeInt64(1), "knownFlags": constant.MakeInt64(1)}); err != nil {
			t.Fatalf("%s: %v", source, err)
		}
	}
}

func TestGoConstantsRejectInvalidDependencies(t *testing.T) {
	for _, test := range []struct{ source, diagnostic string }{
		{"package p; // const ALPN = 1", "missing const"},
		{"package p; const ALPN = 2 // const ALPN = 1", "disagrees"},
		{"package p; const ALPN = 1; var ALPN = 1", "duplicate"},
		{"package p; const ALPN = 1; const ALPN = 1", "duplicate"},
		{"package p; type uint8 = uint64; const ALPN uint8 = 1", "non-const"},
		{"package p; import \"example/uint8\"; const ALPN uint8 = 1", "non-const"},
		{"package p; const ALPN = true", "disagrees"},
		{"package p; const ALPN = \"1\"", "disagrees"},
		{"package p; var one = 1; const ALPN = one", "non-const"},
		{"package p; const ALPN = external.Value", "selector"},
		{"package p; const ALPN = b; const b = ALPN", "cyclic"},
		{"package p; const (ALPN = 1; sibling = missing)", "unresolved"},
		{"package p; const (sibling = missing; ALPN)", "unresolved"},
		{"package p; const ALPN uint8 = 256", "type check"},
		{"package p; func f() { const ALPN = 1 }", "missing const"},
		{"package p; const len = 2; const ALPN = len(\"x\")", "type check"},
	} {
		err := requireGoConstants("fixture", test.source, map[string]constant.Value{"ALPN": constant.MakeInt64(1)})
		if err == nil || !strings.Contains(err.Error(), test.diagnostic) {
			t.Fatalf("source=%s err=%v, want %q", test.source, err, test.diagnostic)
		}
	}
}

func TestGoConstantsBoundSourceAndExpandedWork(t *testing.T) {
	want := map[string]constant.Value{"ALPN": constant.MakeString("x")}
	if err := requireGoConstants("fixture", "package p; const ALPN = \"x\"", want); err != nil {
		t.Fatal(err)
	}
	oversized := "package p; const ALPN = \"x\"; //" + strings.Repeat("x", qualificationMaximumSourceBytes)
	if err := requireGoConstants("fixture", oversized, want); err == nil || !strings.Contains(err.Error(), "source exceeds") {
		t.Fatalf("oversized source: %v", err)
	}
	var source strings.Builder
	source.WriteString("package p; const a0 = \"x\";")
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&source, "const a%d = a%d+a%d;", i, i-1, i-1)
	}
	source.WriteString("const ALPN = a30")
	if err := requireGoConstants("fixture", source.String(), want); err == nil || !strings.Contains(err.Error(), "constant expansion") {
		t.Fatalf("expanded DAG: %v", err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "source.go")
	if err := os.WriteFile(path, []byte("package p"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRequired(root, "source.go"); err != nil {
		t.Fatalf("read control: %v", err)
	}
	if err := os.WriteFile(path, []byte(oversized), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRequired(root, "source.go"); err == nil || !strings.Contains(err.Error(), "source byte limit") {
		t.Fatalf("bounded read: %v", err)
	}
}

func TestCarrierWireConstantsAcceptEquivalentSource(t *testing.T) {
	for _, change := range []struct{ path, old, new string }{
		{"internal/transport/tlstcp/carrier.go", "ALPN          =", "ALPN /* formatting */ ="},
		{"internal/protocol/wirev1/codec.go", "MaxControlBytes       = 64 << 10", "MaxControlBytes = 65536"},
	} {
		root := copyAuthority(t)
		value, err := loadContract(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateContract(value); err != nil {
			t.Fatal(err)
		}
		if err := verifyGoCopies(root, value); err != nil {
			t.Fatalf("positive control: %v", err)
		}
		if err := replaceFile(root, change.path, change.old, change.new); err != nil {
			t.Fatal(err)
		}
		if err := verifyGoCopies(root, value); err != nil {
			t.Fatalf("equivalent constants: %v", err)
		}
	}
}
