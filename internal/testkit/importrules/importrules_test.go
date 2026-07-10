// Package importrules enforces the architecture-realignment boundary: the
// product runtime and real libraries must never depend on quarantined
// model/contract code. Only the analysis/generation tooling (audit, codegen,
// kcheck) and contracts/product packages themselves may import
// internal/contracts/** or internal/product/**.
//
// This is the executable form of the Stage 6 contract-import gate.
package importrules

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "kurdistan"

// forbiddenImportPrefixes are import paths the runtime must not depend on.
var forbiddenImportPrefixes = []string{
	modulePath + "/internal/contracts/",
	modulePath + "/internal/product/",
}

// allowedImporterPrefixes are the only package paths permitted to import the
// forbidden trees: the analysis/generation tooling that audits, hardens, or
// generates from the models, plus the quarantined trees themselves (intra-tree
// references are fine). The boundary's intent is that the product RUNTIME must
// not depend on models — not that no tool may; analysis tooling legitimately
// consumes them.
var allowedImporterPrefixes = []string{
	modulePath + "/internal/contracts/",
	modulePath + "/internal/product/",
	modulePath + "/internal/audit",
	modulePath + "/internal/codegen",
	modulePath + "/internal/lab/hardening",
	modulePath + "/cmd/kcheck",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from test dir")
		}
		dir = parent
	}
}

func hasPrefixAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func TestRuntimeDoesNotImportContracts(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var violations []string

	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			rel, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			pkgPath := modulePath + "/" + filepath.ToSlash(rel)
			if hasPrefixAny(pkgPath, allowedImporterPrefixes) {
				return nil // this package is permitted to import the quarantined trees
			}
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				ip := strings.Trim(imp.Path.Value, `"`)
				if hasPrefixAny(ip, forbiddenImportPrefixes) {
					violations = append(violations, pkgPath+" imports "+ip)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	if len(violations) > 0 {
		t.Fatalf("runtime/real packages must not import contracts/product (%d violation(s)):\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}
