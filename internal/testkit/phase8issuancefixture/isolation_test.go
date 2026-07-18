package phase8issuancefixture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestWO806ProductionWiringIsolation(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/kprofile", "./internal/product/...")
	cmd.Dir = root
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dependency := range strings.Fields(string(raw)) {
		if strings.Contains(dependency, "/internal/testkit/phase8issuance") {
			t.Fatalf("production dependency reaches test issuance: %s", dependency)
		}
	}
	for _, base := range []string{filepath.Join(root, "cmd", "kprofile"), filepath.Join(root, "internal", "product")} {
		err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, content, 0)
			if err != nil {
				return err
			}
			for _, imp := range file.Imports {
				value, _ := strconv.Unquote(imp.Path.Value)
				if strings.Contains(value, "/internal/testkit/") {
					t.Fatalf("production import %s -> %s", path, value)
				}
			}
			if strings.Contains(path, filepath.Join("cmd", "kprofile")) || strings.HasSuffix(path, "phase8_tooling.go") {
				ast.Inspect(file, func(node ast.Node) bool {
					switch value := node.(type) {
					case *ast.BasicLit:
						literal := strings.ToLower(value.Value)
						for _, forbidden := range []string{"deterministic", "private-key", "seed-key", "getenv", "lookupenv"} {
							if strings.Contains(literal, forbidden) {
								t.Fatalf("production selector %s in %s", forbidden, path)
							}
						}
					case *ast.SelectorExpr:
						if value.Sel.Name == "Getenv" || value.Sel.Name == "LookupEnv" {
							t.Fatalf("environment provider selection in %s", path)
						}
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
