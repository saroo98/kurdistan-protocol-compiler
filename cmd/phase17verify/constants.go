// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"sort"
	"strconv"
)

// requireGoConstants evaluates only a closed set of candidate const groups.
// Dependencies are resolved against the original file before other declarations
// are excluded, so stripping a shadowing declaration cannot change its meaning.
func requireGoConstants(label, source string, want map[string]constant.Value) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%s constants: %s", label, fmt.Sprintf(format, args...))
	}
	if len(source) > qualificationMaximumSourceBytes {
		return fail("source exceeds %d bytes", qualificationMaximumSourceBytes)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, label, source, 0)
	if err != nil {
		return fail("parse: %v", err)
	}
	type binding struct {
		name        string
		group       *ast.GenDecl
		expressions []ast.Expr
		typ         ast.Expr
	}
	declarations := map[string]int{}
	bindings := map[string]*binding{}
	groups := map[*ast.GenDecl][]*binding{}
	declare := func(name string) {
		if name != "_" {
			declarations[name]++
		}
	}
	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if declaration.Recv == nil {
				declare(declaration.Name.Name)
			}
		case *ast.GenDecl:
			var inherited []ast.Expr
			var inheritedType ast.Expr
			for _, spec := range declaration.Specs {
				switch spec := spec.(type) {
				case *ast.ImportSpec:
					if spec.Name != nil {
						declare(spec.Name.Name)
					} else if imported, err := strconv.Unquote(spec.Path.Value); err == nil {
						declare(path.Base(imported))
					}
				case *ast.TypeSpec:
					declare(spec.Name.Name)
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						declare(name.Name)
					}
					if declaration.Tok != token.CONST {
						continue
					}
					if len(spec.Values) != 0 {
						inherited, inheritedType = spec.Values, spec.Type
					}
					for index, name := range spec.Names {
						expressions := inherited
						if len(inherited) == len(spec.Names) {
							expressions = inherited[index : index+1]
						}
						entry := &binding{name.Name, declaration, expressions, inheritedType}
						groups[declaration] = append(groups[declaration], entry)
						if name.Name != "_" {
							bindings[name.Name] = entry
						}
					}
				}
			}
		}
	}
	selected := map[*ast.GenDecl]bool{}
	memo := map[*binding]int{}
	visiting := map[*binding]bool{}
	// Saturation bounds dependency expansion, including each reference occurrence.
	// This is a conservative work guard, not a total-process-memory guarantee.
	limit := qualificationMaximumSourceBytes
	add := func(a, b int) int {
		if a >= limit || b >= limit || a > limit-b {
			return limit + 1
		}
		return a + b
	}
	var weight func(*binding) (int, error)
	weight = func(entry *binding) (int, error) {
		if declarations[entry.name] > 1 {
			return 0, fail("duplicate declaration %s", entry.name)
		}
		if visiting[entry] {
			return 0, fail("cyclic constant dependency %s", entry.name)
		}
		if value, ok := memo[entry]; ok {
			return value, nil
		}
		selected[entry.group] = true
		visiting[entry] = true
		total := 1
		expressions := append([]ast.Expr(nil), entry.expressions...)
		if entry.typ != nil {
			expressions = append(expressions, entry.typ)
		}
		for _, expression := range expressions {
			var walkErr error
			ast.Inspect(expression, func(node ast.Node) bool {
				if node == nil || walkErr != nil {
					return false
				}
				total = add(total, 1)
				switch node := node.(type) {
				case *ast.SelectorExpr:
					walkErr = fail("unsupported selector dependency")
					return false
				case *ast.BasicLit:
					total = add(total, len(node.Value))
				case *ast.Ident:
					total = add(total, len(node.Name))
					if declarations[node.Name] != 0 {
						dependency := bindings[node.Name]
						if dependency == nil {
							walkErr = fail("non-const dependency %s", node.Name)
							return false
						}
						cost, err := weight(dependency)
						if err != nil {
							walkErr = err
							return false
						}
						total = add(total, cost)
					} else {
						switch object := types.Universe.Lookup(node.Name).(type) {
						case *types.Const, *types.Builtin:
						case *types.TypeName:
							if _, ok := object.Type().Underlying().(*types.Basic); !ok {
								walkErr = fail("non-builtin type dependency %s", node.Name)
							}
						default:
							walkErr = fail("unresolved reference %s", node.Name)
						}
					}
				}
				if total > limit {
					walkErr = fail("constant expansion exceeds %d bytes", limit)
					return false
				}
				return true
			})
			if walkErr != nil {
				return 0, walkErr
			}
		}
		visiting[entry] = false
		memo[entry] = total
		return total, nil
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := bindings[name]
		if entry == nil {
			return fail("missing const declaration %s", name)
		}
		if _, err := weight(entry); err != nil {
			return err
		}
	}
	// A dependency can select another group. Budget every sibling, including
	// inherited initializers, until the selected group closure stops growing.
	processed := map[*ast.GenDecl]bool{}
	total := 0
	for {
		progress := false
		for _, declaration := range file.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || !selected[group] || processed[group] {
				continue
			}
			processed[group], progress = true, true
			total = add(total, int(group.End()-group.Pos()))
			for _, entry := range groups[group] {
				cost, err := weight(entry)
				if err != nil {
					return err
				}
				total = add(total, cost)
			}
			if total > limit {
				return fail("constant expansion exceeds %d bytes", limit)
			}
		}
		if !progress {
			break
		}
	}
	synthetic := &ast.File{Name: file.Name}
	for _, declaration := range file.Decls {
		if group, ok := declaration.(*ast.GenDecl); ok && selected[group] {
			synthetic.Decls = append(synthetic.Decls, group)
		}
	}
	config := types.Config{}
	checked, err := config.Check("candidate", fset, []*ast.File{synthetic}, nil)
	if err != nil {
		return fail("type check: %v", err)
	}
	for _, name := range names {
		actual, ok := checked.Scope().Lookup(name).(*types.Const)
		if !ok || !comparableConstantKinds(actual.Val().Kind(), want[name].Kind()) || !constant.Compare(actual.Val(), token.EQL, want[name]) {
			return fail("%s disagrees with authority", name)
		}
	}
	return nil
}

func comparableConstantKinds(a, b constant.Kind) bool {
	numeric := func(k constant.Kind) bool { return k == constant.Int || k == constant.Float || k == constant.Complex }
	return a == b || numeric(a) && numeric(b)
}
