//go:build tools

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package tools records versions of CI-only tools without adding them to the
// product module or runtime dependency graph.
package tools

import (
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "gopkg.in/yaml.v3"
)
