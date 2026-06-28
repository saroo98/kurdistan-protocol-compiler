// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package codegen

import (
	"bytes"
	"fmt"
	"go/format"
	"strconv"
	"strings"

	"kurdistan/internal/ir"
)

type generatedFile struct {
	RelPath string
	Content string
	Go      bool
}

func renderGo(template string, args ...any) (string, error) {
	source := fmt.Sprintf(template, args...)
	formatted, err := format.Source([]byte(source))
	if err != nil {
		return "", fmt.Errorf("format generated Go: %w\n%s", err, source)
	}
	return string(formatted), nil
}

func quote(value string) string {
	return strconv.Quote(value)
}

func quoteSlice(values []string) string {
	var b strings.Builder
	b.WriteString("[]string{")
	for i, value := range values {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(quote(value))
	}
	b.WriteString("}")
	return b.String()
}

func profileLiteral(p *ir.Profile) string {
	cp := *p
	cp.Auth.TestKeyHex = ""
	return fmt.Sprintf("%#v", cp)
}

func stateConsts(states []ir.State) string {
	var b strings.Builder
	b.WriteString("const (\n")
	for i, st := range states {
		fmt.Fprintf(&b, "\tState%02d%s = %s\n", i, SanitizeIdentifier(st.ID), quote(st.ID))
	}
	b.WriteString(")\n")
	return b.String()
}

func transitionsLiteral(transitions []ir.Transition) string {
	var b strings.Builder
	b.WriteString("[]GeneratedTransition{\n")
	for _, tr := range transitions {
		fmt.Fprintf(&b, "\t{From: %s, To: %s, Role: %s, OnMessage: %s, EmitsMessage: %s, RequiresAuth: %t},\n",
			quote(tr.From), quote(tr.To), quote(tr.Role), quote(tr.OnMessage), quote(tr.EmitsMessage), tr.RequiresAuth)
	}
	b.WriteString("}")
	return b.String()
}

func firstContactLiteral(steps []ir.FirstContactStep) string {
	var b strings.Builder
	b.WriteString("[]GeneratedFirstContactStep{\n")
	for i, step := range steps {
		fmt.Fprintf(&b, "\t{Index: %d, Role: %s, Direction: %s, Message: %s, WireSymbol: %s, FromState: %s, ToState: %s, PayloadSize: %d, Proof: %t, Decoy: %t},\n",
			i, quote(step.Role), quote(step.Direction), quote(step.Message), quote(step.WireSymbol), quote(step.FromState), quote(step.ToState), step.PayloadSize, step.Proof, step.Decoy)
	}
	b.WriteString("}")
	return b.String()
}

func semanticWireMap(messages []ir.MessageSymbol) string {
	var b strings.Builder
	b.WriteString("map[string]string{\n")
	for _, msg := range messages {
		fmt.Fprintf(&b, "\t%s: %s,\n", quote(msg.Semantic), quote(msg.WireSymbol))
	}
	b.WriteString("}")
	return b.String()
}

func messageBounds(messages []ir.MessageSymbol) string {
	var b strings.Builder
	b.WriteString("map[string]GeneratedMessageBounds{\n")
	for _, msg := range messages {
		fmt.Fprintf(&b, "\t%s: {Direction: %s, MinPayloadSize: %d, MaxPayloadSize: %d},\n",
			quote(msg.Semantic), quote(msg.Direction), msg.MinPayloadSize, msg.MaxPayloadSize)
	}
	b.WriteString("}")
	return b.String()
}

func goMod(modulePath, repoRoot string) string {
	return fmt.Sprintf("module %s\n\ngo 1.22\n\nrequire kurdistan v0.0.0\n\nreplace kurdistan => %s\n", modulePath, filepathSlash(repoRoot))
}

func filepathSlash(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func readme(p *ir.Profile) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Generated Kurdistan Profile %s\n\n", p.ID)
	fmt.Fprintf(&b, "This directory was produced by `cmd/kgen` for a lab-only generated source backend.\n\n")
	fmt.Fprintf(&b, "It contains profile-specific Go constants and static tables for local client/server protocol handling. It does not include deployment code, external target support, payload logging, or production key exchange.\n\n")
	fmt.Fprintf(&b, "## Local Commands\n\n")
	fmt.Fprintf(&b, "```bash\n")
	fmt.Fprintf(&b, "go test ./...\n")
	fmt.Fprintf(&b, "go run ./cmd/generated-echo --listen 127.0.0.1:9100\n")
	fmt.Fprintf(&b, "go run ./cmd/generated-server --listen 127.0.0.1:7100 --target 127.0.0.1:9100\n")
	fmt.Fprintf(&b, "go run ./cmd/generated-client --server 127.0.0.1:7100 --message \"hello generated\"\n")
	fmt.Fprintf(&b, "```\n\n")
	fmt.Fprintf(&b, "All runtime addresses must be loopback addresses.\n")
	return b.String()
}
