// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// ExecutableEvidenceCommands returns the explicit subprocess matrix that must
// run outside ordinary package tests. The returned slices are independent so
// callers cannot mutate the authoritative inventory.
func ExecutableEvidenceCommands() [][]string {
	source := [][]string{
		{"test", "-timeout", "300s", "-count=1", "./internal/runtime", "-run", "TestGeneratedProfileParityV1|TestInterpretedPolicyParityCoveringArrayV1|TestPolicyMatrixOwnerWitnessLiteralCompleteV1|TestPolicyMatrixAdmissionOnlyExecutedLedgerV1|TestPolicyMatrixCausalOwnerRegistryCompleteV1"},
		{"test", "-timeout", "300s", "-count=1", "./internal/codegen", "-run", "TestStrictGeneratedIdentifiersAndRoleSeparatedAuthorization|TestGenerateCreatesBuildableProfileSpecificModule|TestStrictGenerateSignedBoundaryMultiSeedAndPreOutput"},
		{"test", "-timeout", "300s", "-count=1", "./internal/testkit/importrules", "-run", "TestLabFaultCapabilityCannotReachNormalPaths|VersionMigrationBoundary|OfflineMigrationReachability|GeneratedAuthorizationBoundary|NoLabShortcut"},
		{"test", "-timeout", "300s", "-count=1", "./internal/crypto/...", "./internal/runtime/...", "./internal/protocol/framing/..."},
	}
	result := make([][]string, len(source))
	for index := range source {
		result[index] = append([]string(nil), source[index]...)
	}
	return result
}

type executableEvidenceRunner func(context.Context, string, []string) ([]byte, error)

// RunExecutableEvidence executes every authoritative nested command in order.
// It fails closed on the first missing or failed result.
func RunExecutableEvidence(ctx context.Context, root string, output io.Writer) error {
	return runExecutableEvidence(ctx, root, output, func(ctx context.Context, root string, args []string) ([]byte, error) {
		command := exec.CommandContext(ctx, "go", args...)
		command.Dir = root
		return command.CombinedOutput()
	})
}

func runExecutableEvidence(ctx context.Context, root string, output io.Writer, runner executableEvidenceRunner) error {
	if root == "" || runner == nil || output == nil {
		return fmt.Errorf("executable evidence runner configuration is incomplete")
	}
	for index, args := range ExecutableEvidenceCommands() {
		if err := ctx.Err(); err != nil {
			return err
		}
		fmt.Fprintf(output, "== executable evidence %d/%d: go %s ==\n", index+1, len(ExecutableEvidenceCommands()), strings.Join(args, " "))
		raw, err := runner(ctx, root, append([]string(nil), args...))
		if len(raw) > 0 {
			_, _ = output.Write(raw)
			if raw[len(raw)-1] != '\n' {
				_, _ = fmt.Fprintln(output)
			}
		}
		if err != nil {
			return fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}
