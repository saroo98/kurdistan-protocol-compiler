// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase16planreceipt creates or verifies an expiry-bounded receipt for
// the exact private Terraform plan and its deny-by-default policy result. It
// never prints plan contents, Terraform variables, or authorization values.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"kurdistan/internal/phase16receipt"
)

func main() {
	mode := flag.String("mode", "", "create or verify")
	receiptPath := flag.String("receipt", "", "receipt path")
	output := flag.String("out", "", "create output path")
	plan := flag.String("plan", "", "binary plan path")
	planJSON := flag.String("plan-json", "", "plan JSON path")
	policy := flag.String("policy", "", "Rego policy path")
	policyResult := flag.String("policy-result", "", "OPA deny-count path")
	tfvars := flag.String("tfvars", "", "Terraform variables path")
	workflowFile := flag.String("workflow-file", "", "workflow file path")
	subject := flag.String("subject", "", "exact commit SHA")
	tree := flag.String("tree", "", "exact tree SHA")
	authorization := flag.String("authorization-id", "", "protected authorization ID")
	opaVersion := flag.String("opa-version", "", "OPA version")
	runIDText := flag.String("run-id", "", "GitHub run ID")
	runAttemptText := flag.String("run-attempt", "", "GitHub run attempt")
	createdAt := flag.Int64("created-at", 0, "creation epoch")
	expiresAt := flag.Int64("expires-at", 0, "expiry epoch")
	now := flag.Int64("now", 0, "verification epoch")
	flag.Parse()

	runID, err := strconv.ParseUint(*runIDText, 10, 64)
	failIf(err)
	runAttempt, err := strconv.ParseUint(*runAttemptText, 10, 64)
	failIf(err)
	input := phase16receipt.Inputs{
		SubjectSHA: *subject, TreeSHA: *tree,
		PlanPath: *plan, PlanJSONPath: *planJSON,
		PolicyPath: *policy, PolicyResultPath: *policyResult,
		TerraformVariablesPath: *tfvars,
		WorkflowPath:           ".github/workflows/phase16-production-plan.yml",
		WorkflowFilePath:       *workflowFile,
		AuthorizationID:        *authorization, OPAVersion: *opaVersion,
		RunID: runID, RunAttempt: runAttempt, CreatedAt: *createdAt, ExpiresAt: *expiresAt,
	}

	switch *mode {
	case "create":
		receipt, err := phase16receipt.Create(input)
		failIf(err)
		raw, err := phase16receipt.Marshal(receipt)
		failIf(err)
		if *output == "" {
			failIf(phase16receipt.ErrReceipt)
		}
		failIf(os.WriteFile(*output, raw, 0o600))
		fmt.Println(phase16receipt.Digest(raw))
	case "verify":
		raw, err := os.ReadFile(*receiptPath)
		failIf(err)
		verificationTime := *now
		if verificationTime == 0 {
			verificationTime = time.Now().Unix()
		}
		_, err = phase16receipt.Verify(raw, input, verificationTime)
		failIf(err)
		fmt.Println(phase16receipt.Digest(raw))
	default:
		failIf(phase16receipt.ErrReceipt)
	}
}

func failIf(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "phase16 plan receipt rejected")
	os.Exit(1)
}
